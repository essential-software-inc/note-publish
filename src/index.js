/**
 * Publish-to-Web backend for Note Builder.
 * Implements publish-feature-plan.md sections 3-6, plus Google sign-in and
 * cross-device account sync (notes backup + published-page ownership).
 *
 * Bindings expected (see wrangler.toml):
 *   NOTES_BUCKET  - R2 bucket, stores "<slug>.html" and "sync/<sub>/notes.json"
 *   SLUGS         - KV namespace, stores JSON metadata per slug, plus
 *                   "owner:<sub>:<slug>" index keys for GET /my/pages
 *   REPORTS       - KV namespace, stores report records
 *   ACCOUNTS      - KV namespace, stores "user:<sub>" records and
 *                   "session:<hash>" tokens (see handleGoogleAuth)
 *   REPORT_WEBHOOK_URL (secret, optional) - POSTed with report JSON for alerting
 *   GOOGLE_CLIENT_IDS (secret) - comma-separated OAuth client IDs accepted
 *                   as the idToken audience (the app's web client ID, and
 *                   any Android client IDs that ever appear as `aud`) —
 *                   see verifyGoogleIdToken
 *   ADS_DB        - D1 database, Publish-as-Ad only: round-robin cursor +
 *                   view-credit ledger (see migrations/0001_ads.sql). Page
 *                   HTML/slugs/tokens for ads still live in SLUGS/NOTES_BUCKET
 *                   above — an ad IS a published page, just also listed here.
 *   REVENUECAT_WEBHOOK_SECRET (secret) - must match the "Authorization Header
 *                   value" configured on the RevenueCat project's webhook
 *                   (Project settings → Integrations → Webhooks) — see
 *                   handleRevenueCatWebhook. Without this set the webhook
 *                   endpoint refuses everything (fail closed).
 *
 * Rate limiting on POST /publish and PUT /publish/:slug is configured via
 * Cloudflare's dashboard Rate Limiting Rules (plan §4) — not implemented in
 * code. GET /@:slug and /check-slug/:slug are intentionally left open.
 */

const MAX_HTML_BYTES = 2 * 1024 * 1024; // 2MB — plan §6, tune as needed
const MAX_SYNC_BYTES = 8 * 1024 * 1024; // notes backups carry embedded images, so a higher cap than a single published page
const SLUG_RE = /^[a-z0-9-]{3,48}$/;
const RESERVED_SLUGS = new Set([
  'admin', 'api', 'report', 'reports', 'check-slug', 'publish', 'n',
  'www', 'assets', 'static', 'favicon.ico', 'robots.txt', 'health',
  'auth', 'sync', 'my'
]);
const SOFT_DELETE_RETENTION_MS = 30 * 24 * 60 * 60 * 1000; // 30 days, plan §3.5
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days — re-issued on every successful /auth/google, not sliding

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  };
}
function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(), ...extraHeaders }
  });
}
function textError(status, message) {
  return json({ error: message }, status);
}

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function newToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}
// Constant-time-ish string compare for tokens: a plain `!==` short-circuits
// on the first mismatched character, which leaks a (tiny, but real) timing
// signal an attacker could use to guess a token byte-by-byte. This always
// walks the full string. The length check still leaks length up front, but
// both tokens compared here are fixed-length hex output (sha256Hex/newToken
// or the ADMIN_TOKEN secret), so that leak reveals nothing useful.
function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
function validSlug(slug) {
  return typeof slug === 'string' && SLUG_RE.test(slug) && !RESERVED_SLUGS.has(slug);
}

async function getMeta(env, slug) {
  const raw = await env.SLUGS.get('slug:' + slug);
  return raw ? JSON.parse(raw) : null;
}
async function putMeta(env, slug, meta) {
  await env.SLUGS.put('slug:' + slug, JSON.stringify(meta));
}

/* ---------------- Google auth + sessions ---------------- */

// Verifies the idToken the client got from Google (either the native
// GoogleAuth Capacitor plugin or the Identity Services web fallback) by
// asking Google itself rather than implementing JWT/JWKS verification
// here — tokeninfo is rate-limited (fine at this app's scale) and is the
// approach Google's own docs point at for a lightweight server-side check.
// Returns { sub, email } or null; never throws.
async function verifyGoogleIdToken(env, idToken) {
  if (typeof idToken !== 'string' || !idToken) return null;
  let resp;
  try {
    resp = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(idToken));
  } catch (e) { return null; }
  if (!resp.ok) return null;
  let payload;
  try { payload = await resp.json(); } catch (e) { return null; }
  if (!payload || !payload.sub) return null;
  const allowed = (env.GOOGLE_CLIENT_IDS || '').split(',').map(s => s.trim()).filter(Boolean);
  // Misconfiguration (the secret was never set) should fail closed, not
  // accept a token audienced to literally anyone.
  if (!allowed.length || !allowed.includes(payload.aud)) return null;
  return { sub: payload.sub, email: payload.email || null };
}

async function getUser(env, sub) {
  const raw = await env.ACCOUNTS.get('user:' + sub);
  return raw ? JSON.parse(raw) : null;
}
async function putUser(env, sub, user) {
  await env.ACCOUNTS.put('user:' + sub, JSON.stringify(user));
}

async function createSession(env, sub) {
  const token = newToken();
  const tokenHash = await sha256Hex(token);
  await env.ACCOUNTS.put('session:' + tokenHash, JSON.stringify({ sub, expiresAt: Date.now() + SESSION_TTL_MS }), {
    expirationTtl: Math.ceil(SESSION_TTL_MS / 1000)
  });
  return token;
}
// Reads the session token from `Authorization: Bearer <token>` and
// resolves it to the Google `sub` it belongs to, plus the token's own
// hash (needed by handleDeleteAccount to revoke this specific session).
// Returns null if missing, malformed, or unrecognized (already expired
// sessions are pruned by KV's own expirationTtl, so a lookup miss covers
// that case too).
async function requireSessionInfo(env, request) {
  const header = request.headers.get('Authorization') || '';
  const m = /^Bearer\s+(.+)$/i.exec(header.trim());
  if (!m) return null;
  const tokenHash = await sha256Hex(m[1]);
  const raw = await env.ACCOUNTS.get('session:' + tokenHash);
  if (!raw) return null;
  let session;
  try { session = JSON.parse(raw); } catch (e) { return null; }
  if (!session || !session.sub || session.expiresAt < Date.now()) return null;
  return { sub: session.sub, tokenHash };
}
async function requireSession(env, request) {
  const info = await requireSessionInfo(env, request);
  return info ? info.sub : null;
}

async function handleGoogleAuth(env, request) {
  let body;
  try { body = await request.json(); } catch (e) { return textError(400, 'invalid JSON body'); }
  const identity = await verifyGoogleIdToken(env, body && body.idToken);
  if (!identity) return textError(401, 'invalid Google idToken');
  let user = await getUser(env, identity.sub);
  const now = Date.now();
  let deletionCancelled = false;
  if (!user) {
    user = { sub: identity.sub, email: identity.email, createdAt: now };
  } else {
    // Email can legitimately change on Google's side between sign-ins;
    // keep it current rather than pinned to whatever it was at signup.
    user.email = identity.email;
    // Signing back in during the 30-day grace period (see
    // handleDeleteAccount) cancels the scheduled deletion.
    if (user.pendingDeletionAt) {
      delete user.pendingDeletionAt;
      deletionCancelled = true;
    }
  }
  user.lastSignInAt = now;
  await putUser(env, identity.sub, user);
  const sessionToken = await createSession(env, identity.sub);
  return json({ sessionToken, sub: identity.sub, email: identity.email, deletionCancelled });
}

// Sign-out is mostly a client-side concern (drop the stored token), but
// invalidating it here too means a token that already leaked (e.g. left
// in a log somewhere) stops working the moment the person signs out,
// rather than silently remaining valid until its 30-day TTL runs out.
async function handleSignOut(env, request) {
  let body;
  try { body = await request.json(); } catch (e) { body = {}; }
  const token = body && body.sessionToken;
  if (typeof token === 'string' && token) {
    const tokenHash = await sha256Hex(token);
    await env.ACCOUNTS.delete('session:' + tokenHash);
  }
  return json({ ok: true });
}

/* ---------------- Account sync (notes backup) ---------------- */

// The uploaded blob is opaque to the worker — same {app, version, notes,
// images} shape Note Builder's own file-based backup already writes, just
// stored server-side under the account instead of downloaded. Kept as a
// single R2 object per account (last-write-wins) rather than per-note
// records: the client already does its own additive-by-id merge on pull
// (see nbSyncPull), so there's no server-side merge to get right here.
async function handleSyncPush(env, request) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  const bodyText = await request.text();
  if (new TextEncoder().encode(bodyText).length > MAX_SYNC_BYTES) return textError(413, 'backup too large');
  let parsed;
  try { parsed = JSON.parse(bodyText); } catch (e) { return textError(400, 'invalid JSON body'); }
  if (!parsed || !Array.isArray(parsed.notes)) return textError(400, 'missing notes array');
  await env.NOTES_BUCKET.put('sync/' + sub + '/notes.json', bodyText, {
    httpMetadata: { contentType: 'application/json; charset=utf-8' }
  });
  const now = Date.now();
  await env.ACCOUNTS.put('syncmeta:' + sub, JSON.stringify({ updatedAt: now, sizeBytes: bodyText.length }));
  return json({ ok: true, updatedAt: now });
}

async function handleSyncPull(env, request) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  const obj = await env.NOTES_BUCKET.get('sync/' + sub + '/notes.json');
  if (!obj) return textError(404, 'no backup yet');
  return new Response(obj.body, { headers: { 'Content-Type': 'application/json; charset=utf-8', ...corsHeaders() } });
}

/* ---------------- Route handlers ---------------- */

async function handleCheckSlug(env, slug) {
  if (!validSlug(slug)) return json({ available: false, reason: 'invalid-format' });
  const meta = await getMeta(env, slug);
  // adminLocked (set only by an admin-forced takedown, see handleUnpublish)
  // stays unavailable even after deletedAt — a normal owner unpublish still
  // frees the slug immediately by design, but a DMCA/CSAM/abuse takedown
  // should not let the same slug be reclaimed and republished right away.
  const takenAndLive = meta && (!meta.deletedAt || meta.adminLocked);
  return json({ available: !takenAndLive, reason: (meta && meta.adminLocked) ? 'disabled' : undefined });
}

async function handlePublish(env, request) {
  let body;
  try { body = await request.json(); } catch (e) { return textError(400, 'invalid JSON body'); }
  const { slug, html } = body || {};
  if (!validSlug(slug)) return textError(400, 'invalid or reserved slug');
  if (typeof html !== 'string' || !html) return textError(400, 'missing html');
  if (new TextEncoder().encode(html).length > MAX_HTML_BYTES) {
    return textError(413, 'page too large');
  }
  const existing = await getMeta(env, slug);
  if (existing && existing.adminLocked) return textError(403, 'slug permanently disabled');
  if (existing && !existing.deletedAt) return textError(409, 'slug already taken');

  const token = newToken();
  const tokenHash = await sha256Hex(token);
  const now = Date.now();
  // Ownership tagging is best-effort and purely additive: an absent or
  // invalid Authorization header just means this page publishes the same
  // way it always has (anonymous, owner-token-only). A signed-in owner
  // gets it listed under GET /my/pages too, via the index key below.
  const ownerSub = await requireSession(env, request);

  await env.NOTES_BUCKET.put(slug + '.html', html, {
    httpMetadata: { contentType: 'text/html; charset=utf-8' }
  });
  await putMeta(env, slug, {
    tokenHash,
    createdAt: now,
    updatedAt: now,
    sizeBytes: html.length,
    deletedAt: null,
    ownerSub: ownerSub || null
  });
  if (ownerSub) await env.SLUGS.put('owner:' + ownerSub + ':' + slug, '1');
  return json({ slug, token }, 201);
}

async function handleUpdate(env, request, slug) {
  if (!validSlug(slug)) return textError(400, 'invalid slug');
  let body;
  try { body = await request.json(); } catch (e) { return textError(400, 'invalid JSON body'); }
  const { html, token } = body || {};
  if (typeof html !== 'string' || !html) return textError(400, 'missing html');
  if (typeof token !== 'string' || !token) return textError(401, 'missing token');
  if (new TextEncoder().encode(html).length > MAX_HTML_BYTES) {
    return textError(413, 'page too large');
  }
  const meta = await getMeta(env, slug);
  if (!meta || meta.deletedAt) return textError(404, 'not found');
  const tokenHash = await sha256Hex(token);
  if (!timingSafeEqual(tokenHash, meta.tokenHash)) return textError(403, 'invalid token');

  await env.NOTES_BUCKET.put(slug + '.html', html, {
    httpMetadata: { contentType: 'text/html; charset=utf-8' }
  });
  meta.updatedAt = Date.now();
  meta.sizeBytes = html.length;
  await putMeta(env, slug, meta);
  return json({ ok: true });
}

async function handleUnpublish(env, request, slug) {
  if (!validSlug(slug)) return textError(400, 'invalid slug');
  let body;
  try { body = await request.json(); } catch (e) { body = {}; }
  const { token, adminToken } = body || {};
  const meta = await getMeta(env, slug);
  if (!meta || meta.deletedAt) return textError(404, 'not found');

  // Admin bypass (plan §5a/§8): non-cooperative takedowns (DMCA, abuse,
  // CSAM) don't have the owner's token, so ADMIN_TOKEN lets a force-unpublish
  // through instead. Checked before the owner-token path so an admin never
  // needs a slug's token at all.
  let isAdminTakedown = false;
  if (typeof adminToken === 'string' && adminToken && env.ADMIN_TOKEN) {
    if (!timingSafeEqual(adminToken, env.ADMIN_TOKEN)) return textError(403, 'invalid admin token');
    isAdminTakedown = true;
  } else {
    if (typeof token !== 'string' || !token) return textError(401, 'missing token');
    const tokenHash = await sha256Hex(token);
    if (!timingSafeEqual(tokenHash, meta.tokenHash)) return textError(403, 'invalid token');
  }

  // Snapshot the live content to its own retained key *before* unlinking.
  // Soft-delete alone isn't enough to guarantee the 30-day retention promise
  // (plan §3.5): the slug becomes reclaimable immediately, and a republish
  // under the same slug would overwrite "<slug>.html" — destroying exactly
  // the content a pending report/takedown investigation might need, before
  // the retention window is up. The snapshot is independent of whatever
  // happens to the live slug afterward; handlePurge() below deletes it once
  // it's past SOFT_DELETE_RETENTION_MS.
  const now = Date.now();
  const liveObj = await env.NOTES_BUCKET.get(slug + '.html');
  if (liveObj) {
    await env.NOTES_BUCKET.put(`deleted/${slug}/${now}.html`, liveObj.body, {
      httpMetadata: { contentType: 'text/html; charset=utf-8' }
    });
  }

  // Soft-delete (plan §3.5): unlink immediately (slug 404s). A normal owner
  // unpublish also frees the slug for immediate reclaim by design. An admin-
  // forced takedown does not: adminLocked stays true permanently, so the
  // exact same slug can't just be republished right back by whoever it was
  // taken down from (see handleCheckSlug/handlePublish) — someone here has
  // to consciously clear it (e.g. a manual KV edit) once a takedown is
  // resolved, rather than it silently reopening.
  meta.deletedAt = now;
  if (isAdminTakedown) meta.adminLocked = true;
  await putMeta(env, slug, meta);
  // Drop this slug out of its owner's GET /my/pages listing either way —
  // an admin takedown shouldn't keep showing up in the owner's own page
  // list any more than a normal unpublish would.
  if (meta.ownerSub) await env.SLUGS.delete('owner:' + meta.ownerSub + ':' + slug);
  return json({ ok: true });
}

// Lists every currently-live slug owned by the signed-in account, for a
// "your published pages" view that works across devices without the
// per-page owner token ever having to leave the device it was issued on.
async function handleMyPages(env, request) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  const prefix = 'owner:' + sub + ':';
  const pages = [];
  let cursor;
  do {
    const page = await env.SLUGS.list({ prefix, cursor });
    for (const key of page.keys) {
      const slug = key.name.slice(prefix.length);
      const meta = await getMeta(env, slug);
      if (!meta || meta.deletedAt) continue; // stale index entry (e.g. a purge raced this) — skip rather than list a dead page
      pages.push({ slug, createdAt: meta.createdAt, updatedAt: meta.updatedAt, sizeBytes: meta.sizeBytes });
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return json({ pages });
}

async function handleServe(env, slug) {
  if (!SLUG_RE.test(slug)) return new Response('Not found', { status: 404 });
  const meta = await getMeta(env, slug);
  if (!meta || meta.deletedAt) return new Response('Not found', { status: 404 });
  const obj = await env.NOTES_BUCKET.get(slug + '.html');
  if (!obj) return new Response('Not found', { status: 404 });

  // Security hardening (plan §6): this page is now attacker-reachable at a
  // public URL, unlike the locally-opened export it started as. Restrict
  // script-src so a published note can't be turned into an XSS/phishing
  // vector; the exported HTML's own inline sizing script still runs
  // ('unsafe-inline') but no external script host does.
  const csp = [
    "default-src 'self'",
    "script-src 'unsafe-inline'",
    "style-src 'unsafe-inline'",
    "img-src * data: blob:",
    "frame-src https://www.youtube.com https://www.instagram.com https://open.spotify.com",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'"
  ].join('; ');

  return new Response(obj.body, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': csp,
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'strict-origin-when-cross-origin'
    }
  });
}

// Best-effort rate limit for POST /report/:slug (plan §11 only covers
// /publish and /publish/* via dashboard rules — and even those require a
// Cloudflare zone/domain, unavailable on a bare *.workers.dev deployment).
// A fixed window per IP, stored in the REPORTS namespace: cheap, not
// perfectly accurate (the window slides forward on every report within it,
// so sustained abuse can delay the reset), but enough to stop naive
// spam/DoS against this endpoint and the Slack webhook it can trigger.
const REPORT_RATE_LIMIT_MAX = 5;
const REPORT_RATE_LIMIT_WINDOW_S = 60;
async function checkReportRateLimit(env, ip) {
  const key = 'ratelimit:report:' + ip;
  const raw = await env.REPORTS.get(key);
  const count = raw ? (parseInt(raw, 10) || 0) : 0;
  if (count >= REPORT_RATE_LIMIT_MAX) return false;
  await env.REPORTS.put(key, String(count + 1), { expirationTtl: REPORT_RATE_LIMIT_WINDOW_S });
  return true;
}

async function handleReport(env, request, slug) {
  if (!SLUG_RE.test(slug)) return textError(400, 'invalid slug');
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!(await checkReportRateLimit(env, ip))) {
    return textError(429, 'too many reports from this address — try again in a minute');
  }
  let body;
  try { body = await request.json(); } catch (e) { return textError(400, 'invalid JSON body'); }
  const reason = typeof body?.reason === 'string' ? body.reason.slice(0, 40) : 'other';
  const details = typeof body?.details === 'string' ? body.details.slice(0, 2000) : '';
  // CSAM is split into its own category deliberately (plan §5.1/§5.2): it is
  // the one case where "we don't moderate" doesn't apply. It must be
  // reported to NCMEC's CyberTipline and the content preserved rather than
  // deleted — that response path is a legal/operational process outside
  // this Worker, not something to automate away here.
  const record = {
    slug, reason, details,
    isCsam: reason === 'csam',
    reportedAt: Date.now()
  };
  const key = 'report:' + slug + ':' + record.reportedAt;
  await env.REPORTS.put(key, JSON.stringify(record));

  if (env.REPORT_WEBHOOK_URL) {
    try {
      // Slack (and most incoming-webhook consumers) require a top-level
      // "text" field to render anything at all — a raw JSON dump of
      // `record` with no "text" key gets silently rejected with
      // invalid_payload, which is exactly the kind of failure the catch
      // below would swallow without a trace. `record` itself is untouched
      // and still what gets stored in KV either way.
      const summary = `New report for /${slug}${record.isCsam ? ' — CSAM' : ''}\n`
        + `Reason: ${reason}\n`
        + `Details: ${details || '(none provided)'}`;
      await fetch(env.REPORT_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: summary })
      });
    } catch (e) {
      // Don't fail the report just because alerting failed — the record is
      // already durably stored in KV either way.
    }
  }
  return json({ ok: true });
}

// Purge job (plan §3.5/§12): deletes R2 blobs (and their KV metadata) for
// slugs soft-deleted more than SOFT_DELETE_RETENTION_MS ago, plus the
// pre-overwrite snapshots handleUnpublish() writes under "deleted/". Wired
// to the cron trigger declared in wrangler.toml via the scheduled() export
// below — GET/POST/etc. traffic never touches this, only Cloudflare's
// scheduler does.
async function handlePurge(env) {
  const cutoff = Date.now() - SOFT_DELETE_RETENTION_MS;
  let purged = 0;

  let cursor;
  do {
    const page = await env.SLUGS.list({ prefix: 'slug:', cursor });
    for (const key of page.keys) {
      const raw = await env.SLUGS.get(key.name);
      if (!raw) continue;
      let meta;
      try { meta = JSON.parse(raw); } catch (e) { continue; }
      if (!meta.deletedAt || meta.deletedAt >= cutoff) continue;
      const slug = key.name.slice('slug:'.length);
      // adminLocked slugs stay soft-deleted forever on purpose (see
      // handleUnpublish) — clearing the KV entry here would silently
      // reopen a DMCA/CSAM/abuse takedown for reclaim. The lock itself
      // doesn't expire, but its content is already safely preserved
      // under "deleted/" (see handleUnpublish), so the now-redundant
      // root object can still be freed without weakening the lock.
      if (meta.adminLocked) {
        await env.NOTES_BUCKET.delete(slug + '.html');
        continue;
      }
      await env.NOTES_BUCKET.delete(slug + '.html');
      await env.SLUGS.delete(key.name);
      if (meta.ownerSub) await env.SLUGS.delete('owner:' + meta.ownerSub + ':' + slug);
      purged++;
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);

  let r2Cursor;
  do {
    const page = await env.NOTES_BUCKET.list({ prefix: 'deleted/', cursor: r2Cursor });
    for (const obj of page.objects) {
      const match = obj.key.match(/\/(\d+)\.html$/);
      const ts = match ? parseInt(match[1], 10) : NaN;
      if (!Number.isFinite(ts) || ts >= cutoff) continue;
      await env.NOTES_BUCKET.delete(obj.key);
      purged++;
    }
    r2Cursor = page.truncated ? page.cursor : undefined;
  } while (r2Cursor);

  // Accounts scheduled for deletion (see handleDeleteAccount) whose
  // 30-day grace period has elapsed without the owner signing back in —
  // purge them the same way handleDeleteAccount used to do immediately.
  let acctCursor;
  do {
    const page = await env.ACCOUNTS.list({ prefix: 'user:', cursor: acctCursor });
    for (const key of page.keys) {
      const raw = await env.ACCOUNTS.get(key.name);
      if (!raw) continue;
      let user;
      try { user = JSON.parse(raw); } catch (e) { continue; }
      if (!user.pendingDeletionAt || user.pendingDeletionAt >= cutoff) continue;
      const sub = key.name.slice('user:'.length);
      await purgeAccountData(env, sub);
      purged++;
    }
    acctCursor = page.list_complete ? undefined : page.cursor;
  } while (acctCursor);

  return purged;
}

// Schedules the signed-in account for deletion after a 30-day grace
// period (SOFT_DELETE_RETENTION_MS, same window handleUnpublish's page
// soft-delete uses) rather than deleting anything immediately — signing
// back in with the same Google account during that window cancels it
// (see handleGoogleAuth). The actual purge happens in purgeAccountData,
// invoked by the cron-triggered handlePurge once the grace period
// elapses. Only revokes *this* session, so the device signs out right
// away; other signed-in devices fall off naturally via their own 30-day
// session TTL if the deletion isn't cancelled in time.
async function handleDeleteAccount(env, request) {
  const info = await requireSessionInfo(env, request);
  if (!info) return textError(401, 'sign-in required');
  const { sub, tokenHash } = info;

  const user = await getUser(env, sub);
  const pendingDeletionAt = Date.now();
  if (user) {
    user.pendingDeletionAt = pendingDeletionAt;
    await putUser(env, sub, user);
  }
  await env.ACCOUNTS.delete('session:' + tokenHash);

  return json({ ok: true, pendingDeletionAt });
}

// Permanently removes an account and everything tied to it. Reuses
// handleUnpublish's soft-delete + 30-day retention snapshot for every
// page the account owns, rather than a separate deletion path for those
// — same reasoning applies (a pending report shouldn't lose its evidence
// just because the owner's account is gone). Called only from the purge
// job below, once an account's grace period (see handleDeleteAccount)
// has elapsed.
async function purgeAccountData(env, sub) {
  const prefix = 'owner:' + sub + ':';
  let cursor;
  do {
    const page = await env.SLUGS.list({ prefix, cursor });
    for (const key of page.keys) {
      const slug = key.name.slice(prefix.length);
      const meta = await getMeta(env, slug);
      if (meta && !meta.deletedAt) {
        const now = Date.now();
        const liveObj = await env.NOTES_BUCKET.get(slug + '.html');
        if (liveObj) {
          await env.NOTES_BUCKET.put(`deleted/${slug}/${now}.html`, liveObj.body, {
            httpMetadata: { contentType: 'text/html; charset=utf-8' }
          });
        }
        meta.deletedAt = now;
        await putMeta(env, slug, meta);
      }
      await env.SLUGS.delete(key.name);
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);

  await env.ACCOUNTS.delete('user:' + sub);
  await env.ACCOUNTS.delete('syncmeta:' + sub);
  await env.NOTES_BUCKET.delete('sync/' + sub + '/notes.json');
}

/* ---------------- Publish as Ad ---------------- */

// Verbatim required text — must appear exactly once, unmodified, visible.
// Kept as one constant so the publish-time check and the re-check on every
// edit (handleAdUpdate) can never drift apart.
const AD_ATTRIBUTION_TEXT = "All third-party trademarks, service marks, logos, and brand names appearing in advertisements or on this platform are the property of their respective owners.";
// Matches upload.wikimedia.org, commons.wikimedia.org, and every
// language subdomain of wikipedia.org (en., fr., de., ...), plus the bare
// domains themselves — anything actually hosted under Wikipedia or
// Wikimedia. Suffix-matched rather than an enumerated Set so no language
// edition has to be special-cased in here.
const AD_ALLOWED_IMAGE_HOST_SUFFIXES = ['.wikimedia.org', '.wikipedia.org'];
const AD_ALLOWED_IMAGE_HOST_EXACT = new Set(['wikimedia.org', 'wikipedia.org']);
function isAllowedAdImageHost(host) {
  if (AD_ALLOWED_IMAGE_HOST_EXACT.has(host)) return true;
  return AD_ALLOWED_IMAGE_HOST_SUFFIXES.some(suffix => host.endsWith(suffix));
}
const AD_MAX_IMAGES = 2;
// Video/social embed src is generated entirely by our own client code
// (youTubeEmbedUrl/parseSocialUrl + _socialEmbedSpec), which
// only ever produces these exact hosts — so an exact match is intentional,
// not a suffix match like the image host list. Anything else means the
// block's src was set some other way (e.g. a direct API call bypassing the
// editor UI's parsers), which is exactly what this exists to catch: an ad
// is auto-shown to every user who taps Create, not opt-in like a link.
const AD_ALLOWED_EMBED_HOSTS = new Set([
  'www.youtube.com',    // youTubeEmbedUrl()
  'www.instagram.com',  // _socialEmbedSpec('instagram')
  'open.spotify.com'    // _socialEmbedSpec('spotify')
]);
function isAllowedAdEmbedHost(host) {
  return AD_ALLOWED_EMBED_HOSTS.has(host);
}

// Server-side re-check of the eligibility rules — the client can (and
// should) block the "Publish as Ad" tab from submitting when these fail,
// but that's a UX convenience only; nothing here trusts the client's own
// judgment about its own note. Runs on both initial ad registration
// (handleAdPublish) and every subsequent edit (handleAdUpdate), since an
// owner could edit an already-running ad back out of compliance.
//
// Uses HTMLRewriter (Workers-native streaming HTML parsing — no DOMParser
// available in this runtime) to walk `.blk` blocks and collect just the
// two things the rules care about: text-block contents and image srcs.
async function validateAdEligibility(html) {
  const textBlockContents = [];
  const imageSrcs = [];
  const embedSrcs = [];
  const captionContents = [];
  let currentTextBuf = null; // accumulates text inside the block currently being walked
  let currentCapBuf = null; // same, for the image/video/social caption currently being walked

  const rewriter = new HTMLRewriter()
    .on('.blk[data-type="text"]', {
      element() { currentTextBuf = { text: '' }; textBlockContents.push(currentTextBuf); },
    })
    .on('.blk[data-type="text"] *', {
      text(t) { if (currentTextBuf) currentTextBuf.text += t.text; }
    })
    .on('.blk-img img', {
      element(el) { imageSrcs.push(el.getAttribute('src') || ''); }
    })
    .on('.blk-media-frame iframe, .blk-social-embed iframe', {
      element(el) { embedSrcs.push(el.getAttribute('src') || ''); }
    })
    // Captions on image/video/social blocks. Text can sit directly in the
    // figcaption or inside inline formatting elements, so both are covered.
    .on('.blk-caption figcaption', {
      element(el) {
        currentCapBuf = { text: '', placeholder: el.getAttribute('data-placeholder') === 'true' };
        captionContents.push(currentCapBuf);
      },
      text(t) { if (currentCapBuf) currentCapBuf.text += t.text; }
    })
    .on('.blk-caption figcaption *', {
      text(t) { if (currentCapBuf) currentCapBuf.text += t.text; }
    });

  // HTMLRewriter only does work as the response body is *read* — transform()
  // itself is lazy, so .text() below is what actually drives the walk and
  // populates the arrays above via the handlers' side effects.
  await rewriter.transform(new Response(html)).text();

  // Rule: no added text/captions, blank lines and the attribution line
  // are the only allowed non-empty text blocks.
  const nonBlankBlocks = textBlockContents
    .map(b => b.text.replace(/\s+/g, ' ').trim())
    .filter(t => t.length > 0);
  const attributionOccurrences = nonBlankBlocks.filter(t => t === AD_ATTRIBUTION_TEXT).length;
  const strayText = nonBlankBlocks.filter(t => t !== AD_ATTRIBUTION_TEXT);
  if (attributionOccurrences === 0) return { ok: false, reason: 'missing-attribution' };
  if (attributionOccurrences > 1) return { ok: false, reason: 'duplicate-attribution' };
  if (strayText.length > 0) return { ok: false, reason: 'added-text' };

  // Rule: same for captions — blank lines only, no caption text.
  // data-placeholder="true" is the reliable "never actually edited" signal
  // (cleared on input, not on blur — see the client-side fix). The literal-
  // "Caption" match is kept only as a fallback for notes saved before that
  // fix, where the attribute could already be stripped despite no edit.
  const strayCaptions = captionContents
    .filter(b => !b.placeholder)
    .map(b => b.text.replace(/\s+/g, ' ').trim())
    .filter(t => t.length > 0 && t !== 'Caption');
  if (strayCaptions.length > 0) return { ok: false, reason: 'added-caption' };

  // Rule: attribution block itself must not be shrunk or hidden. Best-effort
  // on the surrounding markup — checks the block and its style attribute for
  // the obvious ways to make text present-but-invisible. Not a full computed-
  // style engine (none available here), but catches the direct cases.
  const attrBlockMatch = html.match(/<[^>]*data-type="text"[^>]*>(?:(?!<\/div>)[\s\S])*?All third-party trademarks[\s\S]*?<\/div>/);
  if (attrBlockMatch) {
    const chunk = attrBlockMatch[0];
    const hiddenPattern = /(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0*)?\s*[;"']|font-size\s*:\s*[0-9](?:px)?\s*[;"'])/i;
    if (hiddenPattern.test(chunk)) return { ok: false, reason: 'attribution-hidden-or-shrunk' };
  }

  // Rule: at most 2 image components.
  if (imageSrcs.length > AD_MAX_IMAGES) return { ok: false, reason: 'too-many-images' };

  // Rule: no device-uploaded images (data: URIs), and any image present
  // must be hotlinked from Wikipedia/Wikimedia.
  for (const src of imageSrcs) {
    if (!src) continue; // an empty/placeholder image slot isn't "containing" an image
    if (/^data:/i.test(src)) return { ok: false, reason: 'device-image' };
    let host;
    try { host = new URL(src).hostname.toLowerCase(); } catch (e) { return { ok: false, reason: 'invalid-image-src' }; }
    if (!isAllowedAdImageHost(host)) return { ok: false, reason: 'non-wikimedia-image' };
  }

  // Rule: any video/social embed must be one our own editor generates —
  // see AD_ALLOWED_EMBED_HOSTS above for why this is exact-match and why
  // it exists at all (this is the only server-side check on embed src;
  // nothing else in this function looks at video/social blocks). Also
  // caps each platform at one embed — each of the 5 allowed hosts maps to
  // exactly one platform, so counting by host IS counting by platform.
  const embedHostCounts = new Map();
  for (const src of embedSrcs) {
    if (!src) continue; // an empty/placeholder embed slot isn't "containing" an embed
    let u;
    try { u = new URL(src); } catch (e) { return { ok: false, reason: 'invalid-embed-src' }; }
    if (u.protocol !== 'https:') return { ok: false, reason: 'invalid-embed-src' };
    const host = u.hostname.toLowerCase();
    if (!isAllowedAdEmbedHost(host)) return { ok: false, reason: 'non-allowed-embed' };
    embedHostCounts.set(host, (embedHostCounts.get(host) || 0) + 1);
  }
  if (Array.from(embedHostCounts.values()).some(c => c > 1)) {
    return { ok: false, reason: 'duplicate-platform-embed' };
  }

  return { ok: true };
}

/* ---- D1 helpers ---- */

async function getCreditBalance(env, sub) {
  const row = await env.ADS_DB.prepare(
    'SELECT COALESCE(SUM(delta), 0) AS balance FROM view_credits_ledger WHERE owner_sub = ?'
  ).bind(sub).first();
  return row ? row.balance : 0;
}

/* ---- RevenueCat webhook: credits the ledger off a verified purchase ---- */

// product_id (as configured in Play Console/RevenueCat, section 3 of the
// setup guide) -> views granted. Add a row here for every view-package
// product created. Kept server-side and not trusted from the client at all.
const AD_VIEW_PACKAGES = {
  'nb_ad_views_1000': 1000,
  'nb_ad_views_5000': 5000,
  'nb_ad_views_20000': 20000,
  'nb_ad_views_100000': 100000,
};

async function handleRevenueCatWebhook(env, request) {
  const auth = request.headers.get('Authorization') || '';
  if (!env.REVENUECAT_WEBHOOK_SECRET || !timingSafeEqual(auth, env.REVENUECAT_WEBHOOK_SECRET)) {
    return textError(401, 'invalid webhook auth');
  }
  let body;
  try { body = await request.json(); } catch (e) { return textError(400, 'invalid JSON body'); }
  const event = body && body.event;
  if (!event || !event.id) return textError(400, 'missing event');

  // NON_RENEWING_PURCHASE (RevenueCat's type for a consumable one-time
  // product bought again) and INITIAL_PURCHASE (the very first buy) grant
  // views. A refunded consumable arrives as CANCELLATION with cancel_reason
  // CUSTOMER_SUPPORT and claws those views back below. Every other event
  // type is ignored.
  const isRefund = event.type === 'CANCELLATION' && event.cancel_reason === 'CUSTOMER_SUPPORT';
  if (!isRefund && event.type !== 'NON_RENEWING_PURCHASE' && event.type !== 'INITIAL_PURCHASE') {
    return json({ ok: true, ignored: event.type });
  }
  const views = AD_VIEW_PACKAGES[event.product_id];
  if (!views) return json({ ok: true, ignored: 'unrecognized-product:' + event.product_id });

  // app_user_id must be the app's Google `sub` for this to land in the
  // right person's balance — set on the client via
  // Purchases.configure({ appUserID: sub }) after Google sign-in, not left
  // as RevenueCat's own anonymous ID. Flagging this because it's an easy
  // thing to have missed when the SDK was first wired up for the Pro
  // unlock, where the app-user-id didn't matter as much.
  const sub = event.app_user_id;
  if (!sub) return textError(400, 'missing app_user_id');

  if (isRefund) {
    // Negative ledger row for the refunded package. Keyed on the store
    // transaction (falling back to the event id) so a repeated or
    // redelivered CANCELLATION can't debit the same purchase twice.
    // The balance is allowed to go negative — handleAdPublish refuses to
    // spend from a balance that doesn't cover the request, so a negative one
    // blocks new ads — and any ads the account still has running are pulled
    // from rotation, since their views were paid for by a purchase that no
    // longer stands.
    await env.ADS_DB.prepare(
      'INSERT OR IGNORE INTO view_credits_ledger (owner_sub, delta, reason, rc_event_id, created_at) VALUES (?, ?, ?, ?, ?)'
    ).bind(sub, -views, 'refund', 'refund:' + String(event.transaction_id || event.id), Date.now()).run();
    if ((await getCreditBalance(env, sub)) < 0) {
      await env.ADS_DB.prepare(
        "UPDATE ads SET status = 'unpublished', updated_at = ? WHERE owner_sub = ? AND status = 'active'"
      ).bind(Date.now(), sub).run();
    }
    return json({ ok: true, refunded: views });
  }

  // OR IGNORE on rc_event_id: RevenueCat retries webhook delivery on
  // non-2xx and can occasionally redeliver even after a 200 was returned —
  // this makes crediting idempotent regardless of why the retry happened.
  await env.ADS_DB.prepare(
    'INSERT OR IGNORE INTO view_credits_ledger (owner_sub, delta, reason, rc_event_id, created_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(sub, views, 'purchase', String(event.id), Date.now()).run();

  return json({ ok: true });
}

/* ---- Ad handlers ---- */

// Registers an already-published page (published the normal way, via
// POST /publish — same slug, same owner token) as a running ad. Doesn't
// touch R2/SLUGS at all; only reads the page back to re-validate eligibility
// server-side, then writes the D1 side.
async function handleAdPublish(env, request) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  let body;
  try { body = await request.json(); } catch (e) { return textError(400, 'invalid JSON body'); }
  const { slug, token, views } = body || {};
  if (!validSlug(slug)) return textError(400, 'invalid slug');
  if (!Number.isInteger(views) || views <= 0) return textError(400, 'invalid views');

  const meta = await getMeta(env, slug);
  if (!meta || meta.deletedAt) return textError(404, 'slug not published');
  if (meta.ownerSub !== sub) return textError(403, 'not the owner of this page');
  if (typeof token !== 'string' || !token || !timingSafeEqual(await sha256Hex(token), meta.tokenHash)) {
    return textError(403, 'invalid token');
  }

  const existingAd = await env.ADS_DB.prepare('SELECT slug FROM ads WHERE slug = ?').bind(slug).first();
  if (existingAd) return textError(409, 'already registered as an ad — use PUT to edit or top up separately');

  const obj = await env.NOTES_BUCKET.get(slug + '.html');
  if (!obj) return textError(404, 'page content missing');
  const html = await obj.text();
  const eligibility = await validateAdEligibility(html);
  if (!eligibility.ok) return textError(422, 'not eligible: ' + eligibility.reason);

  const balance = await getCreditBalance(env, sub);
  if (balance < views) return textError(402, 'insufficient view credits');

  const now = Date.now();
  // The balance check above is only a fast path — it and the debit below
  // aren't atomic, so two simultaneous publishes could both pass it and
  // overdraw the ledger. The batch (one D1 transaction) re-checks the balance
  // inside itself: the ad row is inserted only if the balance still covers
  // `views`, and the debit only if that ad row landed, so a failure or race
  // can't leave the ledger debited with no ad (or an ad with no debit).
  // The rotation slot is claimed separately beforehand; losing the race
  // just leaves an unused number, which the ordering already tolerates.
  const seqRow = await env.ADS_DB.prepare(
    'UPDATE ad_rotation_seq SET next_value = next_value + 1 WHERE id = 1 RETURNING next_value - 1 AS assigned'
  ).first();
  const rotationOrder = seqRow.assigned;
  const results = await env.ADS_DB.batch([
    env.ADS_DB.prepare(
      `INSERT INTO ads (slug, owner_sub, views_total, views_used, rotation_order, status, created_at, updated_at)
       SELECT ?, ?, ?, 0, ?, 'active', ?, ?
       WHERE (SELECT COALESCE(SUM(delta), 0) FROM view_credits_ledger WHERE owner_sub = ?) >= ?`
    ).bind(slug, sub, views, rotationOrder, now, now, sub, views),
    env.ADS_DB.prepare(
      `INSERT INTO view_credits_ledger (owner_sub, delta, reason, slug, created_at)
       SELECT ?, ?, 'allocate', ?, ?
       WHERE EXISTS (SELECT 1 FROM ads WHERE slug = ? AND owner_sub = ? AND created_at = ?)`
    ).bind(sub, -views, slug, now, slug, sub, now),
  ]);
  if (!results[0].meta.changes) return textError(402, 'insufficient view credits');

  return json({ ok: true, slug, viewsTotal: views }, 201);
}

// Re-validates and swaps the page content for an already-running ad — the
// "Save Changes" action in the Publish as Ad tab. Reuses the same page
// write handleUpdate does; an ad that fails re-validation is rejected
// outright (nothing is written, the ad keeps running on its prior content)
// rather than silently pulled from rotation, so a bad edit can't quietly
// kill a campaign without the owner knowing why.
async function handleAdUpdate(env, request, slug) {
  if (!validSlug(slug)) return textError(400, 'invalid slug');
  let body;
  try { body = await request.json(); } catch (e) { return textError(400, 'invalid JSON body'); }
  const { html, token } = body || {};
  if (typeof html !== 'string' || !html) return textError(400, 'missing html');
  if (typeof token !== 'string' || !token) return textError(401, 'missing token');
  if (new TextEncoder().encode(html).length > MAX_HTML_BYTES) return textError(413, 'page too large');

  const meta = await getMeta(env, slug);
  if (!meta || meta.deletedAt) return textError(404, 'not found');
  if (!timingSafeEqual(await sha256Hex(token), meta.tokenHash)) return textError(403, 'invalid token');

  const ad = await env.ADS_DB.prepare('SELECT slug FROM ads WHERE slug = ?').bind(slug).first();
  if (!ad) return textError(404, 'not registered as an ad');

  const eligibility = await validateAdEligibility(html);
  if (!eligibility.ok) return textError(422, 'not eligible: ' + eligibility.reason);

  await env.NOTES_BUCKET.put(slug + '.html', html, { httpMetadata: { contentType: 'text/html; charset=utf-8' } });
  meta.updatedAt = Date.now();
  meta.sizeBytes = html.length;
  await putMeta(env, slug, meta);
  await env.ADS_DB.prepare('UPDATE ads SET updated_at = ? WHERE slug = ?').bind(Date.now(), slug).run();
  return json({ ok: true });
}

// Pulls an ad out of rotation and forfeits whatever views it had left (per
// spec — no ledger refund). Deliberately doesn't touch the underlying
// published page at all; unpublishing the page itself is still the
// existing DELETE /publish/:slug, a separate action in the Publish to Web
// tab. The two are independent: an owner can stop an ad while leaving the
// page live, or vice versa.
async function handleAdUnpublish(env, request, slug) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  if (!validSlug(slug)) return textError(400, 'invalid slug');
  const ad = await env.ADS_DB.prepare('SELECT owner_sub, status FROM ads WHERE slug = ?').bind(slug).first();
  if (!ad) return textError(404, 'not found');
  if (ad.owner_sub !== sub) return textError(403, 'not the owner of this ad');
  if (ad.status === 'unpublished') return json({ ok: true }); // already done, idempotent
  await env.ADS_DB.prepare('UPDATE ads SET status = ?, updated_at = ? WHERE slug = ?')
    .bind('unpublished', Date.now(), slug).run();
  return json({ ok: true });
}

// GET /ads/mine — the Publish as Ad tab's "views so far" display, plus
// remaining credit balance for buying more.
async function handleMyAds(env, request) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  const { results } = await env.ADS_DB.prepare(
    'SELECT slug, views_total, views_used, status, created_at, updated_at FROM ads WHERE owner_sub = ? ORDER BY created_at DESC'
  ).bind(sub).all();
  const balance = await getCreditBalance(env, sub);
  return json({ ads: results || [], creditBalance: balance });
}

// GET /ads/next — called from the Create screen instead of always loading
// the pristine template. Public (no session needed — any device browsing
// Create can be handed the next ad in rotation), returns null when nothing
// is active so the client falls back to the pristine template exactly as
// it does today.
async function handleAdNext(env, request) {
  const activeCount = await env.ADS_DB.prepare("SELECT COUNT(*) AS n FROM ads WHERE status = 'active'").first();
  if (!activeCount || activeCount.n === 0) return json({ ad: null });

  // One statement, one implicit D1 transaction: advance the cursor to the
  // next active ad past its current position, wrapping to the first active
  // ad if the cursor's past the end — or leaving it unmoved (fallback to
  // its own current value) in the never-expected case both subqueries miss.
  // This is what makes concurrent Create taps each get a distinct ad
  // instead of racing onto the same one.
  const cursorRow = await env.ADS_DB.prepare(`
    UPDATE ad_rotation_cursor
    SET position = COALESCE(
      (SELECT rotation_order FROM ads WHERE status = 'active' AND rotation_order > ad_rotation_cursor.position ORDER BY rotation_order ASC LIMIT 1),
      (SELECT rotation_order FROM ads WHERE status = 'active' ORDER BY rotation_order ASC LIMIT 1),
      ad_rotation_cursor.position
    )
    WHERE id = 1
    RETURNING position
  `).first();

  const ad = await env.ADS_DB.prepare(
    "SELECT slug FROM ads WHERE status = 'active' AND rotation_order = ?"
  ).bind(cursorRow.position).first();
  if (!ad) return json({ ad: null }); // lost a race against an unpublish between the two queries above — next tap retries

  const obj = await env.NOTES_BUCKET.get(ad.slug + '.html');
  if (!obj) return json({ ad: null });
  return json({ ad: { slug: ad.slug, html: await obj.text() } });
}

// POST /ads/:slug/view — the edit-time decrement: called once the person
// actually starts editing the ad-template handed to them by GET /ads/next
// (not merely on seeing it), per the agreed "edit-time is truer" tracking.
// The UPDATE's own WHERE clause (status='active' AND views_used < views_total)
// makes the increment-and-cap-check atomic and self-limiting — no separate
// read-then-write race window where two simultaneous edits could both
// slip in under the cap.
async function handleAdView(env, request, slug) {
  if (!validSlug(slug)) return textError(400, 'invalid slug');
  const row = await env.ADS_DB.prepare(`
    UPDATE ads
    SET views_used = views_used + 1,
        updated_at = ?,
        status = CASE WHEN views_used + 1 >= views_total THEN 'exhausted' ELSE status END
    WHERE slug = ? AND status = 'active' AND views_used < views_total
    RETURNING views_used, views_total, status
  `).bind(Date.now(), slug).first();
  // Not finding a row to update (already exhausted/unpublished/unknown
  // slug, or a race with another view landing the exact same moment) isn't
  // an error worth surfacing to the editor — the view simply isn't counted.
  return json({ ok: true, counted: !!row, ...(row || {}) });
}

/* ---------------- Router ---------------- */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;
    const method = request.method;

    if (method === 'OPTIONS') return new Response(null, { headers: corsHeaders() });

    try {
      if (method === 'GET' && pathname.startsWith('/check-slug/')) {
        return handleCheckSlug(env, decodeURIComponent(pathname.slice('/check-slug/'.length)));
      }
      if (method === 'POST' && pathname === '/publish') {
        return handlePublish(env, request);
      }
      if (method === 'PUT' && pathname.startsWith('/publish/')) {
        return handleUpdate(env, request, decodeURIComponent(pathname.slice('/publish/'.length)));
      }
      if (method === 'DELETE' && pathname.startsWith('/publish/')) {
        return handleUnpublish(env, request, decodeURIComponent(pathname.slice('/publish/'.length)));
      }
      if (method === 'GET' && pathname.startsWith('/@')) {
        return handleServe(env, decodeURIComponent(pathname.slice('/@'.length)));
      }
      if (method === 'POST' && pathname.startsWith('/report/')) {
        return handleReport(env, request, decodeURIComponent(pathname.slice('/report/'.length)));
      }
      if (method === 'POST' && pathname === '/auth/google') {
        return handleGoogleAuth(env, request);
      }
      if (method === 'POST' && pathname === '/auth/signout') {
        return handleSignOut(env, request);
      }
      if (method === 'DELETE' && pathname === '/account') {
        return handleDeleteAccount(env, request);
      }
      if (method === 'PUT' && pathname === '/sync/notes') {
        return handleSyncPush(env, request);
      }
      if (method === 'GET' && pathname === '/sync/notes') {
        return handleSyncPull(env, request);
      }
      if (method === 'GET' && pathname === '/my/pages') {
        return handleMyPages(env, request);
      }
      if (method === 'POST' && pathname === '/ads/publish') {
        return handleAdPublish(env, request);
      }
      if (method === 'GET' && pathname === '/ads/next') {
        return handleAdNext(env, request);
      }
      if (method === 'GET' && pathname === '/ads/mine') {
        return handleMyAds(env, request);
      }
      if (method === 'PUT' && pathname.startsWith('/ads/')) {
        return handleAdUpdate(env, request, decodeURIComponent(pathname.slice('/ads/'.length)));
      }
      if (method === 'POST' && pathname.startsWith('/ads/') && pathname.endsWith('/view')) {
        return handleAdView(env, request, decodeURIComponent(pathname.slice('/ads/'.length, -'/view'.length)));
      }
      if (method === 'DELETE' && pathname.startsWith('/ads/')) {
        return handleAdUnpublish(env, request, decodeURIComponent(pathname.slice('/ads/'.length)));
      }
      if (method === 'POST' && pathname === '/webhooks/revenuecat') {
        return handleRevenueCatWebhook(env, request);
      }
      // Manual trigger for the same purge scheduled() runs nightly (see
      // below) — lets you test it by just visiting a URL in a browser,
      // no terminal/wrangler needed. Takes the admin token as a query
      // param rather than a header/body since that's the only thing a
      // browser address bar can send; the tradeoff is the token then sits
      // in browser history and any server access logs, so this is meant
      // for a one-off manual test (see remaining-steps.md §14), not
      // something to leave linked or bookmarked long-term.
      if (method === 'GET' && pathname === '/debug-purge') {
        const provided = url.searchParams.get('adminToken');
        if (!provided || !env.ADMIN_TOKEN || !timingSafeEqual(provided, env.ADMIN_TOKEN)) {
          return textError(403, 'invalid admin token');
        }
        const purged = await handlePurge(env);
        return json({ ok: true, purged });
      }
      return textError(404, 'not found');
    } catch (e) {
      return textError(500, 'internal error: ' + (e && e.message));
    }
  },

  // Invoked by Cloudflare on the cron schedule in wrangler.toml (daily,
  // 3am UTC). ctx.waitUntil keeps the Worker alive until the purge loop
  // finishes instead of it being killed once this function returns.
  async scheduled(event, env, ctx) {
    ctx.waitUntil(handlePurge(env));
  }
};
