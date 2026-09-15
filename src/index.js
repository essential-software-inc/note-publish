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
    'Access-Control-Allow-Headers': 'Content-Type'
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
  if (!user) {
    user = { sub: identity.sub, email: identity.email, createdAt: now };
  } else {
    // Email can legitimately change on Google's side between sign-ins;
    // keep it current rather than pinned to whatever it was at signup.
    user.email = identity.email;
  }
  user.lastSignInAt = now;
  await putUser(env, identity.sub, user);
  const sessionToken = await createSession(env, identity.sub);
  return json({ sessionToken, sub: identity.sub, email: identity.email });
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
    "frame-src https://www.youtube.com https://www.instagram.com",
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

  return purged;
}

// Deletes the signed-in account and everything tied to it (plan: account
// deletion). Reuses handleUnpublish's soft-delete + 30-day retention
// snapshot for every page this account owns, rather than a separate
// deletion path for those — same reasoning applies (a pending report
// shouldn't lose its evidence just because the owner deleted their
// account). Only revokes *this* session; other signed-in devices fall
// off naturally via their own 30-day session TTL once the account record
// backing them is gone.
async function handleDeleteAccount(env, request) {
  const info = await requireSessionInfo(env, request);
  if (!info) return textError(401, 'sign-in required');
  const { sub, tokenHash } = info;

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
  await env.ACCOUNTS.delete('session:' + tokenHash);
  await env.NOTES_BUCKET.delete('sync/' + sub + '/notes.json');

  return json({ ok: true });
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
