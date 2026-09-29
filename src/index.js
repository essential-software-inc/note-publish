/**
 * Publish-to-Web backend for Note Builder.
 * Implements publish-feature-plan.md sections 3-6, plus Google sign-in and
 * cross-device account sync (notes backup + published-page ownership).
 *
 * Bindings expected (see wrangler.toml):
 *   NOTES_BUCKET  - R2 bucket, stores "<slug>.html", "sync/<sub>/notes.json",
 *                   "story-images/<slug>" (ring-avatar blobs for the
 *                   Stories feature — see storeStoryImage/handleServeStoryImage
 *                   and storeStoryCardImages/handleServeStoryCardImage for
 *                   the ring avatar vs. Subscribed-feed card thumbnails),
 *                   and "profile-images/<sub>" (account profile pictures —
 *                   see handleSetProfileImage/handleServeProfileImage)
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
 *   ADS_DB        - D1 database. Originally ads-only (round-robin cursor +
 *                   view-credit ledger, see migrations/0001_ads.sql; also
 *                   ad_viewers, a reporting-only unique-viewer dedup table,
 *                   see migrations/0002_ad_viewers.sql — it never gates
 *                   spend or the views_used/views_total counters, which are
 *                   unrelated and unchanged by it). Also holds stories,
 *                   subscriptions, and story_seen (migrations/0003_stories.sql;
 *                   the story card's description/tags/note-created time are
 *                   migrations/0009_story_card_fields.sql),
 *                   plus likes (migrations/0006_likes.sql), and published_notes, an
 *                   indexed mirror of the SLUGS "owner:<sub>:<slug>" keys used only for
 *                   GET /account/published-notes' keyset pagination (migrations/0010_published_notes.sql),
 *                   for the Stories feature — same rationale as the ads
 *                   tables: feed/ring queries need real joins that KV can't
 *                   do. Page HTML/slugs/tokens stay in SLUGS/NOTES_BUCKET as
 *                   before — a story or an ad IS a published page, just also
 *                   indexed here for the queries that need it.
 *   REVENUECAT_WEBHOOK_SECRET (secret) - must match the "Authorization Header
 *                   value" configured on the RevenueCat project's webhook
 *                   (Project settings → Integrations → Webhooks) — see
 *                   handleRevenueCatWebhook. Without this set the webhook
 *                   endpoint refuses everything (fail closed).
 *
 * Rate limiting on POST /publish and PUT /publish/:slug is configured via
 * Cloudflare's dashboard Rate Limiting Rules (plan §4) as the primary
 * defense, PLUS an in-code per-IP backstop (checkPublishRateLimit) so the
 * two endpoints that write to R2/D1 are never left unthrottled if the
 * dashboard rule is missing, misconfigured, or reset. GET /@:slug,
 * /check-slug/:slug, and /meta/:slug are intentionally left open
 * (read-only, cheap).
 */

const MAX_HTML_BYTES = 2 * 1024 * 1024; // 2MB — plan §6, tune as needed
// Backup images are stored one object each under sync/<sub>/img/<id> rather
// than embedded in the single notes.json, so the backup file itself stays
// small (text only) and a sync only ever uploads images it hasn't sent before.
// The app already downsizes every image to ~1600px JPEG, so a single image is
// normally a few hundred KB; this is a generous ceiling, not a target.
const MAX_SYNC_IMAGE_BYTES = 6 * 1024 * 1024;
const MAX_SYNC_IMAGES_PER_ACCOUNT = 2000;
const SYNC_IMAGE_ID_RE = /^[A-Za-z0-9_-]{1,80}$/;
const SYNC_IMAGE_GC_MIN_AGE_MS = 14 * 24 * 60 * 60 * 1000; // never delete a still-fresh upload — see gcSyncImages
const MAX_SYNC_BYTES = 8 * 1024 * 1024; // notes backups carry embedded images, so a higher cap than a single published page
// Per-account cap on simultaneously-live published pages. At MAX_HTML_BYTES
// each this bounds one account's worst-case R2 footprint to ~1GB; well
// above any legitimate usage pattern, but closes off unbounded growth from
// a compromised/scripted account. Anonymous (no ownerSub) publishes aren't
// covered by this cap since there's no account to count against — they're
// covered by the IP-based checkPublishRateLimit below instead.
const MAX_PAGES_PER_ACCOUNT = 500;
// Backstop rate limit for POST /publish and PUT /publish/:slug (see header
// comment). Same best-effort fixed-window approach as
// checkReportRateLimit — not perfectly accurate under sustained abuse, but
// enough to stop a naive scripted loop from running up R2 PUTs/storage
// before the dashboard rule (or an operator) catches it.
const PUBLISH_RATE_LIMIT_MAX = 20;
const PUBLISH_RATE_LIMIT_WINDOW_S = 60;
const SLUG_RE = /^[a-z0-9-]{3,48}$/;
const RESERVED_SLUGS = new Set([
  'admin', 'api', 'report', 'reports', 'check-slug', 'meta', 'publish', 'n',
  'www', 'assets', 'static', 'favicon.ico', 'robots.txt', 'health',
  'auth', 'sync', 'my'
]);
const SOFT_DELETE_RETENTION_MS = 30 * 24 * 60 * 60 * 1000; // 30 days, plan §3.5
// CSAM-reported pages and their report records are held for 18 months (548 days),
// counted from the report (or, for dismissed report records, from dismissal). 18 U.S.C.
// § 2258A(h) requires preservation for 1 year from the NCMEC CyberTipline submission;
// the extra 6 months covers the gap between a report arriving and the manual NCMEC filing.
const CSAM_RETENTION_MS = 548 * 24 * 60 * 60 * 1000;
const CSAM_HOLD_PREFIX = 'csamhold:'; // SLUGS key: csamhold:<slug> = {until, etag}, auto-expires via KV TTL
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days — re-issued on every successful /auth/google, not sliding
const MAX_VIEWER_ID_LEN = 200; // client sends a UUID-ish string; generous cap against abuse, not a format check

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, If-Match, If-None-Match, X-Action-Time',
    // Without this a browser/WebView hides the ETag response header from
    // fetch(), so the app's backup If-Match check could never engage.
    'Access-Control-Expose-Headers': 'ETag, Retry-After, X-Server-Time',
    // Lets the app measure how far its own clock is from ours, so the
    // X-Action-Time it sends (latest-tap-wins) isn't skewed by a slow or fast phone clock.
    'X-Server-Time': String(Date.now())
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

/* ---------------- Opaque author IDs ---------------- */

// What viewers' devices see instead of an account's Google `sub`. See
// migrations/0008_authors.sql. The JSON field keeps its old name (`authorSub`,
// `subs`) so app builds already in the wild keep working; the value is just
// opaque now.
const AUTHOR_ID_RE = /^a_[a-f0-9]{32}$/;
// Older app builds still send a raw sub back (subscribe, profile picture URL
// for their own account, follows queued offline). Accept it on INPUT only, so
// nothing breaks during rollout. Set false once old builds have aged out.
const ACCEPT_LEGACY_SUB_INPUT = true;
function newAuthorId() {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return 'a_' + [...b].map(x => x.toString(16).padStart(2, '0')).join('');
}
async function authorIdFor(env, sub) {
  if (!sub) return null;
  const row = await env.ADS_DB.prepare('SELECT author_id FROM authors WHERE sub = ?').bind(sub).first();
  if (row) return row.author_id;
  await env.ADS_DB.prepare('INSERT OR IGNORE INTO authors (sub, author_id, created_at) VALUES (?, ?, ?)')
    .bind(sub, newAuthorId(), Date.now()).run();
  const made = await env.ADS_DB.prepare('SELECT author_id FROM authors WHERE sub = ?').bind(sub).first();
  return made ? made.author_id : null;
}
// subs[] -> { sub: authorId }, creating any that are missing.
async function authorIdsFor(env, subs) {
  const out = {};
  const uniq = [...new Set(subs.filter(Boolean))];
  for (let i = 0; i < uniq.length; i += 80) {
    const chunk = uniq.slice(i, i + 80);
    const { results } = await env.ADS_DB.prepare(
      'SELECT sub, author_id FROM authors WHERE sub IN (' + chunk.map(() => '?').join(',') + ')'
    ).bind(...chunk).all();
    results.forEach(r => { out[r.sub] = r.author_id; });
  }
  for (const sub of uniq) if (!out[sub]) out[sub] = await authorIdFor(env, sub);
  return out;
}
// A path/param from a client -> the real sub, or null if it names nobody.
async function resolveAuthorParam(env, param) {
  if (typeof param !== 'string' || !param) return null;
  if (AUTHOR_ID_RE.test(param)) {
    const row = await env.ADS_DB.prepare('SELECT sub FROM authors WHERE author_id = ?').bind(param).first();
    return row ? row.sub : null;
  }
  return ACCEPT_LEGACY_SUB_INPUT ? param : null;
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

const PROFILE_NAME_MAX = 30;

// Cosmetic-only display name (plan: Stories feature) set from the Log Out
// confirm dialog. Not unique, not the real identity — email stays that.
// Shown only on Subscribed-feed note cards, before the title.
async function handleSetProfileName(env, request) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  let body;
  try { body = await request.json(); } catch (e) { return textError(400, 'invalid JSON body'); }
  let { name } = body || {};
  if (typeof name !== 'string') return textError(400, 'missing name');
  name = name.trim().slice(0, PROFILE_NAME_MAX);
  const user = (await getUser(env, sub)) || {};
  user.profileName = name || null;
  await putUser(env, sub, user);
  return json({ ok: true, profileName: user.profileName });
}

// GET /account/profile-name — reads back the signed-in account's own
// cosmetic display name (the Log Out dialog previously only ever cached
// its last local write; this is what lets a second device, or a
// reinstall, pick up a name set elsewhere instead of showing blank).
async function handleGetProfileName(env, request) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  const user = await getUser(env, sub);
  return json({ ok: true, profileName: (user && user.profileName) || null, authorId: await authorIdFor(env, sub) });
}

// R2 key for an account's profile picture. One object per sub
// (overwritten on re-upload), mirroring storyImageKey — see that
// function's note on why this lives in R2 rather than as a data: URI in
// KV/D1.
function profileImageKey(sub) {
  return `profile-images/${sub}`;
}

// Same cap as STORY_IMAGE_MAX_BYTES, applied to the decoded bytes of a
// profile picture upload. Kept as its own constant (rather than reusing
// STORY_IMAGE_MAX_BYTES directly) since the two caps protect unrelated
// uploads and aren't meant to move together if one changes later.
const PROFILE_IMAGE_MAX_BYTES = 300 * 1024;

// POST /account/profile-image — body: { dataUrl } where dataUrl is a
// data: URI. The client already compresses/downscales the picked image
// client-side with the same pipeline used for in-note images
// (downscaleImageForEmbed) before sending it here, so this only needs to
// decode and cap it, not re-encode. { dataUrl: null } clears the picture.
// Decoded bytes are stored in R2 under profileImageKey, never in KV —
// same reasoning as storeStoryImage.
async function handleSetProfileImage(env, request) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  let body;
  try { body = await request.json(); } catch (e) { return textError(400, 'invalid JSON body'); }
  const dataUrl = body && body.dataUrl;

  await env.NOTES_BUCKET.delete(profileImageKey(sub));
  const user = (await getUser(env, sub)) || {};

  if (dataUrl === null || dataUrl === undefined || dataUrl === '') {
    user.hasProfileImage = false;
    await putUser(env, sub, user);
    return json({ ok: true, hasProfileImage: false });
  }
  if (typeof dataUrl !== 'string') return textError(400, 'invalid dataUrl');

  const m = /^data:([^;,]*)(;base64)?,(.*)$/s.exec(dataUrl);
  if (!m) return textError(400, 'invalid dataUrl');
  const contentType = m[1] || 'image/jpeg';
  if (!/^image\//.test(contentType)) return textError(400, 'not an image');

  const isBase64 = !!m[2];
  let bytes;
  try {
    if (isBase64) {
      const binary = atob(m[3]);
      bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    } else {
      bytes = new TextEncoder().encode(decodeURIComponent(m[3]));
    }
  } catch (e) {
    return textError(400, 'malformed dataUrl');
  }
  if (bytes.byteLength > PROFILE_IMAGE_MAX_BYTES) return textError(413, 'image too large');

  await env.NOTES_BUCKET.put(profileImageKey(sub), bytes, { httpMetadata: { contentType } });
  user.hasProfileImage = true;
  await putUser(env, sub, user);
  return json({ ok: true, hasProfileImage: true });
}

// GET /account/profile-image/:authorId — serves the R2-stored profile picture
// for any account. Public, like /stories/image/:slug — the story strip
// needs to load other people's avatars, not just the signed-in viewer's
// own. A sub with no picture (never set, or cleared) 404s; the client's
// onerror avatar fallback chain (profile picture -> story's first image
// -> initial letter) already handles that.
async function handleServeProfileImage(env, param, request) {
  // The URL carries the opaque author ID (older builds may still send the sub
  // for their own picture — see ACCEPT_LEGACY_SUB_INPUT).
  const sub = await resolveAuthorParam(env, param);
  if (!sub) return textError(404, 'not found');
  // A picture exists to sit on a story, so it's only served while its owner has
  // at least one live story — or to the owner themself (they send their session
  // token). Anyone else, including someone holding the author ID, gets the same
  // 404 as for a missing picture, so nothing reveals whether one exists.
  const viewer = await requireSession(env, request);
  const isOwner = !!viewer && viewer === sub;
  if (!isOwner) {
    const live = await env.ADS_DB.prepare('SELECT 1 AS x FROM stories WHERE author_sub = ? LIMIT 1').bind(sub).first();
    if (!live) return textError(404, 'not found');
  }
  const obj = await env.NOTES_BUCKET.get(profileImageKey(sub));
  if (!obj) return textError(404, 'not found');
  return new Response(obj.body, {
    headers: {
      'Content-Type': (obj.httpMetadata && obj.httpMetadata.contentType) || 'application/octet-stream',
      // Owner-only responses must not sit in shared caches after stories go away.
      'Cache-Control': isOwner ? 'private, max-age=300' : 'public, max-age=300',
      ...corsHeaders()
    }
  });
}

async function createSession(env, sub) {
  const token = newToken();
  const tokenHash = await sha256Hex(token);
  const ttl = { expirationTtl: Math.ceil(SESSION_TTL_MS / 1000) };
  // `idx: true` = this session has an entry in the per-account index below, so
  // handleDeleteAccount can revoke it. Sessions from before the index existed
  // lack the flag and are checked against the account's deletion state instead
  // (see requireSessionInfo) until they expire.
  await env.ACCOUNTS.put('session:' + tokenHash, JSON.stringify({ sub, expiresAt: Date.now() + SESSION_TTL_MS, idx: true }), ttl);
  await env.ACCOUNTS.put('usess:' + sub + ':' + tokenHash, '1', ttl);
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
  if (!session.idx) {
    // Pre-index session: can't be found by account, so ask the account instead.
    const user = await getUser(env, session.sub);
    if (user && user.pendingDeletionAt) {
      await env.ACCOUNTS.delete('session:' + tokenHash);
      return null;
    }
  }
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
  return json({ sessionToken, sub: identity.sub, email: identity.email, authorId: await authorIdFor(env, identity.sub), deletionCancelled });
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
    try {
      const raw = await env.ACCOUNTS.get('session:' + tokenHash);
      const sess = raw ? JSON.parse(raw) : null;
      if (sess && sess.sub) await env.ACCOUNTS.delete('usess:' + sess.sub + ':' + tokenHash);
    } catch (e) { /* index entry just expires on its own */ }
    await env.ACCOUNTS.delete('session:' + tokenHash);
  }
  return json({ ok: true });
}

/* ---------------- Account sync (notes backup) ---------------- */

// The uploaded blob is opaque to the worker — same {app, version, notes,
// images} shape Note Builder's own file-based backup already writes, plus
// the app's favorites/settings fields, stored server-side under the account
// instead of downloaded. Kept as a single R2 object per account rather than
// per-note records: the client already does its own additive-by-id merge on
// pull (see nbSyncPull), so there's no server-side merge to get right here.
//
// Concurrency: the object is one file, so a plain overwrite means whichever
// device uploads last silently erases the other's change. To close that,
// pulls return the object's ETag and a push may send it back as If-Match.
// The check is R2's own conditional put (onlyIf.etagMatches), which is atomic
// on R2's side — two devices pushing at the same instant can't both pass it,
// unlike a read-then-write done here in the Worker. A mismatch answers 409
// and the client pulls, merges and retries. A push with no If-Match (first
// ever backup, or an older app build) stays an unconditional overwrite unless
// REQUIRE_IF_MATCH is set (then 428); a first backup sends If-None-Match: *.
function normalizeEtag(v) {
  return String(v || '').trim().replace(/^W\//, '').replace(/^"(.*)"$/, '$1');
}
async function handleSyncPush(env, request) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  const limited = await accountRateLimitResponse(env, sub, 'syncPush');
  if (limited) return limited;
  const bodyText = await request.text();
  if (new TextEncoder().encode(bodyText).length > MAX_SYNC_BYTES) return textError(413, 'backup too large');
  let parsed;
  try { parsed = JSON.parse(bodyText); } catch (e) { return textError(400, 'invalid JSON body'); }
  if (!parsed || !Array.isArray(parsed.notes)) return textError(400, 'missing notes array');
  const putOpts = { httpMetadata: { contentType: 'application/json; charset=utf-8' } };
  const ifMatch = request.headers.get('If-Match');
  // If-None-Match: * = "create only" — the client's first ever backup, sent
  // after a pull that definitively found none. Without it a first push that
  // races another device's first push would overwrite it.
  const createOnly = (request.headers.get('If-None-Match') || '').trim() === '*';
  if (ifMatch) putOpts.onlyIf = { etagMatches: normalizeEtag(ifMatch) };
  else if (createOnly) putOpts.onlyIf = { etagDoesNotMatch: '*' };
  else if (env.REQUIRE_IF_MATCH === 'true' || env.REQUIRE_IF_MATCH === '1') {
    // Older app builds send neither header and would overwrite blindly. Set
    // REQUIRE_IF_MATCH once enough people have updated; until then they still work.
    return json({ error: 'update the app to keep syncing' }, 428);
  }
  const stored = await env.NOTES_BUCKET.put('sync/' + sub + '/notes.json', bodyText, putOpts);
  // R2 returns null (rather than throwing) when the precondition fails —
  // including "there is no object at all" — so this is the conflict case.
  if (!stored) return json({ error: 'backup changed on another device. Pull and retry' }, 409);
  const now = Date.now();
  await env.ACCOUNTS.put('syncmeta:' + sub, JSON.stringify({ updatedAt: now, sizeBytes: bodyText.length }));
  return json({ ok: true, updatedAt: now, etag: stored.httpEtag }, 200, { 'ETag': stored.httpEtag });
}

async function handleSyncPull(env, request) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  // Conditional pull: the app polls every ~20s and sends the ETag it already
  // holds. A cheap metadata read answers 304 when nothing changed, without
  // reading (or sending) the whole backup.
  const inm = normalizeEtag(request.headers.get('If-None-Match'));
  if (inm) {
    const head = await env.NOTES_BUCKET.head('sync/' + sub + '/notes.json');
    if (head && normalizeEtag(head.httpEtag) === inm) {
      return new Response(null, { status: 304, headers: { 'ETag': head.httpEtag, ...corsHeaders() } });
    }
  }
  const obj = await env.NOTES_BUCKET.get('sync/' + sub + '/notes.json');
  if (!obj) return textError(404, 'no backup yet');
  return new Response(obj.body, {
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'ETag': obj.httpEtag, ...corsHeaders() }
  });
}

/* ---------------- Account sync (backup images) ---------------- */

function syncImageKey(sub, id) { return 'sync/' + sub + '/img/' + id; }

// POST /sync/images/missing {ids:[...]} -> {missing:[...]}: which of these
// image ids the server doesn't have yet. Lets a freshly signed-in or
// reinstalled device find out what to upload in one call instead of
// re-sending everything.
const MAX_MISSING_IDS_PER_CALL = 500;
async function handleSyncImagesMissing(env, request) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  const limited = await accountRateLimitResponse(env, sub, 'syncImage');
  if (limited) return limited;
  let body;
  try { body = await request.json(); } catch (e) { return textError(400, 'invalid JSON body'); }
  const ids = body && body.ids;
  if (!Array.isArray(ids) || ids.length > MAX_MISSING_IDS_PER_CALL) return textError(400, 'ids must be an array of at most ' + MAX_MISSING_IDS_PER_CALL);
  const missing = [];
  for (const id of ids) {
    if (typeof id !== 'string' || !SYNC_IMAGE_ID_RE.test(id)) return textError(400, 'invalid image id');
    if (!(await env.NOTES_BUCKET.head(syncImageKey(sub, id)))) missing.push(id);
  }
  return json({ missing });
}

// PUT /sync/images/:id — body is the image's data: URL, exactly as the app
// stores it. Ids are content hashes made by the app, so an id that already
// exists is the same image: it's left alone (first write wins) and reported ok.
async function handleSyncImagePut(env, request, id) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  if (!SYNC_IMAGE_ID_RE.test(id)) return textError(400, 'invalid image id');
  const limited = await accountRateLimitResponse(env, sub, 'syncImage');
  if (limited) return limited;
  const text = await request.text();
  if (new TextEncoder().encode(text).length > MAX_SYNC_IMAGE_BYTES) return textError(413, 'image too large');
  if (!/^data:image\/[a-z0-9.+-]+[;,]/i.test(text)) return textError(400, 'expected an image data URL');
  const key = syncImageKey(sub, id);
  if (await env.NOTES_BUCKET.head(key)) return json({ ok: true, existed: true });
  const listing = await env.NOTES_BUCKET.list({ prefix: 'sync/' + sub + '/img/', limit: MAX_SYNC_IMAGES_PER_ACCOUNT + 1 });
  if (listing.objects.length >= MAX_SYNC_IMAGES_PER_ACCOUNT) return textError(413, 'too many backed-up images');
  await env.NOTES_BUCKET.put(key, text, { httpMetadata: { contentType: 'text/plain; charset=utf-8' } });
  return json({ ok: true, existed: false });
}

async function handleSyncImageGet(env, request, id) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  if (!SYNC_IMAGE_ID_RE.test(id)) return textError(400, 'invalid image id');
  const obj = await env.NOTES_BUCKET.get(syncImageKey(sub, id));
  if (!obj) return textError(404, 'no such image');
  return new Response(obj.body, { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'private, max-age=31536000, immutable', ...corsHeaders() } });
}

// Nightly cleanup of backup images no note references any more (deleted
// notes, replaced images). Deliberately cautious, because a wrong delete here
// is unrecoverable data loss for someone's photos:
//  - only images older than SYNC_IMAGE_GC_MIN_AGE_MS are candidates (a device
//    uploads images just before pushing the notes that use them, so a
//    fresh upload can legitimately be unreferenced for a moment);
//  - an account whose notes.json is missing or unparsable is skipped entirely;
//  - "referenced" means any image ref found in any note's content.
async function gcSyncImages(env) {
  const bySub = new Map();
  let cursor;
  do {
    const page = await env.NOTES_BUCKET.list({ prefix: 'sync/', cursor });
    for (const obj of page.objects) {
      const parts = obj.key.split('/');
      if (parts.length === 4 && parts[2] === 'img') {
        if (!bySub.has(parts[1])) bySub.set(parts[1], []);
        bySub.get(parts[1]).push({ key: obj.key, id: parts[3], uploaded: obj.uploaded ? new Date(obj.uploaded).getTime() : Date.now() });
      }
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  const cutoff = Date.now() - SYNC_IMAGE_GC_MIN_AGE_MS;
  let deleted = 0;
  for (const [sub, imgs] of bySub) {
    const old = imgs.filter(i => i.uploaded < cutoff);
    if (!old.length) continue;
    const obj = await env.NOTES_BUCKET.get('sync/' + sub + '/notes.json');
    if (!obj) continue;
    let parsed;
    try { parsed = JSON.parse(await new Response(obj.body).text()); } catch (e) { continue; }
    if (!parsed || !Array.isArray(parsed.notes)) continue;
    const referenced = new Set();
    for (const n of parsed.notes) {
      const content = (n && typeof n.content === 'string') ? n.content : '';
      const re = /data-note-img-ref="([^"]+)"/g;
      let m;
      while ((m = re.exec(content))) referenced.add(m[1]);
    }
    for (const i of old) {
      if (referenced.has(i.id)) continue;
      await env.NOTES_BUCKET.delete(i.key);
      deleted++;
    }
  }
  return deleted;
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

// GET /meta/:slug — public, read-only lookup of a published page's title
// and owner, for the app's "paste a note link" search (as opposed to
// browsing the Stories strip, where GET /stories already returns
// author_sub alongside each slug). check-slug deliberately only ever
// answers "is this taken" and stays that way; this is a separate route
// rather than a mode flag on it so a slug-availability check (typed on
// every keystroke while publishing) never accidentally leaks a live
// page's owner. Same not-found gating as handleServe (missing meta or
// deletedAt) so an unpublished/never-existed slug reads identically
// either way; adminLocked pages fall in here too since a takedown page
// has no legitimate note content or owner to hand back.
async function handleMeta(env, slug) {
  if (!SLUG_RE.test(slug)) return json({ found: false }, 404);
  const meta = await getMeta(env, slug);
  if (!meta || meta.deletedAt || meta.adminLocked) return json({ found: false }, 404);
  return json({
    found: true,
    slug,
    title: meta.title || 'Untitled note',
    authorSub: meta.ownerSub ? await authorIdFor(env, meta.ownerSub) : null // opaque ID, never the Google sub
  });
}

// Shared backstop limiter for the two storage-writing publish routes (see
// header comment + PUBLISH_RATE_LIMIT_* above). Keyed by IP rather than
// account so it also throttles anonymous publishes, which have no ownerSub
// for MAX_PAGES_PER_ACCOUNT to apply to.
async function checkPublishRateLimit(env, request) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const key = 'ratelimit:publish:' + ip;
  const raw = await env.REPORTS.get(key);
  const count = raw ? parseInt(raw, 10) || 0 : 0;
  if (count >= PUBLISH_RATE_LIMIT_MAX) return false;
  await env.REPORTS.put(key, String(count + 1), { expirationTtl: PUBLISH_RATE_LIMIT_WINDOW_S });
  return true;
}

// Per-account backstop for the signed-in write routes (likes, subscribing,
// marking stories seen, backup uploads). Same best-effort KV fixed-window
// approach as the limiters above, but keyed by account and split into
// per-window buckets so each request only ever touches the current window's
// key. Two things it deliberately does NOT try to be: exact (KV is
// eventually consistent, so a burst spread across locations can slip a few
// over) or a hard failure point (if KV itself errors, the request is allowed
// rather than locking a signed-in person out of likes/sync).
// Like/unlike share one bucket and subscribe/unsubscribe share another, so
// toggling can't be used to double the allowance.
const ACCOUNT_RATE_LIMITS = {
  like:      { max: 60,  windowS: 60 },
  subscribe: { max: 30,  windowS: 60 },
  seen:      { max: 120, windowS: 60 },
  syncPush:  { max: 30,  windowS: 60 },
  syncImage: { max: 300, windowS: 60 }
};
async function checkAccountRateLimit(env, sub, action) {
  const cfg = ACCOUNT_RATE_LIMITS[action];
  if (!cfg) return { ok: true };
  const nowS = Math.floor(Date.now() / 1000);
  const bucket = Math.floor(nowS / cfg.windowS);
  const key = 'ratelimit:acct:' + action + ':' + sub + ':' + bucket;
  try {
    const raw = await env.REPORTS.get(key);
    const count = raw ? parseInt(raw, 10) || 0 : 0;
    if (count >= cfg.max) return { ok: false, retryAfter: Math.max(1, (bucket + 1) * cfg.windowS - nowS) };
    // KV's minimum expirationTtl is 60s; the bucket is dead after its window anyway.
    await env.REPORTS.put(key, String(count + 1), { expirationTtl: Math.max(60, cfg.windowS * 2) });
  } catch (e) { /* fail open — see above */ }
  return { ok: true };
}
// Returns a ready 429 Response when `sub` is over its `action` limit, else null.
async function accountRateLimitResponse(env, sub, action) {
  const r = await checkAccountRateLimit(env, sub, action);
  if (r.ok) return null;
  return json({ error: 'too many requests, slow down' }, 429, { 'Retry-After': String(r.retryAfter) });
}

// Counts (a cap-bounded number of) an owner's currently-live pages via the
// existing "owner:<sub>:<slug>" index, so this is a single bounded KV.list
// call — not a full per-account scan — regardless of how large the account
// ever gets. Returns true once MAX_PAGES_PER_ACCOUNT is reached or exceeded.
async function ownerAtPageCap(env, ownerSub) {
  const page = await env.SLUGS.list({ prefix: 'owner:' + ownerSub + ':', limit: MAX_PAGES_PER_ACCOUNT });
  return page.keys.length >= MAX_PAGES_PER_ACCOUNT;
}

// Story card fields (description, tags, when the note was created) shown on a
// Subscribed-feed card. They live only on the stories row, so they disappear with it
// (toggle off, unpublish, account deletion). Each cleaner returns null for "not sent"
// so an update that doesn't carry the field leaves the stored value alone (COALESCE).
const STORY_DESC_MAX = 200;
const STORY_TAGS_MAX = 10;
const STORY_TAG_MAX_LEN = 40;
function cleanStoryDesc(v) { return typeof v === 'string' ? v.trim().slice(0, STORY_DESC_MAX) : null; }
function cleanStoryTags(v) {
  if (!Array.isArray(v)) return null;
  const out = [];
  for (const raw of v) {
    if (typeof raw !== 'string') continue;
    const s = raw.trim().slice(0, STORY_TAG_MAX_LEN);
    if (s && !out.includes(s)) out.push(s);
    if (out.length >= STORY_TAGS_MAX) break;
  }
  return JSON.stringify(out);
}
function cleanNoteCreatedAt(v) {
  const n = Number(v);
  return (Number.isFinite(n) && n > 0 && n <= Date.now() + 86400000) ? Math.floor(n) : null;
}
function parseStoryTags(raw) {
  try { const a = JSON.parse(raw); return Array.isArray(a) ? a.filter(x => typeof x === 'string') : []; }
  catch (e) { return []; }
}

async function handlePublish(env, request) {
  if (!(await checkPublishRateLimit(env, request))) return textError(429, 'too many publishes, slow down');
  let body;
  try { body = await request.json(); } catch (e) { return textError(400, 'invalid JSON body'); }
  const { slug, html, title, showInStories, desc, tags, createdAt } = body || {};
  if (!validSlug(slug)) return textError(400, 'invalid or reserved slug');
  if (typeof html !== 'string' || !html) return textError(400, 'missing html');
  if (new TextEncoder().encode(html).length > MAX_HTML_BYTES) {
    return textError(413, 'page too large');
  }
  const existing = await getMeta(env, slug);
  if (existing && existing.adminLocked) return textError(403, 'slug permanently disabled');
  if (existing && !existing.deletedAt) return textError(409, 'slug already taken');

  // Ownership tagging normally happens further down (after the token is
  // minted), but the page-count cap only means anything for an owned
  // account, so it's checked here, before any writes, against the same
  // requireSession call that path already does.
  const capOwnerSub = await requireSession(env, request);
  if (capOwnerSub && (await ownerAtPageCap(env, capOwnerSub))) {
    return textError(403, `page limit reached (max ${MAX_PAGES_PER_ACCOUNT} live pages per account). Unpublish something first`);
  }

  const token = newToken();
  const tokenHash = await sha256Hex(token);
  const now = Date.now();
  // Ownership tagging is best-effort and purely additive: an absent or
  // invalid Authorization header just means this page publishes the same
  // way it always has (anonymous, owner-token-only). A signed-in owner
  // gets it listed under GET /my/pages too, via the index key below.
  // (Same session already resolved above for the page-count cap check.)
  const ownerSub = capOwnerSub;
  // Stories requires a signed-in owner (subscriptions/feed are per-account)
  // — an anonymous publish silently ignores the toggle rather than 401ing,
  // since publish itself stays anonymous-friendly.
  const wantsStory = !!showInStories && !!ownerSub;
  const storyTitle = (typeof title === 'string' ? title.trim() : '').slice(0, 200) || 'Untitled note';

  await env.NOTES_BUCKET.put(slug + '.html', html, {
    httpMetadata: { contentType: 'text/html; charset=utf-8' }
  });
  await putMeta(env, slug, {
    tokenHash,
    createdAt: now,
    updatedAt: now,
    sizeBytes: html.length,
    deletedAt: null,
    ownerSub: ownerSub || null,
    showInStories: wantsStory,
    title: storyTitle,
    // Card details kept for every published page (not just stories) so a note someone
    // likes from its link can be shown as a full card on their Liked tab.
    desc: cleanStoryDesc(desc) || '',
    tags: cleanStoryTags(tags),
    noteCreatedAt: cleanNoteCreatedAt(createdAt)
  });
  if (ownerSub) {
    await env.SLUGS.put('owner:' + ownerSub + ':' + slug, '1');
    await env.ADS_DB.prepare('INSERT OR REPLACE INTO published_notes (slug, author_sub, created_at) VALUES (?, ?, ?)')
      .bind(slug, ownerSub, now).run();
  }
  if (wantsStory) {
    const imageUrl = await storeStoryImage(env, slug, html);
    const imageUrls = await storeStoryCardImages(env, slug, html);
    await env.ADS_DB.prepare(
      'INSERT OR REPLACE INTO stories (slug, author_sub, title, created_at, image_url, image_urls, description, tags, note_created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(slug, ownerSub, storyTitle, now, imageUrl, imageUrls, cleanStoryDesc(desc), cleanStoryTags(tags), cleanNoteCreatedAt(createdAt)).run();
  }
  return json({ slug, token }, 201);
}

async function handleUpdate(env, request, slug) {
  if (!(await checkPublishRateLimit(env, request))) return textError(429, 'too many publishes, slow down');
  if (!validSlug(slug)) return textError(400, 'invalid slug');
  let body;
  try { body = await request.json(); } catch (e) { return textError(400, 'invalid JSON body'); }
  const { html, token, title, showInStories, desc, tags, createdAt } = body || {};
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
  if (typeof title === 'string' && title.trim()) meta.title = title.trim().slice(0, 200);
  // Card details only change when this call actually carries them (an older app build can't wipe them).
  { const d = cleanStoryDesc(desc), t = cleanStoryTags(tags), c = cleanNoteCreatedAt(createdAt);
    if (d !== null) meta.desc = d;
    if (t !== null) meta.tags = t;
    if (c !== null) meta.noteCreatedAt = c; }

  // showInStories is only togglable here for an owned page — an anonymous
  // publish (meta.ownerSub null) has no account to attribute a story row
  // to, so the toggle is a no-op for it regardless of what's sent.
  if (typeof showInStories === 'boolean' && meta.ownerSub) {
    const was = !!meta.showInStories;
    const wants = showInStories;
    if (wants && !was) {
      const [imageUrl, imageUrls] = await Promise.all([storeStoryImage(env, slug, html), storeStoryCardImages(env, slug, html)]);
      await env.ADS_DB.prepare(
        'INSERT OR REPLACE INTO stories (slug, author_sub, title, created_at, image_url, image_urls, description, tags, note_created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
      ).bind(slug, meta.ownerSub, meta.title || 'Untitled note', meta.updatedAt, imageUrl, imageUrls, cleanStoryDesc(desc), cleanStoryTags(tags), cleanNoteCreatedAt(createdAt)).run();
    } else if (!wants && was) {
      await Promise.all([
        deleteStoryImage(env, slug),
        deleteStoryCardImages(env, slug),
        env.ADS_DB.batch([
          env.ADS_DB.prepare('DELETE FROM stories WHERE slug = ?').bind(slug),
          env.ADS_DB.prepare('DELETE FROM story_seen WHERE slug = ?').bind(slug)
        ])
      ]);
    } else if (wants && was) {
      // Title and/or the note's images may have changed this same call —
      // keep the story row's denormalized copies in sync without touching
      // created_at (that would reorder it in the strip/feed, which an
      // edit shouldn't). storeStoryImage/storeStoryCardImages also clear/
      // replace the R2 blobs as needed (removed image, shrunk image,
      // swapped for a remote URL, etc).
      const [imageUrl, imageUrls] = await Promise.all([storeStoryImage(env, slug, html), storeStoryCardImages(env, slug, html)]);
      // description/tags/note_created_at only change when this call actually carries them
      // (COALESCE keeps the stored value for a null), so an update from an older app build
      // or one that only sends html can't wipe them.
      await env.ADS_DB.prepare('UPDATE stories SET title = ?, image_url = ?, image_urls = ?, description = COALESCE(?, description), tags = COALESCE(?, tags), note_created_at = COALESCE(?, note_created_at) WHERE slug = ?')
        .bind(meta.title || 'Untitled note', imageUrl, imageUrls, cleanStoryDesc(desc), cleanStoryTags(tags), cleanNoteCreatedAt(createdAt), slug).run();
    }
    meta.showInStories = wants;
  }

  await putMeta(env, slug, meta);
  return json({ ok: true });
}

// PUT /publish/:slug/stories — flips "Show in stories" for an owned page WITHOUT re-sending the page.
// PUT /publish/:slug needs the whole html in the body (the app had to rebuild it, upload it, and this
// worker had to rewrite it to R2) just to change one flag. Here the body is only { token, showInStories }
// plus the optional card details; turning a story on reads the already-stored page from R2 for its
// preview images. The response carries the story row in the same shape GET /stories returns, so the
// app can put it in the strip straight away instead of making a second request.
async function handleSetStories(env, request, slug) {
  if (!(await checkPublishRateLimit(env, request))) return textError(429, 'too many publishes, slow down');
  if (!validSlug(slug)) return textError(400, 'invalid slug');
  let body;
  try { body = await request.json(); } catch (e) { return textError(400, 'invalid JSON body'); }
  const { token, showInStories, title, desc, tags, createdAt } = body || {};
  if (typeof token !== 'string' || !token) return textError(401, 'missing token');
  if (typeof showInStories !== 'boolean') return textError(400, 'showInStories must be true or false');
  const meta = await getMeta(env, slug);
  if (!meta || meta.deletedAt) return textError(404, 'not found');
  const tokenHash = await sha256Hex(token);
  if (!timingSafeEqual(tokenHash, meta.tokenHash)) return textError(403, 'invalid token');
  // Stories are per-account; an anonymous page has no account to attribute a story row to.
  if (!meta.ownerSub) return textError(403, 'sign-in required to show a note in stories');

  const was = !!meta.showInStories;
  const wants = showInStories;
  // Card details only change when this call carries them, same rule as PUT /publish/:slug.
  if (typeof title === 'string' && title.trim()) meta.title = title.trim().slice(0, 200);
  const d = cleanStoryDesc(desc), t = cleanStoryTags(tags), c = cleanNoteCreatedAt(createdAt);
  if (d !== null) meta.desc = d;
  if (t !== null) meta.tags = t;
  if (c !== null) meta.noteCreatedAt = c;

  if (wants && !was) {
    const obj = await env.NOTES_BUCKET.get(slug + '.html');
    if (!obj) return textError(404, 'page content missing');
    const html = await obj.text();
    const now = Date.now();
    meta.updatedAt = now;
    const [imageUrl, imageUrls] = await Promise.all([storeStoryImage(env, slug, html), storeStoryCardImages(env, slug, html)]);
    await env.ADS_DB.prepare(
      'INSERT OR REPLACE INTO stories (slug, author_sub, title, created_at, image_url, image_urls, description, tags, note_created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(slug, meta.ownerSub, meta.title || 'Untitled note', now, imageUrl, imageUrls, meta.desc ?? null, meta.tags ?? null, meta.noteCreatedAt ?? null).run();
  } else if (!wants && was) {
    await Promise.all([
      deleteStoryImage(env, slug),
      deleteStoryCardImages(env, slug),
      env.ADS_DB.batch([
        env.ADS_DB.prepare('DELETE FROM stories WHERE slug = ?').bind(slug),
        env.ADS_DB.prepare('DELETE FROM story_seen WHERE slug = ?').bind(slug)
      ])
    ]);
  } else if (wants && was) {
    // Already showing: only the card text can have changed (no page was sent, so images stay as stored).
    await env.ADS_DB.prepare('UPDATE stories SET title = ?, description = COALESCE(?, description), tags = COALESCE(?, tags), note_created_at = COALESCE(?, note_created_at) WHERE slug = ?')
      .bind(meta.title || 'Untitled note', d, t, c, slug).run();
  }
  meta.showInStories = wants;

  // Save the meta and (when showing) assemble the strip row side by side.
  const origin = new URL(request.url).origin;
  const buildStory = async () => {
    if (!wants) return null;
    const row = await env.ADS_DB.prepare('SELECT slug, title, created_at, image_url FROM stories WHERE slug = ?').bind(slug).first();
    if (!row) return null;
    const [user, idBySub] = await Promise.all([getUser(env, meta.ownerSub), authorIdsFor(env, [meta.ownerSub])]);
    return {
      slug: row.slug,
      title: row.title,
      authorSub: idBySub[meta.ownerSub], // opaque author ID, same as GET /stories
      authorProfileName: (user && user.profileName) || null,
      createdAt: row.created_at,
      seen: false,
      imageUrl: row.image_url === STORY_IMAGE_R2_MARKER
        ? `${origin}/stories/image/${encodeURIComponent(row.slug)}`
        : (row.image_url || null)
    };
  };
  const [story] = await Promise.all([buildStory(), putMeta(env, slug, meta)]);
  return json({ ok: true, showInStories: wants, story });
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
    const auth = await adminAuthOk(env, request, adminToken);
    if (auth === 'limited') return textError(429, 'too many failed attempts, try again in 5 minutes');
    if (auth !== 'ok') return textError(403, 'invalid admin token');
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
      httpMetadata: { contentType: 'text/html; charset=utf-8' },
      customMetadata: { source: isAdminTakedown ? 'takedown' : 'unpublish' }
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
  if (meta.ownerSub) {
    await env.SLUGS.delete('owner:' + meta.ownerSub + ':' + slug);
    await env.ADS_DB.prepare('DELETE FROM published_notes WHERE slug = ?').bind(slug).run();
  }
  // A story stops being a story the moment its page is gone — it doesn't
  // wait for handlePurge's 30-day hard-delete pass, that's KV/R2 cleanup
  // for already-dead entries, not the thing that makes a story live.
  // Thumbnails cached for the Liked tab exist even when the note is not a story.
  await deleteStoryCardImages(env, slug);
  await env.SLUGS.delete(cardImagesKey(slug));
  if (meta.showInStories) {
    await deleteStoryImage(env, slug);
    await env.ADS_DB.batch([
      env.ADS_DB.prepare('DELETE FROM stories WHERE slug = ?').bind(slug),
      env.ADS_DB.prepare('DELETE FROM story_seen WHERE slug = ?').bind(slug)
    ]);
  }
  // Likes belong to the note, not to whoever holds the slug next: an unpublished
  // slug is reclaimable immediately, so its likes go now or a new note at the
  // same slug would start life with someone else's likes (and the old author's
  // total would keep counting them).
  await env.ADS_DB.batch([
    env.ADS_DB.prepare('DELETE FROM likes WHERE slug = ?').bind(slug),
    // ...and every liker's latest-tap clock for it, which would otherwise pile up unused.
    env.ADS_DB.prepare("DELETE FROM action_clocks WHERE kind = 'like' AND item = ?").bind(slug)
  ]);
  // An ad IS this page: unpublishing the page must take the ad down too, or
  // /ads/next would keep handing out its HTML until the 30-day purge.
  await env.ADS_DB.prepare("UPDATE ads SET status = 'unpublished', updated_at = ? WHERE slug = ? AND status != 'unpublished'")
    .bind(now, slug).run();
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

/* ---------------- Stories ---------------- */

const STORIES_STRIP_LIMIT = 12;
// Discovery-strip pool: wider than what's shown (see handleStoriesStrip) so that different
// viewers, drawing from the same pool, land on genuinely different subsets rather than
// everyone re-deriving the same top 12. The pool is the newest stories with at most
// STORIES_STRIP_PER_AUTHOR per author, so a heavy poster can't fill it.
const STORIES_STRIP_CANDIDATE_LIMIT = 120;
const STORIES_STRIP_PER_AUTHOR = 2;
// Of the 12 slots for other people's stories, this many are the same for every signed-in viewer
// in a rotation window (the shared experience); the rest are personal to the viewer.
const STORIES_STRIP_SHARED = 4;
// How often the shared picks and each viewer's personal picks reshuffle.
const STORIES_STRIP_ROTATE_MS = 6 * 60 * 60 * 1000;
// A signed-in viewer's OWN live stories always lead the strip and don't count toward
// STORIES_STRIP_LIMIT (which is only for other people's). Capped as a safety net, not a design limit.
const STORIES_STRIP_OWN_LIMIT = 20;
// A story only appears in the discovery strip or the Subscribed feed for
// this long after being posted — Instagram-style ephemerality. The
// published page itself is untouched; this only affects the Stories
// listings (see handleStoriesStrip / handleSubscriptionsFeed). Also
// bounds the pool itself.
const STORIES_LOOKBACK_MS = 24 * 60 * 60 * 1000;
// How long a story stays in a follower's Subscribed feed after it became a story. Unlike the
// 24h strip window this is a normal feed's horizon: older posts age out of the feed (the story
// row and published page are untouched; Liked/Published tabs are unaffected).
const SUBSCRIPTIONS_FEED_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

// Non-cryptographic string hash (FNV-1a) + mulberry32 PRNG, used only to
// seed a per-viewer shuffle of the discovery-strip candidate pool — not
// security-sensitive, just needs to be cheap and deterministic for a
// given (sub, day-bucket) pair so the same viewer sees a stable order
// within one STORIES_LOOKBACK_MS window and a different one the next.
function _storiesHashSeed(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}
function _storiesMulberry32(seed) {
  let t = seed >>> 0;
  return function () {
    t += 0x6D2B79F5;
    let r = Math.imul(t ^ (t >>> 15), 1 | t);
    r ^= r + Math.imul(r ^ (r >>> 7), 61 | r);
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
  };
}
// Deterministic pseudo-random order: each story gets a score from (seedStr, slug), and the list is
// sorted by it. Same seedStr always yields the same order, and unlike an index-based shuffle a story
// being posted or expiring doesn't reorder the others, so picks stay stable through a rotation window.
function _storiesSeededOrder(arr, seedStr) {
  const score = r => _storiesMulberry32(_storiesHashSeed(seedStr + '|' + r.slug))();
  return arr.map(r => [score(r), r]).sort((x, y) => x[0] - y[0]).map(x => x[1]);
}
// Ring avatar preview: skip storing an image bigger than this, whether
// it ends up in R2 (decoded data: URI bytes) or, for an already-remote
// src, the URL string itself. 300KB comfortably covers a compressed
// device photo; anything bigger just falls back to the title-text avatar
// client-side. (Previously this bounded the base64 string written
// straight into the D1 image_url column; see storeStoryImage.)
const STORY_IMAGE_MAX_BYTES = 300 * 1024;

// Pulls the note's raw first image src for the story-ring avatar preview,
// reusing the same '.blk-img img' HTMLRewriter selector validateAdEligibility
// already walks below. Returns null if there's no image. Callers decide
// what to do with a data: URI vs. an already-remote URL (see
// storeStoryImage) and where the size cutoff applies.
async function extractFirstImageSrc(html) {
  let first = null;
  const rewriter = new HTMLRewriter().on('.blk-img img', {
    element(el) {
      if (first === null) {
        const src = el.getAttribute('src') || '';
        if (src) first = src;
      }
    }
  });
  await rewriter.transform(new Response(html)).text();
  return first;
}

// Same idea as extractFirstImageSrc but collects up to `max` image srcs
// in document order (candidates for the Subscribed-feed card thumbnails)
// while still counting every image in the note, so the card can show the
// "+N" for the ones it doesn't preview, same as a normal note card.
async function extractImageSrcs(html, max) {
  const found = [];
  let total = 0;
  const rewriter = new HTMLRewriter().on('.blk-img img', {
    element(el) {
      const src = el.getAttribute('src') || '';
      if (!src) return;
      total++;
      if (found.length < max) found.push(src);
    }
  });
  await rewriter.transform(new Response(html)).text();
  return { srcs: found, total };
}

// R2 key for one of a story's up-to-3 card-preview images (distinct from
// storyImageKey's single ring-avatar blob — the ring shows just the
// first image, the Subscribed-feed card shows up to three, same as any
// other note card's thumbnail row).
function storyCardImageKey(slug, index) {
  return `story-card-images/${slug}/${index}`;
}

// Card previews live in R2 (not D1), so they get a roomier per-image cap
// than the 300KB ring-avatar/URL-string cap: the app embeds photos at up
// to 1600px, which routinely lands above 300KB, and dropping those left
// the card with fewer thumbnails than the note has images.
const STORY_CARD_IMAGE_MAX_BYTES = 1.5 * 1024 * 1024;

// Mirrors storeStoryImage but for up to 3 images instead of 1. Returns a
// JSON string for the stories.image_urls column: {"e": [...], "n": total
// images in the note}. "e" is an array (possibly empty) of entries, each
// either STORY_IMAGE_R2_MARKER (blob at storyCardImageKey(slug, i)) or a
// plain remote URL — same per-entry convention as the single-image column.
//
// An entry's position in the array IS its R2 slot (expandStoryImageUrls
// builds /stories/card-image/<slug>/<position>), so blobs are written at
// entries.length, never at the source image's index. Skipping an
// unusable image therefore closes the gap instead of shifting every later
// entry onto a slot that was never written (which 404'd as an empty
// placeholder). Slots past what's stored are cleared at the end, so a
// note that loses images (or shrinks from 3 to 1) leaves no orphans.
//
// Up to STORY_CARD_CANDIDATES sources are considered so an unusable image
// (too big, malformed) is replaced by the next one and the card still
// previews three when the note has them. "n" counts every image, so the
// client shows "+N" for whatever isn't previewed.
const STORY_CARD_CANDIDATES = 12;
async function storeStoryCardImages(env, slug, html) {
  const { srcs, total } = await extractImageSrcs(html, STORY_CARD_CANDIDATES);
  const entries = [];
  for (const src of srcs) {
    if (entries.length >= 3) break;
    const m = /^data:([^;,]*)(;base64)?,(.*)$/s.exec(src);
    if (!m) {
      if (new TextEncoder().encode(src).length <= STORY_IMAGE_MAX_BYTES) entries.push(src);
      continue;
    }
    const contentType = m[1] || 'application/octet-stream';
    const isBase64 = !!m[2];
    let bytes;
    try {
      if (isBase64) {
        const binary = atob(m[3]);
        bytes = new Uint8Array(binary.length);
        for (let j = 0; j < binary.length; j++) bytes[j] = binary.charCodeAt(j);
      } else {
        bytes = new TextEncoder().encode(decodeURIComponent(m[3]));
      }
    } catch (e) {
      continue; // malformed data URI — skip this image
    }
    if (bytes.byteLength > STORY_CARD_IMAGE_MAX_BYTES) continue;
    await env.NOTES_BUCKET.put(storyCardImageKey(slug, entries.length), bytes, { httpMetadata: { contentType } });
    entries.push(STORY_IMAGE_R2_MARKER);
  }
  await Promise.all([0, 1, 2].filter(i => i >= entries.length).map(i => env.NOTES_BUCKET.delete(storyCardImageKey(slug, i))));
  return JSON.stringify({ e: entries, n: total });
}

// Cleans up all of a story's card-preview blobs (up to 3), mirroring
// deleteStoryImage — called from the same places that call it (story
// toggled off, unpublished, purged, or simply re-stored on an edit).
async function deleteStoryCardImages(env, slug) {
  await Promise.all([0, 1, 2].map(i => env.NOTES_BUCKET.delete(storyCardImageKey(slug, i))));
}

// GET /stories/card-image/:slug/:index — serves one of the up-to-3
// R2-stored card-preview blobs. Same public/no-auth/short-cache shape as
// handleServeStoryImage; a missing slot (never had that many images, or
// fewer now) 404s, which the client's onerror thumbnail handling already
// tolerates.
async function handleServeStoryCardImage(env, slug, indexStr) {
  if (!validSlug(slug)) return textError(404, 'not found');
  const index = Number(indexStr);
  if (!Number.isInteger(index) || index < 0 || index > 2) return textError(404, 'not found');
  const obj = await env.NOTES_BUCKET.get(storyCardImageKey(slug, index));
  if (!obj) return textError(404, 'not found');
  return new Response(obj.body, {
    headers: {
      'Content-Type': (obj.httpMetadata && obj.httpMetadata.contentType) || 'application/octet-stream',
      'Cache-Control': 'public, max-age=300',
      ...corsHeaders()
    }
  });
}

// Expands a stories.image_urls JSON column value into absolute URLs plus
// the note's total image count, using the same STORY_IMAGE_R2_MARKER
// convention as the single-image column. Accepts the current {e, n} shape
// and the older bare-array shape (count then falls back to what's
// previewable); tolerates a null/empty/malformed column by returning no
// images.
function expandStoryImageUrls(origin, slug, imageUrlsJson) {
  let parsed;
  try { parsed = JSON.parse(imageUrlsJson || '[]'); } catch (e) { parsed = []; }
  const entries = Array.isArray(parsed) ? parsed : (parsed && Array.isArray(parsed.e) ? parsed.e : []);
  const images = entries.map((entry, i) => entry === STORY_IMAGE_R2_MARKER
    ? `${origin}/stories/card-image/${encodeURIComponent(slug)}/${i}`
    : entry
  ).filter(Boolean);
  const n = parsed && !Array.isArray(parsed) ? Number(parsed.n) : NaN;
  return { images, count: Number.isFinite(n) ? Math.max(n, images.length) : images.length };
}

// R2 key for a story's ring-avatar image blob. One object per slug
// (overwritten on republish/edit), so no separate cleanup bookkeeping is
// needed beyond deleting this key when the story stops existing.
function storyImageKey(slug) {
  return `story-images/${slug}`;
}

// Sentinel stored in the D1 stories.image_url column when the avatar image
// lives in R2 (see storyImageKey) rather than being a plain remote URL.
// handleStoriesStrip expands this into an absolute /stories/image/<slug>
// URL at read time, using the request's own origin.
const STORY_IMAGE_R2_MARKER = 'r2';

// Extracts the note's first image for the story-ring avatar and, if it's
// an inline data: URI, decodes and stores the raw bytes in R2 (see
// storyImageKey) instead of writing the (often large) base64 string into
// D1 — D1 image_url previously held the data URI directly, which bloated
// row size and every /stories response. Returns the value to store in the
// stories.image_url column: STORY_IMAGE_R2_MARKER when an image was
// written to R2, a plain URL when the note's first image is already a
// remote (non-data:) src, or null when there's no usable image (no image,
// unparseable data URI, or over STORY_IMAGE_MAX_BYTES once decoded) — the
// client falls back to a title-text avatar in all null cases. Always
// clears any stale R2 object for this slug first so a shrunk/removed
// image, or a switch from a data: URI to a remote URL, doesn't leave an
// orphaned blob behind.
async function storeStoryImage(env, slug, html) {
  const src = await extractFirstImageSrc(html);
  await env.NOTES_BUCKET.delete(storyImageKey(slug));
  if (!src) return null;

  const m = /^data:([^;,]*)(;base64)?,(.*)$/s.exec(src);
  if (!m) {
    // Already a remote URL (or some other non-data src) — nothing to
    // move to R2; store it as before, still capped against abuse.
    if (new TextEncoder().encode(src).length > STORY_IMAGE_MAX_BYTES) return null;
    return src;
  }

  const contentType = m[1] || 'application/octet-stream';
  const isBase64 = !!m[2];
  let bytes;
  try {
    if (isBase64) {
      const binary = atob(m[3]);
      bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    } else {
      bytes = new TextEncoder().encode(decodeURIComponent(m[3]));
    }
  } catch (e) {
    return null; // malformed data URI — treat like "no image"
  }
  // Decoded blobs live in R2, so they get the same roomier cap as the card
  // previews; only URL strings (stored in D1) stay at STORY_IMAGE_MAX_BYTES.
  if (bytes.byteLength > STORY_CARD_IMAGE_MAX_BYTES) return null;

  await env.NOTES_BUCKET.put(storyImageKey(slug), bytes, {
    httpMetadata: { contentType }
  });
  return STORY_IMAGE_R2_MARKER;
}

// Cleans up a story's R2 avatar blob (if any) whenever its stories row
// goes away — toggled off, unpublished, or purged. A no-op delete on a
// slug that never had an image (or already had it cleared by
// storeStoryImage) is harmless.
async function deleteStoryImage(env, slug) {
  await env.NOTES_BUCKET.delete(storyImageKey(slug));
}

// GET /stories/image/:slug — serves the R2-stored ring-avatar blob for a
// story whose image_url is STORY_IMAGE_R2_MARKER. Public, like the strip
// itself; a slug with no stored image (already unpublished, toggled off,
// or never had one) 404s, which the client's onerror avatar fallback
// already handles for the <img> tag.
async function handleServeStoryImage(env, slug) {
  if (!validSlug(slug)) return textError(404, 'not found');
  const obj = await env.NOTES_BUCKET.get(storyImageKey(slug));
  if (!obj) return textError(404, 'not found');
  return new Response(obj.body, {
    headers: {
      'Content-Type': (obj.httpMetadata && obj.httpMetadata.contentType) || 'application/octet-stream',
      // Short cache: the same key can be overwritten by a later edit, so
      // this isn't content-addressed/immutable like the note HTML snapshots.
      'Cache-Control': 'public, max-age=300',
      ...corsHeaders()
    }
  });
}

// GET /stories — the horizontal strip on the Notes screen. A signed-in viewer's own live stories
// come first (not counted in the 12); the rest of it is a
// *discovery* surface, not a feed of people you already follow: a story
// only qualifies for STORIES_LOOKBACK_MS (24h) after it's posted, and
// any author the signed-in caller already subscribes to is excluded
// (those show as note cards in the Subscribed category instead — see
// handleSubscriptionsFeed).
//
// Signed-in viewers get a mix of shared and personal picks from a wide pool (the newest
// STORIES_STRIP_CANDIDATE_LIMIT stories, at most STORIES_STRIP_PER_AUTHOR per author):
//  - STORIES_STRIP_SHARED slots are the same for everyone: the first eligible stories of a
//    shuffle seeded only by the rotation window, skipping the viewer's own and followed authors.
//  - The remaining slots are personal: a shuffle seeded by the viewer + window, with stories
//    the viewer hasn't opened ahead of ones they have.
// Both reshuffle every STORIES_STRIP_ROTATE_MS. Anonymous callers have no identity to vary
// by, so they get the newest-first list of the same pool.
async function handleStoriesStrip(env, request) {
  const sub = await requireSession(env, request);
  const now = Date.now();
  const cutoff = now - STORIES_LOOKBACK_MS;

  let followedAuthors = [];
  let ownStories = [];
  if (sub) {
    // Follows and the viewer's own live stories are independent lookups: run them together.
    const [followRows, ownRows] = await Promise.all([
      env.ADS_DB.prepare('SELECT author_sub FROM subscriptions WHERE subscriber_sub = ?').bind(sub).all(),
      env.ADS_DB.prepare(
        'SELECT slug, author_sub, title, created_at, image_url FROM stories WHERE author_sub = ? AND created_at >= ? ORDER BY created_at DESC LIMIT ?'
      ).bind(sub, cutoff, STORIES_STRIP_OWN_LIMIT).all()
    ]);
    followedAuthors = followRows.results.map(r => r.author_sub);
    ownStories = ownRows.results;
  }

  // Global pool, identical for every viewer (so the shared picks can be): newest first, capped per author.
  const { results: rawPool } = await env.ADS_DB.prepare(
    'SELECT slug, author_sub, title, created_at, image_url FROM stories WHERE created_at >= ? ORDER BY created_at DESC LIMIT ?'
  ).bind(cutoff, STORIES_STRIP_CANDIDATE_LIMIT * 3).all();
  const perAuthor = {};
  const pool = [];
  for (const r of rawPool) {
    perAuthor[r.author_sub] = (perAuthor[r.author_sub] || 0) + 1;
    if (perAuthor[r.author_sub] <= STORIES_STRIP_PER_AUTHOR) pool.push(r);
    if (pool.length >= STORIES_STRIP_CANDIDATE_LIMIT) break;
  }

  // Own stories lead the strip; followed authors show in Subscribed instead.
  const skipAuthors = new Set(followedAuthors);
  if (sub) skipAuthors.add(sub);
  const eligible = pool.filter(r => !skipAuthors.has(r.author_sub));

  let seenSlugs = new Set();
  if (sub) {
    const slugs = [...ownStories, ...eligible].map(r => r.slug);
    for (let i = 0; i < slugs.length; i += 80) { // D1 caps bound parameters per query
      const chunk = slugs.slice(i, i + 80);
      const { results: seenRows } = await env.ADS_DB.prepare(
        `SELECT slug FROM story_seen WHERE subscriber_sub = ? AND slug IN (${chunk.map(() => '?').join(',')})`
      ).bind(sub, ...chunk).all();
      seenRows.forEach(r => seenSlugs.add(r.slug));
    }
  }

  let others;
  if (!sub) {
    others = eligible.slice(0, STORIES_STRIP_LIMIT);
  } else {
    const bucket = Math.floor(now / STORIES_STRIP_ROTATE_MS);
    // Shared picks: same shuffle for everyone, first eligible ones win.
    const shared = _storiesSeededOrder(pool, 'shared:' + bucket)
      .filter(r => !skipAuthors.has(r.author_sub))
      .slice(0, STORIES_STRIP_SHARED);
    const sharedSlugs = new Set(shared.map(r => r.slug));
    // Personal picks: unseen first, each group shuffled per viewer.
    const rest = eligible.filter(r => !sharedSlugs.has(r.slug));
    const seed = sub + ':' + bucket;
    const personal = [
      ..._storiesSeededOrder(rest.filter(r => !seenSlugs.has(r.slug)), seed),
      ..._storiesSeededOrder(rest.filter(r => seenSlugs.has(r.slug)), seed)
    ].slice(0, STORIES_STRIP_LIMIT - shared.length);
    others = [...shared, ...personal];
  }
  const ranked = [...ownStories, ...others]; // yours first, then up to 12 from others

  // image_url is either STORY_IMAGE_R2_MARKER (image lives in R2, served
  // via GET /stories/image/:slug — see storeStoryImage/handleServeStoryImage),
  // a plain remote URL (passed through as-is), or null. authorProfileName
  // mirrors handleSubscriptionsFeed's per-distinct-author lookup below —
  // the client's avatar fallback chain (profile picture -> story's first
  // image -> initial letter) needs it for the initial when the author has
  // a display name set.
  const authorSubs = [...new Set(ranked.map(r => r.author_sub))];
  const nameBySub = {};
  for (const authorSub of authorSubs) {
    const user = await getUser(env, authorSub);
    nameBySub[authorSub] = (user && user.profileName) || null;
  }
  const idBySub = await authorIdsFor(env, authorSubs);

  const origin = new URL(request.url).origin;
  return json({
    stories: ranked.map(r => ({
      slug: r.slug,
      title: r.title,
      authorSub: idBySub[r.author_sub], // opaque author ID (field name kept for older app builds)
      authorProfileName: nameBySub[r.author_sub],
      createdAt: r.created_at,
      seen: seenSlugs.has(r.slug),
      imageUrl: r.image_url === STORY_IMAGE_R2_MARKER
        ? `${origin}/stories/image/${encodeURIComponent(r.slug)}`
        : (r.image_url || null)
    }))
  });
}

// POST /stories/:slug/seen — marks a story opened by the signed-in
// viewer, so its ring greys out across every device on this account
// (plan: ring state is server-synced, not per-device local state).
// Silently no-ops for a slug that isn't actually a live story (already
// unpublished, toggled off, or never existed) rather than 404ing — the
// client fires this right after opening whatever the strip handed it,
// and a race with the author turning the story off a moment later isn't
// worth surfacing as an error.
async function handleMarkStorySeen(env, request, slug) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  { const limited = await accountRateLimitResponse(env, sub, 'seen'); if (limited) return limited; }
  if (!validSlug(slug)) return textError(400, 'invalid slug');
  await env.ADS_DB.prepare(
    'INSERT OR REPLACE INTO story_seen (subscriber_sub, slug, seen_at) VALUES (?, ?, ?)'
  ).bind(sub, slug, Date.now()).run();
  return json({ ok: true });
}

// Latest-tap-wins. The app sends X-Action-Time (when the person actually
// tapped, which for a queued offline tap is well before it arrives). An action
// only applies if it is newer than the newest one already applied for this
// (account, kind, item); an older replay is a no-op and the reply carries the
// current state so the app can correct itself. The clock upsert and the change
// run in one D1 batch (a transaction), and the change is conditional on the
// clock still being this action's, so two devices racing can't interleave.
// No header (older builds) = server time. Clamped to server time so a phone
// with a fast clock can't lock an item against later taps.
function actionTime(request) {
  const now = Date.now();
  const t = Number(request.headers.get('X-Action-Time'));
  return Number.isFinite(t) && t > 0 ? Math.min(Math.floor(t), now) : now;
}
function clockUpsert(env, sub, kind, item, t) {
  return env.ADS_DB.prepare(
    'INSERT INTO action_clocks (sub, kind, item, t) VALUES (?, ?, ?, ?) ' +
    'ON CONFLICT(sub, kind, item) DO UPDATE SET t = excluded.t WHERE excluded.t >= action_clocks.t'
  ).bind(sub, kind, item, t);
}
const CLOCK_IS = 'EXISTS (SELECT 1 FROM action_clocks WHERE sub = ? AND kind = ? AND item = ? AND t = ?)';

// POST /subscriptions/:authorSub — follow an author. authorSub is that
// account's Google `sub`, taken from a story's authorSub field (the
// client never has to know or expose email/identity beyond that).
async function handleSubscribe(env, request, authorParam) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  { const limited = await accountRateLimitResponse(env, sub, 'subscribe'); if (limited) return limited; }
  if (!authorParam) return textError(400, 'missing author');
  const authorSub = await resolveAuthorParam(env, authorParam);
  if (!authorSub) return textError(404, 'author not found');
  if (authorSub === sub) return textError(400, 'can\u2019t subscribe to yourself');
  return applySubscription(env, request, sub, authorSub, true);
}

async function handleUnsubscribe(env, request, authorParam) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  { const limited = await accountRateLimitResponse(env, sub, 'subscribe'); if (limited) return limited; }
  const authorSub = await resolveAuthorParam(env, authorParam);
  // An author who no longer exists has nothing left to unfollow.
  if (!authorSub) return json({ ok: true, subscribed: false });
  return applySubscription(env, request, sub, authorSub, false);
}

async function applySubscription(env, request, sub, authorSub, want) {
  const t = actionTime(request);
  const change = want
    ? env.ADS_DB.prepare('INSERT OR IGNORE INTO subscriptions (subscriber_sub, author_sub, created_at) SELECT ?, ?, ? WHERE ' + CLOCK_IS)
        .bind(sub, authorSub, Date.now(), sub, 'sub', authorSub, t)
    : env.ADS_DB.prepare('DELETE FROM subscriptions WHERE subscriber_sub = ? AND author_sub = ? AND ' + CLOCK_IS)
        .bind(sub, authorSub, sub, 'sub', authorSub, t);
  await env.ADS_DB.batch([clockUpsert(env, sub, 'sub', authorSub, t), change]);
  const row = await env.ADS_DB.prepare('SELECT 1 AS x FROM subscriptions WHERE subscriber_sub = ? AND author_sub = ?').bind(sub, authorSub).first();
  return json({ ok: true, subscribed: !!row });
}

// GET /account/subscriber-count — how many accounts subscribe to the
// signed-in caller, for the account sheet's own stats (not another
// account's — this is always self-scoped, same as GET /my/pages). A
// straight COUNT against the same `subscriptions` table handleSubscribe/
// handleUnsubscribe already write, keyed by author_sub the way every
// other subscriptions query here is.
async function handleSubscriberCount(env, request) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  const [subs, likes] = await env.ADS_DB.batch([
    env.ADS_DB.prepare('SELECT COUNT(*) AS c FROM subscriptions WHERE author_sub = ?').bind(sub),
    env.ADS_DB.prepare('SELECT COUNT(*) AS c FROM likes WHERE author_sub = ?').bind(sub)
  ]);
  const one = (r) => (r && r.results && r.results[0] && r.results[0].c) || 0;
  // `likes` = total likes across every note this account has published, shown
  // next to the subscriber count on the Account sheet.
  return json({ count: one(subs), likes: one(likes) });
}

// GET /subscriptions — every author the signed-in account follows, as a list
// of author subs. This is the server-side source of truth the app reconciles
// its local "who I follow" list against, so the Subscribe button and the
// "Subscribed" category are right on a new/second device instead of only on
// the device where the follow happened.
const MAX_SUBSCRIPTIONS_LISTED = 5000;
async function handleGetSubscriptions(env, request) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  const { results } = await env.ADS_DB.prepare(
    'SELECT author_sub FROM subscriptions WHERE subscriber_sub = ? ORDER BY created_at DESC LIMIT ?'
  ).bind(sub, MAX_SUBSCRIPTIONS_LISTED).all();
  const idBySub = await authorIdsFor(env, results.map(r => r.author_sub));
  const subs = results.map(r => idBySub[r.author_sub]).filter(id => typeof id === 'string' && id);
  const skipped = results.length - subs.length;
  if (skipped) console.warn('GET /subscriptions: ' + skipped + ' followed author(s) had no author id and were left out');
  // `partial` tells the app the list can't be trusted for removals (cut off at the
  // cap, or some authors couldn't be mapped): it may add from it but must not drop
  // follows it already has.
  return json({ subs, partial: skipped > 0 || results.length >= MAX_SUBSCRIPTIONS_LISTED });
}

/* ---------------- Likes ---------------- */

// GET /likes/:slug — has the signed-in account liked this note? Lets the
// heart show the right state on a device that never saw the like happen.
async function handleLikeState(env, request, slug) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  if (!validSlug(slug)) return textError(400, 'invalid slug');
  const row = await env.ADS_DB.prepare(
    'SELECT 1 AS x FROM likes WHERE liker_sub = ? AND slug = ?'
  ).bind(sub, slug).first();
  return json({ liked: !!row });
}

// POST /likes/counts — body { slugs: [...] } (max 200). Live like totals for the cards on screen,
// { counts: { slug: n } } with an explicit 0 for slugs nobody has liked. One grouped read per 80 slugs.
async function handleLikeCounts(env, request) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  let body; try { body = await request.json(); } catch (e) { return textError(400, 'invalid JSON body'); }
  const slugs = Array.isArray(body && body.slugs) ? body.slugs.filter(x => typeof x === 'string' && x).slice(0, 200) : [];
  const found = await likeCountsFor(env, slugs);
  const counts = {};
  slugs.forEach(sl => { counts[sl] = found[sl] || 0; });
  return json({ counts });
}

// GET /likes — every slug this account has liked, so a second device shows
// its hearts without having to open each note first.
const MAX_LIKES_LISTED = 5000;
async function handleLikesList(env, request) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  const { results } = await env.ADS_DB.prepare(
    'SELECT slug FROM likes WHERE liker_sub = ? ORDER BY created_at DESC LIMIT ?'
  ).bind(sub, MAX_LIKES_LISTED).all();
  return json({ slugs: results.map(r => r.slug), partial: results.length >= MAX_LIKES_LISTED });
}

// POST /likes/:slug — like a live published note. Idempotent (INSERT OR
// IGNORE), so a retry or a second device that already liked it is harmless.
// Same not-live gating as handleMeta/handleServe; you can't like your own
// note (mirrors "can't subscribe to yourself"). Latest tap wins (see actionTime).
async function handleLike(env, request, slug) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  { const limited = await accountRateLimitResponse(env, sub, 'like'); if (limited) return limited; }
  if (!validSlug(slug)) return textError(400, 'invalid slug');
  const meta = await getMeta(env, slug);
  if (!meta || meta.deletedAt || meta.adminLocked) return textError(404, 'note isn\u2019t available');
  if (meta.ownerSub && meta.ownerSub === sub) return textError(400, 'can\u2019t like your own note');
  const t = actionTime(request);
  await env.ADS_DB.batch([
    clockUpsert(env, sub, 'like', slug, t),
    env.ADS_DB.prepare('INSERT OR IGNORE INTO likes (liker_sub, slug, author_sub, created_at) SELECT ?, ?, ?, ? WHERE ' + CLOCK_IS)
      .bind(sub, slug, meta.ownerSub || '', Date.now(), sub, 'like', slug, t)
  ]);
  const row = await env.ADS_DB.prepare('SELECT 1 AS x FROM likes WHERE liker_sub = ? AND slug = ?').bind(sub, slug).first();
  return json({ ok: true, liked: !!row });
}

// DELETE /likes/:slug — remove this account's like. No liveness check on
// purpose: someone should still be able to clear a like on a note that has
// since been unpublished (its likes are removed anyway, so this is a no-op).
async function handleUnlike(env, request, slug) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  { const limited = await accountRateLimitResponse(env, sub, 'like'); if (limited) return limited; }
  if (!validSlug(slug)) return textError(400, 'invalid slug');
  const t = actionTime(request);
  await env.ADS_DB.batch([
    clockUpsert(env, sub, 'like', slug, t),
    env.ADS_DB.prepare('DELETE FROM likes WHERE liker_sub = ? AND slug = ? AND ' + CLOCK_IS)
      .bind(sub, slug, sub, 'like', slug, t)
  ]);
  const row = await env.ADS_DB.prepare('SELECT 1 AS x FROM likes WHERE liker_sub = ? AND slug = ?').bind(sub, slug).first();
  return json({ ok: true, liked: !!row });
}

const SUBSCRIPTIONS_FEED_PAGE_SIZE = 20;
// Size of the whole list, sent with a list's first page only (no cursor) so the app can show
// "Library (N)" without paging through everything. Best effort: a failed count omits the field
// and the app falls back to counting what it has loaded.
async function listTotal(env, sql, params) {
  try {
    const row = await env.ADS_DB.prepare(sql).bind(...params).first();
    const n = row && Number(row.c);
    return Number.isFinite(n) ? n : undefined;
  } catch (e) { return undefined; }
}

// GET /account/liked-notes — the "Liked" tab: every live note this account has
// liked, newest like first, shaped like a Subscribed-feed card so the app renders
// both the same way. A liked note doesn't have to be a story (it may have been
// found through its link), so card details come from the stories row when there
// is one and otherwise from the note's own metadata (title, author, no thumbnails).
// Paged with a `${likedAt}:${slug}` cursor over the likes rows themselves; notes that
// have since gone (taken down) are skipped without ending the page early.
// Thumbnails for a liked note that isn't a story. Built once from the published page,
// through the same storeStoryCardImages the stories use (so the same public
// /stories/card-image/ URLs serve them), and cached with the page's updatedAt so an
// edit rebuilds them. Removed with the page (unpublish / account deletion).
function cardImagesKey(slug) { return 'cardimgs:' + slug; }
async function ensureCardImages(env, slug, meta) {
  try {
    const raw = await env.SLUGS.get(cardImagesKey(slug));
    if (raw) { const c = JSON.parse(raw); if (c && c.v === meta.updatedAt && typeof c.j === 'string') return c.j; }
    const obj = await env.NOTES_BUCKET.get(slug + '.html');
    if (!obj) return null;
    const j = await storeStoryCardImages(env, slug, await obj.text());
    await env.SLUGS.put(cardImagesKey(slug), JSON.stringify({ v: meta.updatedAt, j }));
    return j;
  } catch (e) { console.log('card images failed for ' + slug + ': ' + (e && e.message)); return null; }
}
// Likes each note has received, as { slug: count } (slugs with none are simply absent).
// One grouped query per chunk, so a page of cards costs a query or two, not one per card.
async function likeCountsFor(env, slugs) {
  const out = {};
  const uniq = [...new Set((slugs || []).filter(Boolean))];
  for (let i = 0; i < uniq.length; i += 80) {
    const chunk = uniq.slice(i, i + 80);
    const { results } = await env.ADS_DB.prepare(
      'SELECT slug, COUNT(*) AS c FROM likes WHERE slug IN (' + chunk.map(() => '?').join(',') + ') GROUP BY slug'
    ).bind(...chunk).all();
    results.forEach(r => { out[r.slug] = r.c; });
  }
  return out;
}

// GET /account/published-notes — the "Published" category: every live note this account
// has published, newest first, shaped like a Subscribed-feed card plus its like total.
// Ownership lives in the owner:<sub>:<slug> KV index (bounded by MAX_PAGES_PER_ACCOUNT),
// so the whole set is read, ordered by publish time, and paged with a
// `${publishedAt}:${slug}` cursor. Card details come from the stories row when the note
// is a story, otherwise from the note's own metadata + cached thumbnails (same as Liked).
// GET /account/stories — the "Stories" tab: the signed-in account's own published notes
// that are toggled to show in stories AND still currently live there — i.e. within the
// same STORIES_LOOKBACK_MS (24h) window as the public discovery strip (see
// handleStoriesStrip). A note whose toggle is on but whose 24h has elapsed keeps showing
// in followers' Subscribed feeds (handleSubscriptionsFeed's cutoff is the longer SUBSCRIPTIONS_FEED_MAX_AGE_MS) but drops out
// of this tab, the same as it drops out of the strip, until it's updated/republished.
async function handleMyStories(env, request) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');

  const url = new URL(request.url);
  const cursorParam = url.searchParams.get('cursor');
  let cursorAt = null, cursorSlug = null;
  if (cursorParam) {
    const i = cursorParam.lastIndexOf(':');
    if (i > 0) {
      const at = Number(cursorParam.slice(0, i));
      if (Number.isFinite(at)) { cursorAt = at; cursorSlug = cursorParam.slice(i + 1); }
    }
  }

  const cutoff = Date.now() - STORIES_LOOKBACK_MS;
  let query = `SELECT slug, title, created_at, image_urls, description, tags, note_created_at
     FROM stories WHERE author_sub = ? AND created_at >= ?`;
  const params = [sub, cutoff];
  if (cursorAt !== null) {
    query += ' AND (created_at < ? OR (created_at = ? AND slug < ?))';
    params.push(cursorAt, cursorAt, cursorSlug);
  }
  query += ' ORDER BY created_at DESC, slug DESC LIMIT ?';
  params.push(SUBSCRIPTIONS_FEED_PAGE_SIZE);
  const { results } = await env.ADS_DB.prepare(query).bind(...params).all();

  const likeCounts = await likeCountsFor(env, results.map(r => r.slug));
  const user = await getUser(env, sub);
  const authorId = (await authorIdsFor(env, [sub]))[sub] || null;
  const origin = url.origin;
  const last = results[results.length - 1];
  const total = cursorParam ? undefined : await listTotal(env,
    'SELECT COUNT(*) AS c FROM stories WHERE author_sub = ? AND created_at >= ?', [sub, cutoff]);
  return json({
    total,
    stories: results.map(r => {
      const card = expandStoryImageUrls(origin, r.slug, r.image_urls);
      return {
        slug: r.slug,
        title: r.title,
        authorSub: authorId,
        authorProfileName: (user && user.profileName) || null,
        createdAt: r.created_at,
        noteCreatedAt: r.note_created_at || null,
        desc: r.description || '',
        tags: parseStoryTags(r.tags),
        seen: false,
        images: card.images,
        imageCount: card.count,
        likes: likeCounts[r.slug] || 0
      };
    }),
    nextCursor: (last && results.length === SUBSCRIPTIONS_FEED_PAGE_SIZE) ? `${last.created_at}:${last.slug}` : null
  });
}

async function handlePublishedNotes(env, request) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');

  const url = new URL(request.url);
  const cursorParam = url.searchParams.get('cursor');
  let cursorAt = null, cursorSlug = null;
  if (cursorParam) {
    const i = cursorParam.lastIndexOf(':');
    if (i > 0) {
      const at = Number(cursorParam.slice(0, i));
      if (Number.isFinite(at)) { cursorAt = at; cursorSlug = cursorParam.slice(i + 1); }
    }
  }

  // Indexed keyset pagination against published_notes (migrations/0010_published_notes.sql),
  // kept in sync with the SLUGS "owner:<sub>:<slug>" keys at publish/unpublish/purge time —
  // same shape as handleLikedNotes/handleSubscriptionsFeed, rather than listing every owned
  // KV key and calling getMeta on each one per request.
  let query = `SELECT slug, created_at FROM published_notes WHERE author_sub = ?`;
  const params = [sub];
  if (cursorAt !== null) {
    query += ' AND (created_at < ? OR (created_at = ? AND slug < ?))';
    params.push(cursorAt, cursorAt, cursorSlug);
  }
  query += ' ORDER BY created_at DESC, slug DESC LIMIT ?';
  params.push(SUBSCRIPTIONS_FEED_PAGE_SIZE);
  const { results } = await env.ADS_DB.prepare(query).bind(...params).all();

  // Live notes only, same guard handleLikedNotes uses — a note taken down since it was
  // indexed here (unpublish already deletes its row, so this only catches an admin
  // takedown or a race) is skipped rather than shown; as there, a page shortened this
  // way can under-report whether more remain, exactly like handleLikedNotes already does.
  const rows = [];
  for (const r of results) {
    const meta = await getMeta(env, r.slug);
    if (!meta || meta.deletedAt || meta.adminLocked) continue;
    rows.push({ slug: r.slug, at: r.created_at, meta });
  }

  const storyBySlug = {};
  if (rows.length) {
    const slugs = rows.map(x => x.slug);
    const { results: storyRows } = await env.ADS_DB.prepare(
      'SELECT slug, title, image_urls, description, tags, note_created_at FROM stories WHERE slug IN (' + slugs.map(() => '?').join(',') + ')'
    ).bind(...slugs).all();
    storyRows.forEach(r => { storyBySlug[r.slug] = r; });
  }
  const likeCounts = await likeCountsFor(env, rows.map(x => x.slug));
  const user = await getUser(env, sub);
  const authorId = (await authorIdsFor(env, [sub]))[sub] || null;
  const origin = url.origin;
  const out = [];
  for (const { slug, at, meta } of rows) {
    const st = storyBySlug[slug];
    const imgJson = st ? st.image_urls : await ensureCardImages(env, slug, meta);
    const card = imgJson ? expandStoryImageUrls(origin, slug, imgJson) : { images: [], count: 0 };
    out.push({
      slug,
      title: st ? st.title : (meta.title || 'Untitled note'),
      authorSub: authorId,
      authorProfileName: (user && user.profileName) || null,
      publishedAt: at,
      noteCreatedAt: (st ? st.note_created_at : meta.noteCreatedAt) || null,
      desc: (st ? st.description : meta.desc) || '',
      tags: st ? parseStoryTags(st.tags) : (Array.isArray(meta.tags) ? meta.tags.filter(x => typeof x === 'string') : []),
      seen: false,
      images: card.images,
      imageCount: card.count,
      likes: likeCounts[slug] || 0
    });
  }
  const last = results[results.length - 1];
  const total = cursorParam ? undefined : await listTotal(env,
    'SELECT COUNT(*) AS c FROM published_notes WHERE author_sub = ?', [sub]);
  return json({
    total,
    stories: out,
    nextCursor: (last && results.length === SUBSCRIPTIONS_FEED_PAGE_SIZE) ? `${last.created_at}:${last.slug}` : null
  });
}

async function handleLikedNotes(env, request) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');

  const url = new URL(request.url);
  const cursorParam = url.searchParams.get('cursor');
  let cursorAt = null, cursorSlug = null;
  if (cursorParam) {
    const i = cursorParam.lastIndexOf(':');
    if (i > 0) {
      const at = Number(cursorParam.slice(0, i));
      if (Number.isFinite(at)) { cursorAt = at; cursorSlug = cursorParam.slice(i + 1); }
    }
  }

  let query = `SELECT l.slug, l.author_sub AS liked_author, l.created_at AS liked_at,
       s.author_sub AS story_author, s.title AS story_title, s.image_urls, s.description, s.tags, s.note_created_at,
       s.created_at AS story_created_at, p.created_at AS published_at
     FROM likes l
     LEFT JOIN stories s ON s.slug = l.slug
     LEFT JOIN published_notes p ON p.slug = l.slug
     WHERE l.liker_sub = ?`;
  const params = [sub];
  if (cursorAt !== null) {
    query += ' AND (l.created_at < ? OR (l.created_at = ? AND l.slug < ?))';
    params.push(cursorAt, cursorAt, cursorSlug);
  }
  query += ' ORDER BY l.created_at DESC, l.slug DESC LIMIT ?';
  params.push(SUBSCRIPTIONS_FEED_PAGE_SIZE);
  const { results } = await env.ADS_DB.prepare(query).bind(...params).all();

  // Live notes only, with the fields each card needs.
  const rows = [];
  for (const r of results) {
    const meta = await getMeta(env, r.slug);
    if (!meta || meta.deletedAt || meta.adminLocked) continue;
    const authorSub = r.story_author || r.liked_author || meta.ownerSub || '';
    const isStory = r.story_title != null;
    rows.push({ r, meta, authorSub, isStory, imgJson: isStory ? r.image_urls : await ensureCardImages(env, r.slug, meta) });
  }
  const authorSubs = [...new Set(rows.map(x => x.authorSub).filter(Boolean))];
  const nameBySub = {};
  for (const a of authorSubs) {
    const user = await getUser(env, a);
    nameBySub[a] = (user && user.profileName) || null;
  }
  const idBySub = authorSubs.length ? await authorIdsFor(env, authorSubs) : {};
  const likeCounts = await likeCountsFor(env, rows.map(x => x.r.slug));

  const origin = url.origin;
  const last = results[results.length - 1];
  const total = cursorParam ? undefined : await listTotal(env,
    'SELECT COUNT(*) AS c FROM likes WHERE liker_sub = ?', [sub]);
  return json({
    total,
    stories: rows.map(({ r, meta, authorSub, isStory, imgJson }) => {
      const card = imgJson ? expandStoryImageUrls(origin, r.slug, imgJson) : { images: [], count: 0 };
      return {
        slug: r.slug,
        title: isStory ? r.story_title : (meta.title || 'Untitled note'),
        authorSub: authorSub ? idBySub[authorSub] : null, // opaque author ID, same as the feed
        authorProfileName: authorSub ? nameBySub[authorSub] : null,
        likedAt: r.liked_at,
        createdAt: isStory ? r.story_created_at : null, // when it became a story (what the card's time-ago shows)
        publishedAt: r.published_at || null, // stands in for a liked note that isn't a story
        noteCreatedAt: (isStory ? r.note_created_at : meta.noteCreatedAt) || null,
        desc: (isStory ? r.description : meta.desc) || '',
        tags: parseStoryTags(isStory ? r.tags : meta.tags),
        seen: false,
        images: card.images,
        imageCount: card.count,
        likes: likeCounts[r.slug] || 0
      };
    }),
    nextCursor: (last && results.length === SUBSCRIPTIONS_FEED_PAGE_SIZE) ? `${last.liked_at}:${last.slug}` : null
  });
}

// GET /subscriptions/feed — the "Subscribed" category: a regular social
// feed, not a Stories surface. No 24h expiry (that ephemerality is
// specific to the discovery strip/ring — see handleStoriesStrip), but
// posts age out after SUBSCRIPTIONS_FEED_MAX_AGE_MS. Three
// things that make this behave like an actual feed rather than a dump
// of everything:
//
// - Age cutoff (SUBSCRIPTIONS_FEED_MAX_AGE_MS, applied in the JOIN below):
//   a post leaves the feed once it's older than that, like any feed.
//
// - Per-author floor at subscribe time (s.created_at >= sub.created_at
//   in the JOIN below): following someone surfaces what they post from
//   that point on, not their whole back catalog — same as following an
//   account anywhere else. Unsubscribing and re-subscribing later resets
//   this floor to the new subscribe time, same reasoning.
// - Keyset pagination via an opaque `cursor` query param (this endpoint's
//   own past output, not something the client constructs): first call
//   omits it; each response's `nextCursor` is passed back to fetch the
//   next older page, `null` means there's nothing more. This is keyset
//   (created_at+slug), not an offset — the client isn't tracking a page
//   number, it's tracking "the last thing I've already loaded", so a new
//   post arriving between page loads doesn't shift already-seen items
//   into a later page or duplicate them into an earlier one.
async function handleSubscriptionsFeed(env, request) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');

  const url = new URL(request.url);
  const cursorParam = url.searchParams.get('cursor');
  let cursorCreatedAt = null, cursorSlug = null;
  if (cursorParam) {
    const i = cursorParam.lastIndexOf(':');
    if (i > 0) {
      const at = Number(cursorParam.slice(0, i));
      if (Number.isFinite(at)) { cursorCreatedAt = at; cursorSlug = cursorParam.slice(i + 1); }
    }
  }

  let query = `SELECT s.slug, s.author_sub, s.title, s.created_at, s.image_urls, s.description, s.tags, s.note_created_at, seen.slug IS NOT NULL AS seen
     FROM stories s
     JOIN subscriptions sub ON sub.author_sub = s.author_sub AND sub.subscriber_sub = ? AND s.created_at >= sub.created_at AND s.created_at >= ?
     LEFT JOIN story_seen seen ON seen.slug = s.slug AND seen.subscriber_sub = ?`;
  const feedCutoff = Date.now() - SUBSCRIPTIONS_FEED_MAX_AGE_MS;
  const params = [sub, feedCutoff, sub];
  if (cursorCreatedAt !== null) {
    query += ' WHERE (s.created_at < ? OR (s.created_at = ? AND s.slug < ?))';
    params.push(cursorCreatedAt, cursorCreatedAt, cursorSlug);
  }
  query += ' ORDER BY s.created_at DESC, s.slug DESC LIMIT ?';
  params.push(SUBSCRIPTIONS_FEED_PAGE_SIZE);

  const { results } = await env.ADS_DB.prepare(query).bind(...params).all();

  // One ACCOUNTS lookup per distinct author, not per story — a prolific
  // subscribed author shouldn't cost a KV read per note. Fine at this
  // app's scale (same tradeoff handleMyPages already makes doing a KV
  // get per slug).
  const authorSubs = [...new Set(results.map(r => r.author_sub))];
  const nameBySub = {};
  for (const authorSub of authorSubs) {
    const user = await getUser(env, authorSub);
    nameBySub[authorSub] = (user && user.profileName) || null;
  }
  const idBySub = await authorIdsFor(env, authorSubs);
  const likeCounts = await likeCountsFor(env, results.map(r => r.slug));

  const origin = new URL(request.url).origin;
  const last = results[results.length - 1];
  const total = cursorParam ? undefined : await listTotal(env,
    `SELECT COUNT(*) AS c FROM stories s
       JOIN subscriptions sub ON sub.author_sub = s.author_sub AND sub.subscriber_sub = ? AND s.created_at >= sub.created_at AND s.created_at >= ?`, [sub, feedCutoff]);
  return json({
    total,
    stories: results.map(r => {
      const card = expandStoryImageUrls(origin, r.slug, r.image_urls);
      return {
        slug: r.slug,
        title: r.title,
        authorSub: idBySub[r.author_sub], // opaque author ID (field name kept for older app builds)
        authorProfileName: nameBySub[r.author_sub],
        createdAt: r.created_at, // when it became a story (drives feed order)
        noteCreatedAt: r.note_created_at || null, // when the note itself was created (what the card's time-ago shows)
        desc: r.description || '',
        tags: parseStoryTags(r.tags),
        seen: !!r.seen,
        images: card.images,
        imageCount: card.count, // total images in the note, for the "+N" badge
        likes: likeCounts[r.slug] || 0 // likes the note has received, shown beside the time-ago
      };
    }),
    // A short page means we've hit the end; only hand back a cursor when
    // there might be more to page to.
    nextCursor: (last && results.length === SUBSCRIPTIONS_FEED_PAGE_SIZE) ? `${last.created_at}:${last.slug}` : null
  });
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
//
// CSAM reports get their own, much higher bucket: a legitimate reporter on a
// shared IP (carrier NAT, school network) must not be locked out of an urgent
// report by other people's traffic, but the endpoint still can't be hammered
// without bound.
const REPORT_RATE_LIMIT_MAX = 5;
const REPORT_RATE_LIMIT_CSAM_MAX = 30;
const REPORT_RATE_LIMIT_WINDOW_S = 60;
// At most one webhook alert per slug per this window (non-CSAM only — CSAM
// alerts are never throttled). Reports are still stored either way.
const REPORT_ALERT_THROTTLE_S = 300;
const REPORT_BODY_MAX_BYTES = 8192;
// Report keys: "rpt:<13-digit inverted ms timestamp>:<slug>:<8 hex>". The
// inverted timestamp makes KV's lexicographic list order newest-first, so the
// admin page can paginate with the KV cursor instead of scanning everything.
// The random suffix prevents two reports in the same millisecond overwriting
// each other. Older records use the legacy "report:<slug>:<ms>" format; the
// admin list still reads them (after the new ones) until they're dismissed.
const REPORT_KEY_PREFIX = 'rpt:';
const REPORT_TS_MAX = 9999999999999;
const REPORT_KEY_RE = /^rpt:(\d{13}):([a-z0-9-]{3,48}):[a-f0-9]{8}$/;
const REPORT_LEGACY_KEY_RE = /^report:([a-z0-9-]{3,48}):(\d+)$/;
const REPORT_DISMISSED_CSAM_TTL_S = Math.ceil(CSAM_RETENTION_MS / 1000);

function makeReportKey(slug, ts) {
  return REPORT_KEY_PREFIX + String(REPORT_TS_MAX - ts).padStart(13, '0')
    + ':' + slug + ':' + crypto.randomUUID().slice(0, 8);
}

async function checkReportRateLimit(env, ip, isCsam) {
  const key = (isCsam ? 'ratelimit:reportcsam:' : 'ratelimit:report:') + ip;
  const max = isCsam ? REPORT_RATE_LIMIT_CSAM_MAX : REPORT_RATE_LIMIT_MAX;
  const raw = await env.REPORTS.get(key);
  const count = raw ? (parseInt(raw, 10) || 0) : 0;
  if (count >= max) return false;
  await env.REPORTS.put(key, String(count + 1), { expirationTtl: REPORT_RATE_LIMIT_WINDOW_S });
  return true;
}

async function sendReportAlert(env, request, record) {
  try {
    if (!record.isCsam) {
      const tKey = 'ratelimit:reportalert:' + record.slug;
      if (await env.REPORTS.get(tKey)) return; // already alerted recently for this slug
      await env.REPORTS.put(tKey, '1', { expirationTtl: REPORT_ALERT_THROTTLE_S });
    }
    // Slack (and most incoming-webhook consumers) require a top-level
    // "text" field to render anything at all — a raw JSON dump of
    // `record` with no "text" key gets silently rejected with
    // invalid_payload, which is exactly the kind of failure the catch
    // below would swallow without a trace. `record` itself is untouched
    // and still what gets stored in KV either way.
    const origin = new URL(request.url).origin;
    const summary = `New report for /${record.slug}${record.isCsam ? ' — CSAM' : ''}\n`
      + `Page: ${origin}/@${record.slug}\n`
      + `Review: ${origin}/admin\n`
      + `Reason: ${record.reason}\n`
      + `Details: ${record.details || '(none provided)'}`;
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

async function handleReport(env, request, slug, ctx) {
  if (!SLUG_RE.test(slug)) return textError(400, 'invalid slug');
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  // Read the body first: the rate-limit bucket depends on the reason (CSAM
  // reports get the higher limit). Size-capped so this can't be used to make
  // the Worker buffer huge bodies.
  const declared = parseInt(request.headers.get('Content-Length') || '0', 10) || 0;
  if (declared > REPORT_BODY_MAX_BYTES) return textError(413, 'report too large');
  let raw;
  try { raw = await request.text(); } catch (e) { return textError(400, 'invalid body'); }
  if (raw.length > REPORT_BODY_MAX_BYTES) return textError(413, 'report too large');
  let body;
  try { body = JSON.parse(raw); } catch (e) { return textError(400, 'invalid JSON body'); }
  const reason = typeof body?.reason === 'string' ? body.reason.slice(0, 40) : 'other';
  const details = typeof body?.details === 'string' ? body.details.slice(0, 2000) : '';
  // CSAM is split into its own category deliberately (plan §5.1/§5.2): it is
  // the one case where "we don't moderate" doesn't apply. It must be
  // reported to NCMEC's CyberTipline and the content preserved rather than
  // deleted — that response path is a legal/operational process outside
  // this Worker, not something to automate away here.
  const isCsam = reason === 'csam';
  if (!(await checkReportRateLimit(env, ip, isCsam))) {
    return textError(429, 'too many reports from this address. Try again in a minute');
  }
  // Reject reports for slugs that were never published, so junk records and
  // alerts can't be generated for made-up slugs. (Unpublished and
  // taken-down slugs keep their metadata and stay reportable.)
  if (!(await getMeta(env, slug))) return textError(404, 'page not found');

  const record = { slug, reason, details, isCsam, reportedAt: Date.now() };
  await env.REPORTS.put(makeReportKey(slug, record.reportedAt), JSON.stringify(record));
  // CSAM report: snapshot the page, and hold this slug's deleted/ snapshots (and root object)
  // out of the purge job for CSAM_RETENTION_MS. Kept in its own key so it survives the slug's KV metadata being
  // purged. A newer report re-arms the full window.
  if (isCsam) {
    // Snapshot the live page now, so an owner edit/republish before takedown can't overwrite
    // the reported content. Skipped when the page is unchanged since the last CSAM report
    // (same etag), so repeated reports don't pile up copies. Best-effort: a failure here
    // must not lose the report or its hold.
    let etag = null;
    try {
      let prev = null;
      try { prev = JSON.parse(await env.SLUGS.get(CSAM_HOLD_PREFIX + slug)); } catch (e) {}
      const head = await env.NOTES_BUCKET.head(slug + '.html');
      etag = head ? head.etag : null;
      if (head && !(prev && prev.etag === etag)) {
        const liveObj = await env.NOTES_BUCKET.get(slug + '.html');
        if (liveObj) {
          await env.NOTES_BUCKET.put(`deleted/${slug}/${record.reportedAt}.html`, liveObj.body, {
            httpMetadata: { contentType: 'text/html; charset=utf-8' },
            customMetadata: { source: 'report' }
          });
        }
      }
    } catch (e) { console.log('csam snapshot failed: ' + (e && e.message)); etag = null; }
    await env.SLUGS.put(CSAM_HOLD_PREFIX + slug,
      JSON.stringify({ until: record.reportedAt + CSAM_RETENTION_MS, etag }),
      { expirationTtl: Math.ceil(CSAM_RETENTION_MS / 1000) });
  }

  if (env.REPORT_WEBHOOK_URL) {
    // Off the reporter's critical path: the response doesn't wait on Slack.
    const task = sendReportAlert(env, request, record);
    if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(task); else await task;
  }
  return json({ ok: true });
}

// Purge job (plan §3.5/§12): deletes R2 blobs (and their KV metadata) for
// slugs soft-deleted more than SOFT_DELETE_RETENTION_MS ago, plus the
// pre-overwrite snapshots handleUnpublish() writes under "deleted/". Wired
// to the cron trigger declared in wrangler.toml via the scheduled() export
// below — GET/POST/etc. traffic never touches this, only Cloudflare's
// scheduler does.
async function isCsamHeld(env, slug) {
  return (await env.SLUGS.get(CSAM_HOLD_PREFIX + slug)) !== null;
}

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
      // CSAM-reported: leave the object, metadata and lock alone until the hold expires.
      if (await isCsamHeld(env, slug)) continue;
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
      if (meta.ownerSub) {
        await env.SLUGS.delete('owner:' + meta.ownerSub + ':' + slug);
        await env.ADS_DB.prepare('DELETE FROM published_notes WHERE slug = ?').bind(slug).run();
      }
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
      const snapSlug = obj.key.split('/')[1];
      if (snapSlug && await isCsamHeld(env, snapSlug)) continue; // CSAM hold: keep the snapshot
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

  // Latest-tap clocks (see actionTime) that no longer guard anything: the like/follow
  // they belong to is gone and the last tap is older than the retention window, so no
  // queued offline replay can still be waiting on them. Also sweeps the backlog left
  // by unpublishes from before those paths cleaned up after themselves.
  try {
    const r = await env.ADS_DB.prepare(
      "DELETE FROM action_clocks WHERE t < ? AND (" +
      "(kind = 'like' AND NOT EXISTS (SELECT 1 FROM likes l WHERE l.liker_sub = action_clocks.sub AND l.slug = action_clocks.item)) OR " +
      "(kind = 'sub' AND NOT EXISTS (SELECT 1 FROM subscriptions s WHERE s.subscriber_sub = action_clocks.sub AND s.author_sub = action_clocks.item)))"
    ).bind(cutoff).run();
    purged += (r && r.meta && r.meta.changes) || 0;
  } catch (e) { console.log('action_clocks gc failed: ' + (e && e.message)); }

  // Best-effort: an error here must never stop the rest of the purge above.
  try { purged += await gcSyncImages(env); } catch (e) { console.log('gcSyncImages failed: ' + (e && e.message)); }

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
async function revokeAllSessions(env, sub) {
  const prefix = 'usess:' + sub + ':';
  let cursor;
  do {
    const page = await env.ACCOUNTS.list({ prefix, cursor });
    for (const key of page.keys) {
      await env.ACCOUNTS.delete('session:' + key.name.slice(prefix.length));
      await env.ACCOUNTS.delete(key.name);
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
}

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
  // Every other device signs out too: revoke all of this account's sessions.
  // Each device finds out on its next request (the app polls sync every ~20s,
  // and a 401 there signs it out locally). Sessions from before the index
  // existed can't be listed; requireSessionInfo rejects those via
  // pendingDeletionAt instead.
  await revokeAllSessions(env, sub);

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
        await env.ADS_DB.batch([
          env.ADS_DB.prepare('DELETE FROM likes WHERE slug = ?').bind(slug),
          env.ADS_DB.prepare("DELETE FROM action_clocks WHERE kind = 'like' AND item = ?").bind(slug)
        ]);
        await deleteStoryCardImages(env, slug);
        await env.SLUGS.delete(cardImagesKey(slug));
        if (meta.showInStories) {
          await deleteStoryImage(env, slug);
          await env.ADS_DB.batch([
            env.ADS_DB.prepare('DELETE FROM stories WHERE slug = ?').bind(slug),
            env.ADS_DB.prepare('DELETE FROM story_seen WHERE slug = ?').bind(slug)
          ]);
        }
      }
      await env.SLUGS.delete(key.name);
      await env.ADS_DB.prepare('DELETE FROM published_notes WHERE slug = ?').bind(slug).run();
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);

  await revokeAllSessions(env, sub);
  await env.ACCOUNTS.delete('user:' + sub);
  await env.ACCOUNTS.delete('syncmeta:' + sub);
  await env.NOTES_BUCKET.delete('sync/' + sub + '/notes.json');
  let imgCursor;
  do {
    const page = await env.NOTES_BUCKET.list({ prefix: 'sync/' + sub + '/img/', cursor: imgCursor });
    for (const o of page.objects) await env.NOTES_BUCKET.delete(o.key);
    imgCursor = page.truncated ? page.cursor : undefined;
  } while (imgCursor);
  await env.NOTES_BUCKET.delete(profileImageKey(sub));
  // Subscriptions run both directions — as a follower and as someone
  // others followed — and story_seen rows are meaningless without the
  // account that saw them, so all three go with the account.
  await env.ADS_DB.batch([
    env.ADS_DB.prepare('DELETE FROM subscriptions WHERE subscriber_sub = ? OR author_sub = ?').bind(sub, sub),
    env.ADS_DB.prepare('DELETE FROM story_seen WHERE subscriber_sub = ?').bind(sub),
    // Likes this account gave, and any still attached to its notes.
    env.ADS_DB.prepare('DELETE FROM likes WHERE liker_sub = ? OR author_sub = ?').bind(sub, sub),
    env.ADS_DB.prepare('DELETE FROM action_clocks WHERE sub = ?').bind(sub),
    // Other people's follow clocks pointing at this (now gone) author.
    env.ADS_DB.prepare("DELETE FROM action_clocks WHERE kind = 'sub' AND item = ?").bind(sub),
    env.ADS_DB.prepare('DELETE FROM authors WHERE sub = ?').bind(sub),
    // Ads (and their unique-viewer rows) this account ran, plus its view-credit
    // ledger (unspent balance included).
    env.ADS_DB.prepare('DELETE FROM ad_viewers WHERE slug IN (SELECT slug FROM ads WHERE owner_sub = ?)').bind(sub),
    env.ADS_DB.prepare('DELETE FROM ads WHERE owner_sub = ?').bind(sub),
    env.ADS_DB.prepare('DELETE FROM view_credits_ledger WHERE owner_sub = ?').bind(sub)
  ]);
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
  if (existingAd) return textError(409, 'already registered as an ad. Use PUT to edit or top up separately');

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
// remaining credit balance for buying more. unique_viewers is a reporting-
// only figure from the ad_viewers dedup table (see handleAdView) — it never
// factors into views_used/views_total or spend, which are unrelated
// impression counters computed straight off the ads row.
async function handleMyAds(env, request) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  const { results } = await env.ADS_DB.prepare(
    `SELECT a.slug, a.views_total, a.views_used, a.status, a.created_at, a.updated_at,
            (SELECT COUNT(*) FROM ad_viewers v WHERE v.slug = a.slug) AS unique_viewers
     FROM ads a WHERE a.owner_sub = ? ORDER BY a.created_at DESC`
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

  // Never serve an ad whose page is gone (unpublished, taken down, or its
  // owner's account was purged). Also heals rows from before handleUnpublish
  // took ads down itself.
  const meta = await getMeta(env, ad.slug);
  if (!meta || meta.deletedAt) {
    await env.ADS_DB.prepare("UPDATE ads SET status = 'unpublished', updated_at = ? WHERE slug = ? AND status = 'active'")
      .bind(Date.now(), ad.slug).run();
    return json({ ad: null }); // next tap moves on to the next ad
  }
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
//
// Separately (and NOT gating the above in any way) records a best-effort
// unique-viewer signal for reporting: the client sends an anonymous,
// per-device id (see _nbDeviceId in the app) as `viewerId`, and an
// INSERT OR IGNORE against ad_viewers's (slug, viewer_id) primary key
// dedupes repeat views from the same device. This is a reporting figure
// only — it does not gate the view/spend counters above, doesn't require
// sign-in, and is a heuristic (same person on two devices counts twice;
// a reinstall counts as a new viewer) rather than a strong identity check.
// A missing/old-client request (no viewerId, or no body at all) still
// counts the impression as before; it's just left out of the unique count.
async function handleAdView(env, request, slug) {
  if (!validSlug(slug)) return textError(400, 'invalid slug');
  let body;
  try { body = await request.json(); } catch (e) { body = {}; }
  const viewerId = typeof body?.viewerId === 'string' ? body.viewerId.slice(0, MAX_VIEWER_ID_LEN) : null;

  const row = await env.ADS_DB.prepare(`
    UPDATE ads
    SET views_used = views_used + 1,
        updated_at = ?,
        status = CASE WHEN views_used + 1 >= views_total THEN 'exhausted' ELSE status END
    WHERE slug = ? AND status = 'active' AND views_used < views_total
    RETURNING views_used, views_total, status
  `).bind(Date.now(), slug).first();

  if (row && viewerId) {
    // Best-effort: never let a failure here affect the response — the
    // impression above already landed regardless of what happens next.
    try {
      await env.ADS_DB.prepare(
        'INSERT OR IGNORE INTO ad_viewers (slug, viewer_id, first_seen_at) VALUES (?, ?, ?)'
      ).bind(slug, viewerId, Date.now()).run();
    } catch (e) { /* reporting-only; swallow */ }
  }

  // Not finding a row to update (already exhausted/unpublished/unknown
  // slug, or a race with another view landing the exact same moment) isn't
  // an error worth surfacing to the editor — the view simply isn't counted.
  return json({ ok: true, counted: !!row, ...(row || {}) });
}

/* ---------------- Admin takedown UI ---------------- */
// GET /admin serves a small single-file page; GET /admin/reports lists
// stored reports (newest first, cursor-paginated) behind the ADMIN_TOKEN, sent in the
// X-Admin-Token header; POST /admin/dismiss clears a handled report. The page's Take down button calls the existing
// DELETE /publish/:slug admin path, so takedown semantics (snapshot to
// deleted/, permanent adminLocked) are unchanged. The token is kept in
// sessionStorage only (cleared when the tab closes).
const ADMIN_PAGE_SIZE = 30; // keeps GETs per request well under the free-plan subrequest cap

async function adminAuthOk(env, request, providedOverride) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rlKey = 'ratelimit:adminfail:' + ip;
  const fails = parseInt((await env.REPORTS.get(rlKey)) || '0', 10) || 0;
  if (fails >= 10) return 'limited';
  const provided = providedOverride || request.headers.get('X-Admin-Token') || '';
  if (env.ADMIN_TOKEN && provided && timingSafeEqual(provided, env.ADMIN_TOKEN)) return 'ok';
  await env.REPORTS.put(rlKey, String(fails + 1), { expirationTtl: 300 });
  return 'denied';
}

// Cursor format: "<phase>:<kv cursor>" where phase "n" walks the current
// "rpt:" keys (already newest-first) and "l" then walks legacy "report:" keys.
// Empty/absent = start. Dismissed records are skipped, so a page can come
// back with fewer than ADMIN_PAGE_SIZE rows (or none) while nextCursor is
// still set; the client keeps loading until it has rows or the list ends.
async function handleAdminReports(env, request, url) {
  const auth = await adminAuthOk(env, request);
  if (auth === 'limited') return textError(429, 'too many failed attempts, try again in 5 minutes');
  if (auth !== 'ok') return textError(403, 'invalid admin token');
  let phase = 'n', kvCursor;
  const cursorParam = url.searchParams.get('cursor') || '';
  if (cursorParam) {
    const m = cursorParam.match(/^([nl]):(.*)$/s);
    if (!m) return textError(400, 'invalid cursor');
    phase = m[1]; kvCursor = m[2] || undefined;
  }
  const items = [];
  let done = false;
  while (items.length < ADMIN_PAGE_SIZE && !done) {
    const page = await env.REPORTS.list({
      prefix: phase === 'n' ? REPORT_KEY_PREFIX : 'report:',
      cursor: kvCursor,
      limit: ADMIN_PAGE_SIZE - items.length
    });
    for (const k of page.keys) {
      if (phase === 'n') {
        const m = k.name.match(REPORT_KEY_RE);
        if (m) items.push({ key: k.name, slug: m[2], ts: REPORT_TS_MAX - parseInt(m[1], 10) });
      } else {
        const m = k.name.match(REPORT_LEGACY_KEY_RE);
        if (m) items.push({ key: k.name, slug: m[1], ts: parseInt(m[2], 10) });
      }
    }
    if (page.list_complete) {
      if (phase === 'n') { phase = 'l'; kvCursor = undefined; } else done = true;
    } else {
      kvCursor = page.cursor;
    }
  }
  const nextCursor = done ? null : phase + ':' + (kvCursor || '');
  const rows = await Promise.all(items.map(async (it) => {
    let rec = null;
    try { rec = JSON.parse(await env.REPORTS.get(it.key)); } catch (e) {}
    if (rec && rec.dismissedAt) return null;
    const meta = await getMeta(env, it.slug);
    return {
      key: it.key, slug: it.slug, reportedAt: it.ts,
      reason: rec ? rec.reason : '?', details: rec ? rec.details : '',
      isCsam: !!(rec && rec.isCsam),
      status: !meta ? 'missing' : meta.adminLocked ? 'taken down' : meta.deletedAt ? 'unpublished' : 'live'
    };
  }));
  return json({ reports: rows.filter(Boolean), nextCursor });
}

// POST /admin/dismiss {key}: clears a handled/bogus report from the list.
// Ordinary reports are deleted. CSAM reports are kept (marked dismissedAt,
// hidden from the list, auto-expiring after 18 months) so there's still a
// record if one is ever needed for the NCMEC/legal process. The key is
// validated against the two report key formats so this can't be pointed at
// other keys in the namespace (rate-limit counters etc).
async function handleAdminDismiss(env, request) {
  const auth = await adminAuthOk(env, request);
  if (auth === 'limited') return textError(429, 'too many failed attempts, try again in 5 minutes');
  if (auth !== 'ok') return textError(403, 'invalid admin token');
  let body;
  try { body = await request.json(); } catch (e) { return textError(400, 'invalid JSON body'); }
  const key = typeof body?.key === 'string' ? body.key : '';
  if (!REPORT_KEY_RE.test(key) && !REPORT_LEGACY_KEY_RE.test(key)) return textError(400, 'invalid report key');
  const raw = await env.REPORTS.get(key);
  if (raw === null) return json({ ok: true }); // already gone
  let rec = null;
  try { rec = JSON.parse(raw); } catch (e) {}
  if (rec && rec.isCsam) {
    rec.dismissedAt = Date.now();
    await env.REPORTS.put(key, JSON.stringify(rec), { expirationTtl: REPORT_DISMISSED_CSAM_TTL_S });
  } else {
    await env.REPORTS.delete(key);
  }
  return json({ ok: true });
}

// GET /admin/snapshots/:slug: lists the deleted/<slug>/<ms>.html copies with
// their timestamp and (for copies written after tagging was added) source:
// 'report' | 'unpublish' | 'takedown'. Older copies come back as 'unknown'.
// Called on demand from the admin page's Snapshots button so the reports list
// itself doesn't pay an R2 list per row.
async function handleAdminSnapshots(env, request, slug) {
  const auth = await adminAuthOk(env, request);
  if (auth === 'limited') return textError(429, 'too many failed attempts, try again in 5 minutes');
  if (auth !== 'ok') return textError(403, 'invalid admin token');
  if (!SLUG_RE.test(slug)) return textError(400, 'invalid slug');
  const out = [];
  let cursor;
  for (let i = 0; i < 5; i++) { // 5 pages x 1000 is far more than one slug will ever have
    const listed = await env.NOTES_BUCKET.list({
      prefix: 'deleted/' + slug + '/', cursor, include: ['customMetadata']
    });
    for (const obj of listed.objects) {
      const m = obj.key.match(/\/(\d+)\.html$/);
      if (!m) continue;
      out.push({
        ts: parseInt(m[1], 10),
        source: (obj.customMetadata && obj.customMetadata.source) || 'unknown',
        size: obj.size
      });
    }
    if (!listed.truncated) break;
    cursor = listed.cursor;
  }
  out.sort((a, b) => b.ts - a.ts);
  return json({ snapshots: out });
}

// GET /admin/snapshot/:slug/:ts: returns one deleted/<slug>/<ts>.html copy as
// inert text/plain (never rendered by the browser on its own, locked-down CSP,
// admin token required). The admin page shows it inside a fully sandboxed
// iframe; see the View button in ADMIN_PAGE_HTML.
async function handleAdminSnapshotGet(env, request, slug, ts) {
  const auth = await adminAuthOk(env, request);
  if (auth === 'limited') return textError(429, 'too many failed attempts, try again in 5 minutes');
  if (auth !== 'ok') return textError(403, 'invalid admin token');
  if (!SLUG_RE.test(slug)) return textError(400, 'invalid slug');
  if (!/^\d{10,16}$/.test(ts)) return textError(400, 'invalid timestamp');
  const obj = await env.NOTES_BUCKET.get('deleted/' + slug + '/' + ts + '.html');
  if (!obj) return textError(404, 'snapshot not found');
  return new Response(obj.body, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Security-Policy': "default-src 'none'; sandbox",
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer'
    }
  });
}

async function handleAdminRestore(env, request, slug) {
  const auth = await adminAuthOk(env, request);
  if (auth === 'limited') return textError(429, 'too many failed attempts, try again in 5 minutes');
  if (auth !== 'ok') return textError(403, 'invalid admin token');
  if (!SLUG_RE.test(slug)) return textError(400, 'invalid slug');
  const meta = await getMeta(env, slug);
  if (!meta) return textError(404, 'not found');
  if (!meta.adminLocked || !meta.deletedAt) return textError(409, 'slug is not admin-taken-down');
  // The live object survives a takedown until the 30-day purge; if it is
  // already gone, fall back to the newest pre-takedown snapshot under deleted/.
  if (!(await env.NOTES_BUCKET.head(slug + '.html'))) {
    let best = null;
    const listed = await env.NOTES_BUCKET.list({ prefix: 'deleted/' + slug + '/' });
    for (const obj of listed.objects) {
      const m = obj.key.match(/\/(\d+)\.html$/);
      const ts = m ? parseInt(m[1], 10) : NaN;
      if (Number.isFinite(ts) && (!best || ts > best.ts)) best = { ts, key: obj.key };
    }
    if (!best) return textError(409, 'content no longer exists (past retention); cannot restore');
    const snap = await env.NOTES_BUCKET.get(best.key);
    if (!snap) return textError(409, 'snapshot missing; cannot restore');
    await env.NOTES_BUCKET.put(slug + '.html', snap.body, { httpMetadata: { contentType: 'text/html; charset=utf-8' } });
  }
  delete meta.deletedAt;
  delete meta.adminLocked;
  // Story rows, story images and likes were deleted at takedown and are not
  // recoverable, so the page comes back as a plain page, not a story.
  meta.showInStories = false;
  await putMeta(env, slug, meta);
  if (meta.ownerSub) {
    await env.SLUGS.put('owner:' + meta.ownerSub + ':' + slug, '1');
    await env.ADS_DB.prepare('INSERT OR REPLACE INTO published_notes (slug, author_sub, created_at) VALUES (?, ?, ?)')
      .bind(slug, meta.ownerSub, meta.createdAt || Date.now()).run();
  }
  return json({ ok: true });
}

// GET /admin/img?u=<https url>: admin-only image fetch-through. The admin page
// uses this so external images in a snapshot preview load from the worker, not
// from the admin's browser (hosts see Cloudflare, not the admin's IP). It is an
// outbound-request endpoint, so it is deliberately narrow: admin token required;
// https on port 443 only; hostnames only (no IP literals, localhost, or
// single-label/internal names); no credentials in the URL; redirects followed
// manually (max 3) with every hop re-validated; 8 s timeout; 5 MB cap; and only
// raster image content types come back (no SVG/HTML). No cookies or Referer are
// sent. The response is inert (nosniff, default-src 'none', no-store).
const ADMIN_IMG_MAX_BYTES = 5 * 1024 * 1024;
const ADMIN_IMG_TYPES = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/avif', 'image/bmp']);

function adminImgTargetOk(u) {
  if (u.protocol !== 'https:') return false;
  if (u.username || u.password) return false;
  if (u.port && u.port !== '443') return false;
  const h = u.hostname.toLowerCase().replace(/\.$/, '');
  if (!/^[a-z0-9.-]+$/.test(h)) return false;          // also rejects IPv6 literals
  if (!h.includes('.')) return false;                  // single-label / intranet names
  if (/^\d+(\.\d+){0,3}$/.test(h)) return false;       // IPv4 literals (incl. short forms)
  if (/^0x/i.test(h.split('.').pop())) return false;   // hex-form IPs
  if (h === 'localhost' || /\.(localhost|local|internal|lan|home|corp|intranet)$/.test(h)) return false;
  return true;
}

async function handleAdminImage(env, request, url) {
  const auth = await adminAuthOk(env, request);
  if (auth === 'limited') return textError(429, 'too many failed attempts, try again in 5 minutes');
  if (auth !== 'ok') return textError(403, 'invalid admin token');
  let cur;
  try { cur = new URL(url.searchParams.get('u') || ''); } catch (e) { return textError(400, 'invalid url'); }
  if (cur.href.length > 2048) return textError(400, 'url too long');
  let res = null;
  for (let hop = 0; hop < 4; hop++) {
    if (!adminImgTargetOk(cur)) return textError(400, 'url not allowed');
    try {
      res = await fetch(cur.href, {
        method: 'GET',
        redirect: 'manual',
        headers: { 'Accept': 'image/*', 'User-Agent': 'Mozilla/5.0 (compatible; NoteAdminPreview)' },
        signal: AbortSignal.timeout(8000)
      });
    } catch (e) { return textError(502, 'fetch failed'); }
    if (res.status >= 300 && res.status < 400 && res.headers.get('Location')) {
      try { cur = new URL(res.headers.get('Location'), cur); } catch (e) { return textError(502, 'bad redirect'); }
      try { await res.body?.cancel(); } catch (e) {}
      res = null;
      continue;
    }
    break;
  }
  if (!res) return textError(502, 'too many redirects');
  if (!res.ok) return textError(502, 'upstream ' + res.status);
  const type = (res.headers.get('Content-Type') || '').split(';')[0].trim().toLowerCase();
  if (!ADMIN_IMG_TYPES.has(type)) return textError(415, 'not a supported image type');
  const declared = parseInt(res.headers.get('Content-Length') || '0', 10) || 0;
  if (declared > ADMIN_IMG_MAX_BYTES) return textError(413, 'image too large');
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    let r;
    try { r = await reader.read(); } catch (e) { return textError(502, 'read failed'); }
    if (r.done) break;
    total += r.value.byteLength;
    if (total > ADMIN_IMG_MAX_BYTES) { try { await reader.cancel(); } catch (e) {} return textError(413, 'image too large'); }
    chunks.push(r.value);
  }
  return new Response(new Blob(chunks, { type }), {
    headers: {
      'Content-Type': type,
      'Content-Security-Policy': "default-src 'none'; sandbox",
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer'
    }
  });
}

function handleAdminPage() {
  return new Response(ADMIN_PAGE_HTML, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'",
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer'
    }
  });
}

const ADMIN_PAGE_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Reports</title><style>
body{font:15px/1.4 system-ui,sans-serif;margin:0;padding:14px;background:#111;color:#eee}
h1{font-size:18px;margin:0 0 12px}input,button{font:inherit;padding:10px 12px;border-radius:8px;border:1px solid #444;background:#222;color:#eee}
input{width:100%;box-sizing:border-box;margin-bottom:8px}button{cursor:pointer}
.card{border:1px solid #333;border-radius:10px;padding:12px;margin:10px 0;background:#1a1a1a}
.csam{border-color:#c33}.badge{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;background:#333;margin-left:6px}
.badge.c{background:#c33}.row{display:flex;gap:8px;margin-top:10px;flex-wrap:wrap}.danger{background:#a22;border-color:#a22}
.meta{color:#999;font-size:13px}.snap{font-size:13px;margin-top:8px;padding-top:8px;border-top:1px solid #333}.snap div{margin:4px 0}.snap .hit{color:#fc6}.snap code{color:#999}#imgs,#ext{width:auto;margin:0 6px 0 0;padding:0}.opt{display:block;margin:0 0 10px;color:#bbb;font-size:13px}.d{white-space:pre-wrap;word-break:break-word;margin:6px 0}#msg{margin:8px 0;color:#f88}
a{color:#8bf}</style></head><body><h1>Reports</h1>
<div id="login"><input id="tok" type="password" placeholder="Admin token" autocomplete="off"><button id="go">Load reports</button></div>
<label class="opt"><input type="checkbox" id="imgs">Load embedded (data:) images in snapshot previews. Off by default.</label>
<label class="opt"><input type="checkbox" id="ext">Also load external (https) images, fetched through the worker so the image hosts see the worker, not your IP. Off by default.</label>
<div id="msg"></div><div id="list"></div><button id="more" style="display:none">Load more</button>
<script>
var tok=sessionStorage.getItem('adm')||'',next=null,shown=0;
var $=function(i){return document.getElementById(i)};
function msg(t){$('msg').textContent=t||''}
function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e}
function load(reset){
  if(reset){$('list').textContent='';next=null;shown=0}
  fetch('/admin/reports'+(next?'?cursor='+encodeURIComponent(next):''),{headers:{'X-Admin-Token':tok}}).then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j}})}).then(function(o){
    if(!o.ok){msg(o.j.error||'failed');sessionStorage.removeItem('adm');$('login').style.display='';return}
    sessionStorage.setItem('adm',tok);$('login').style.display='none';
    o.j.reports.forEach(render);shown+=o.j.reports.length;next=o.j.nextCursor;
    $('more').style.display=next?'':'none';
    if(!o.j.reports.length&&next){load(false);return}
    msg(shown?shown+' report(s) shown'+(next?' so far':''):'No open reports')
  }).catch(function(){msg('network error')})
}
function render(r){
  var c=el('div','card'+(r.isCsam?' csam':''));
  var h=el('div',null,'/'+r.slug);var b=el('span','badge'+(r.isCsam?' c':''),r.reason);h.appendChild(b);h.appendChild(el('span','badge',r.status));c.appendChild(h);
  c.appendChild(el('div','meta',new Date(r.reportedAt).toLocaleString()));
  c.appendChild(el('div','d',r.details||'(no details)'));
  var row=el('div','row');var a=el('a',null,'View page');a.href='/@'+r.slug;a.target='_blank';a.rel='noopener';row.appendChild(a);
  if(r.status==='live'){row.appendChild(mkTake(r,c))}
  if(r.status==='taken down'){row.appendChild(mkRestore(r,c))}
  row.appendChild(mkSnaps(r,c));
  row.appendChild(mkDismiss(r,c));
  c.appendChild(row);$('list').appendChild(c)
}
function mkSnaps(r,card){var t=el('button',null,'Snapshots');var box=null;t.onclick=function(){
  if(box){box.remove();box=null;return}
  t.disabled=true;
  fetch('/admin/snapshots/'+encodeURIComponent(r.slug),{headers:{'X-Admin-Token':tok}}).then(function(x){return x.json().then(function(j){return{ok:x.ok,j:j}})}).then(function(o){
    t.disabled=false;
    if(!o.ok){msg(o.j.error||'snapshot list failed');return}
    box=el('div','snap');
    if(!o.j.snapshots.length)box.appendChild(el('div',null,'No snapshots for /'+r.slug));
    o.j.snapshots.forEach(function(s){
      var d=el('div',s.ts===r.reportedAt?'hit':null);
      d.appendChild(document.createTextNode(new Date(s.ts).toLocaleString()+' - '+s.source+(s.ts===r.reportedAt?' (this report)':'')+' '));
      d.appendChild(el('code',null,new Date(s.ts).toISOString()+' / '+s.ts+' / '+Math.round(s.size/1024)+' KB'));
      d.appendChild(document.createTextNode(' '));
      d.appendChild(mkView(r,s,d));
      box.appendChild(d)
    });
    card.appendChild(box)
  }).catch(function(){t.disabled=false;msg('network error')})
};return t}
function toDataUrl(b){return new Promise(function(res){var r=new FileReader();r.onload=function(){res(r.result)};r.onerror=function(){res(null)};r.readAsDataURL(b)})}
function buildDoc(t){
  var want=$('imgs').checked,ext=$('ext').checked;
  var head='<!doctype html><meta http-equiv=\"Content-Security-Policy\" content=\"img-src '+((want||ext)?'data:':\"'none'\")+'\">';
  if(!ext)return Promise.resolve(head+t);
  var d=new DOMParser().parseFromString(t,'text/html');
  var seen={},urls=[];
  [].slice.call(d.querySelectorAll('img')).forEach(function(im){
    var s=(im.getAttribute('src')||'').trim(),l=s.toLowerCase();
    im.removeAttribute('srcset');
    if(l.indexOf('https:')===0){im.removeAttribute('src');if(!seen[s]){seen[s]=[];urls.push(s)}seen[s].push(im)}
    else if(l.indexOf('data:')===0&&!want)im.removeAttribute('src')
  });
  urls=urls.slice(0,40);
  var i=0;
  function worker(){
    if(i>=urls.length)return Promise.resolve();
    var u=urls[i++];
    return fetch('/admin/img?u='+encodeURIComponent(u),{headers:{'X-Admin-Token':tok}}).then(function(x){return x.ok?x.blob():null}).then(function(b){return b?toDataUrl(b):null}).then(function(du){if(du)seen[u].forEach(function(im){im.setAttribute('src',du)})}).catch(function(){}).then(worker)
  }
  return Promise.all([worker(),worker(),worker(),worker()]).then(function(){return head+d.documentElement.outerHTML})
}
function setFrame(f,t){var g=f._g=(f._g||0)+1;f._t=t;buildDoc(t).then(function(doc){if(f._g===g)f.srcdoc=doc})}
function refreshFrames(){document.querySelectorAll('iframe').forEach(function(f){if(f._t!=null)setFrame(f,f._t)})}
function mkView(r,s,row){var b=el('button',null,'View');var fr=null;b.onclick=function(){
  if(fr){fr.remove();fr=null;b.textContent='View';return}
  if(r.isCsam&&!confirm('This snapshot is from a CSAM report. It opens as text and styling only unless an images checkbox is on. Continue?'))return;
  b.disabled=true;
  fetch('/admin/snapshot/'+encodeURIComponent(r.slug)+'/'+s.ts,{headers:{'X-Admin-Token':tok}}).then(function(x){return x.text().then(function(t){return{ok:x.ok,t:t}})}).then(function(o){
    b.disabled=false;
    if(!o.ok){msg('snapshot load failed');return}
    fr=document.createElement('iframe');fr.setAttribute('sandbox','');fr.referrerPolicy='no-referrer';
    fr.style.cssText='width:100%;height:60vh;margin-top:6px;border:1px solid #444;border-radius:8px;background:#fff';
    row.appendChild(fr);setFrame(fr,o.t);b.textContent='Hide'
  }).catch(function(){b.disabled=false;msg('network error')})
};return b}
$('imgs').onchange=function(){
  if(this.checked&&!confirm('Embedded images in snapshots (including ones from CSAM reports) will be displayed. Continue?')){this.checked=false;return}
  refreshFrames()
};
$('ext').onchange=function(){
  if(this.checked&&!confirm('External images will be fetched by the worker from whatever hosts the page points at. Those hosts see the worker (not your IP) and that a preview was opened, and content from CSAM reports may display. Continue?')){this.checked=false;return}
  refreshFrames()
};
function setStatus(card,t){card.querySelectorAll('.badge')[1].textContent=t}
function mkTake(r,card){var t=el('button','danger','Take down');t.onclick=function(){takedown(r,t,card)};return t}
function mkRestore(r,card){var t=el('button',null,'Restore');t.onclick=function(){restore(r,t,card)};return t}
function mkDismiss(r,card){var t=el('button',null,'Dismiss');t.onclick=function(){dismiss(r,t,card)};return t}
function dismiss(r,btn,card){
  var w=r.isCsam?'CSAM report: only dismiss once the page is handled and NCMEC has been notified. The record is hidden but kept for 18 months. Dismiss the report for /'+r.slug+'?':'Dismiss this report for /'+r.slug+'? It will be removed from the list.';
  if(!confirm(w))return;btn.disabled=true;
  fetch('/admin/dismiss',{method:'POST',headers:{'X-Admin-Token':tok,'Content-Type':'application/json'},body:JSON.stringify({key:r.key})}).then(function(x){
    if(x.ok){card.remove();shown--;msg(shown?shown+' report(s) shown':'No open reports')}else{btn.disabled=false;msg('dismiss failed: '+x.status)}
  }).catch(function(){btn.disabled=false;msg('network error')})
}
function restore(r,btn,card){
  var w=r.isCsam?'WARNING: this page was reported as CSAM. Restoring puts it back online. Only continue if you have confirmed the report was mistaken. Restore /'+r.slug+'?':'Restore /'+r.slug+'? It returns as a plain page (story status and likes are not recovered).';
  if(!confirm(w))return;btn.disabled=true;
  fetch('/admin/restore/'+encodeURIComponent(r.slug),{method:'POST',headers:{'X-Admin-Token':tok}}).then(function(x){return x.json().then(function(j){return{ok:x.ok,j:j}})}).then(function(o){
    if(o.ok){btn.replaceWith(mkTake(r,card));setStatus(card,'live');msg('')}else{btn.disabled=false;msg(o.j.error||'restore failed')}
  }).catch(function(){btn.disabled=false;msg('network error')})
}
function takedown(r,btn,card){
  var warn=r.isCsam?'CSAM report: the page is preserved under deleted/ for 18 months. You must still report to NCMEC. Take down /'+r.slug+'?':'Take down /'+r.slug+'? The slug will be permanently locked.';
  if(!confirm(warn))return;btn.disabled=true;
  fetch('/publish/'+encodeURIComponent(r.slug),{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({adminToken:tok})}).then(function(x){
    if(x.ok){btn.replaceWith(mkRestore(r,card));setStatus(card,'taken down')}else if(x.status===404){btn.remove();setStatus(card,'missing')}else{btn.disabled=false;msg('takedown failed: '+x.status)}
  }).catch(function(){btn.disabled=false;msg('network error')})
}
$('go').onclick=function(){tok=$('tok').value.trim();load(true)};
$('more').onclick=function(){load(false)};
if(tok)load(true)
</script></body></html>`;

/* ---------------- Router ---------------- */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const { pathname } = url;
    const method = request.method;

    if (method === 'OPTIONS') return new Response(null, { headers: corsHeaders() });

    try {
      if (method === 'GET' && pathname.startsWith('/check-slug/')) {
        return handleCheckSlug(env, decodeURIComponent(pathname.slice('/check-slug/'.length)));
      }
      if (method === 'GET' && pathname.startsWith('/meta/')) {
        return handleMeta(env, decodeURIComponent(pathname.slice('/meta/'.length)));
      }
      if (method === 'POST' && pathname === '/publish') {
        return handlePublish(env, request);
      }
      if (method === 'PUT' && pathname.startsWith('/publish/') && pathname.endsWith('/stories')
          && pathname.length > '/publish/'.length + '/stories'.length) {
        return handleSetStories(env, request, decodeURIComponent(pathname.slice('/publish/'.length, -'/stories'.length)));
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
        return handleReport(env, request, decodeURIComponent(pathname.slice('/report/'.length)), ctx);
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
      if (method === 'POST' && pathname === '/sync/images/missing') {
        return handleSyncImagesMissing(env, request);
      }
      if (method === 'PUT' && pathname.startsWith('/sync/images/')) {
        return handleSyncImagePut(env, request, decodeURIComponent(pathname.slice('/sync/images/'.length)));
      }
      if (method === 'GET' && pathname.startsWith('/sync/images/')) {
        return handleSyncImageGet(env, request, decodeURIComponent(pathname.slice('/sync/images/'.length)));
      }
      if (method === 'GET' && pathname === '/my/pages') {
        return handleMyPages(env, request);
      }
      if (method === 'POST' && pathname === '/account/profile-name') {
        return handleSetProfileName(env, request);
      }
      if (method === 'GET' && pathname === '/account/profile-name') {
        return handleGetProfileName(env, request);
      }
      if (method === 'POST' && pathname === '/account/profile-image') {
        return handleSetProfileImage(env, request);
      }
      if (method === 'GET' && pathname.startsWith('/account/profile-image/')) {
        return handleServeProfileImage(env, decodeURIComponent(pathname.slice('/account/profile-image/'.length)), request);
      }
      if (method === 'GET' && pathname === '/stories') {
        return handleStoriesStrip(env, request);
      }
      if (method === 'GET' && pathname.startsWith('/stories/image/')) {
        return handleServeStoryImage(env, decodeURIComponent(pathname.slice('/stories/image/'.length)));
      }
      if (method === 'GET' && pathname.startsWith('/stories/card-image/')) {
        const rest = pathname.slice('/stories/card-image/'.length).split('/');
        return handleServeStoryCardImage(env, decodeURIComponent(rest[0] || ''), rest[1] || '');
      }
      if (method === 'POST' && pathname.startsWith('/stories/') && pathname.endsWith('/seen')) {
        return handleMarkStorySeen(env, request, decodeURIComponent(pathname.slice('/stories/'.length, -'/seen'.length)));
      }
      if (method === 'GET' && pathname === '/account/subscriber-count') {
        return handleSubscriberCount(env, request);
      }
      if (method === 'GET' && pathname === '/subscriptions') {
        return handleGetSubscriptions(env, request);
      }
      if (method === 'GET' && pathname === '/subscriptions/feed') {
        return handleSubscriptionsFeed(env, request);
      }
      if (method === 'GET' && pathname === '/account/stories') {
        return handleMyStories(env, request);
      }
      if (method === 'GET' && pathname === '/account/published-notes') {
        return handlePublishedNotes(env, request);
      }
      if (method === 'GET' && pathname === '/account/liked-notes') {
        return handleLikedNotes(env, request);
      }
      if (method === 'POST' && pathname === '/likes/counts') {
        return handleLikeCounts(env, request);
      }
      if (method === 'GET' && pathname === '/likes') {
        return handleLikesList(env, request);
      }
      if (method === 'GET' && pathname.startsWith('/likes/')) {
        return handleLikeState(env, request, decodeURIComponent(pathname.slice('/likes/'.length)));
      }
      if (method === 'POST' && pathname.startsWith('/likes/')) {
        return handleLike(env, request, decodeURIComponent(pathname.slice('/likes/'.length)));
      }
      if (method === 'DELETE' && pathname.startsWith('/likes/')) {
        return handleUnlike(env, request, decodeURIComponent(pathname.slice('/likes/'.length)));
      }
      if (method === 'POST' && pathname.startsWith('/subscriptions/')) {
        return handleSubscribe(env, request, decodeURIComponent(pathname.slice('/subscriptions/'.length)));
      }
      if (method === 'DELETE' && pathname.startsWith('/subscriptions/')) {
        return handleUnsubscribe(env, request, decodeURIComponent(pathname.slice('/subscriptions/'.length)));
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
      // below). POST with the admin token in the X-Admin-Token header, like
      // the other admin endpoints — it used to be a GET taking the token as
      // a query param, which left the token in browser history and logs.
      //   curl -X POST -H "X-Admin-Token: $TOKEN" https://<worker>/admin/purge
      if (method === 'POST' && pathname === '/admin/purge') {
        const auth = await adminAuthOk(env, request);
        if (auth === 'limited') return textError(429, 'too many failed attempts, try again in 5 minutes');
        if (auth !== 'ok') return textError(403, 'invalid admin token');
        const purged = await handlePurge(env);
        return json({ ok: true, purged });
      }
      if (method === 'GET' && pathname === '/admin') return handleAdminPage();
      if (method === 'GET' && pathname === '/admin/reports') return handleAdminReports(env, request, url);
      if (method === 'GET' && pathname === '/admin/img') return handleAdminImage(env, request, url);
      if (method === 'POST' && pathname === '/admin/dismiss') return handleAdminDismiss(env, request);
      if (method === 'GET' && pathname.startsWith('/admin/snapshot/')) {
        const rest = pathname.slice('/admin/snapshot/'.length).split('/');
        if (rest.length !== 2) return textError(400, 'invalid path');
        return handleAdminSnapshotGet(env, request, decodeURIComponent(rest[0]), rest[1]);
      }
      if (method === 'GET' && pathname.startsWith('/admin/snapshots/')) {
        return handleAdminSnapshots(env, request, decodeURIComponent(pathname.slice('/admin/snapshots/'.length)));
      }
      if (method === 'POST' && pathname.startsWith('/admin/restore/')) {
        return handleAdminRestore(env, request, decodeURIComponent(pathname.slice('/admin/restore/'.length)));
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
