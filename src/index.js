/**
 * Publish-to-Web backend for Note Builder: publishing, Google sign-in,
 * account sync, stories, likes, ads and the admin page.
 *
 * Bindings:
 *   NOTES_BUCKET (R2)  - "<slug>.html", "sync/<sub>/notes.json", sync images,
 *                        "story-images/<slug>", "profile-images/<sub>"
 *   SLUGS (KV)         - JSON metadata per slug, plus "owner:<sub>:<slug>" index keys
 *   REPORTS (KV)       - report records
 *   ACCOUNTS (KV)      - "user:<sub>" records and "session:<hash>" tokens
 *   ADS_DB (D1)        - ads, ad_viewers, stories, subscriptions, story_seen, likes,
 *                        published_notes (indexed mirror of the owner keys, for
 *                        keyset pagination) and alerts (created by ensureAlerts).
 *                        Page HTML, slugs and tokens stay in SLUGS/NOTES_BUCKET;
 *                        D1 only indexes what needs joins. Schema in migrations/.
 *
 * Secrets:
 *   REPORT_WEBHOOK_URL (optional)  - receives report JSON for alerting
 *   GOOGLE_CLIENT_IDS              - comma-separated client IDs accepted as idToken audience
 *   REVENUECAT_WEBHOOK_SECRET      - must match the webhook's Authorization header value;
 *                                    unset, the webhook refuses everything (fail closed)
 *
 * Rate limiting: POST /publish and PUT /publish/:slug are limited by a Cloudflare
 * dashboard rule, plus an in-code per-IP backstop (checkPublishRateLimit) in case the
 * rule is missing or misconfigured. GET /@:slug, /check-slug/:slug and /meta/:slug are
 * intentionally open (read-only, cheap).
 */

const MAX_HTML_BYTES = 2 * 1024 * 1024; // 2MB per published page, tune as needed
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
  'auth', 'sync', 'my', 'presence'
]);
const SOFT_DELETE_RETENTION_MS = 30 * 24 * 60 * 60 * 1000; // soft-deleted pages are kept 30 days before purge
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

/* ---------------- Presence (online / guest counts for the admin Overview) ---------------- */
// Best-effort, reporting-only. Signed-in accounts are touched from requireSessionInfo (any authed
// call, at most once every PRESENCE_TOUCH_MIN_MS per isolate). Guests have no account, so they only appear once the
// app POSTs /presence {deviceId} (same per-device id it already sends as viewerId). The table is
// created lazily; equivalent SQL:
//   CREATE TABLE presence (id TEXT PRIMARY KEY, kind TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL);
//   CREATE INDEX presence_kind_seen ON presence (kind, last_seen);
// id is 'u:<sub>' for accounts and 'g:<deviceId>' for guests. Nothing here can fail a request.
const ONLINE_WINDOW_MS = 5 * 60 * 1000;
const PRESENCE_TOUCH_MIN_MS = 3 * 60 * 1000; // must stay well under ONLINE_WINDOW_MS
const PRESENCE_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;
let presenceReady = null;
const presenceLast = new Map();
function ensurePresence(env) {
  if (!presenceReady) {
    presenceReady = env.ADS_DB.batch([
      env.ADS_DB.prepare('CREATE TABLE IF NOT EXISTS presence (id TEXT PRIMARY KEY, kind TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL)'),
      env.ADS_DB.prepare('CREATE INDEX IF NOT EXISTS presence_kind_seen ON presence (kind, last_seen)')
    ]).catch((e) => { presenceReady = null; throw e; });
  }
  return presenceReady;
}
async function touchPresence(env, kind, key) {
  try {
    const id = (kind === 'u' ? 'u:' : 'g:') + key;
    const now = Date.now();
    if (now - (presenceLast.get(id) || 0) < PRESENCE_TOUCH_MIN_MS) return;
    if (presenceLast.size > 5000) presenceLast.clear();
    presenceLast.set(id, now);
    await ensurePresence(env);
    await env.ADS_DB.prepare(
      'INSERT INTO presence (id, kind, first_seen, last_seen) VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET last_seen = excluded.last_seen'
    ).bind(id, kind, now, now).run();
    await recordActivityDay(env, id, now);
  } catch (e) { /* reporting-only; swallow */ }
}
async function prunePresence(env) {
  try {
    await ensurePresence(env);
    const r = await env.ADS_DB.prepare('DELETE FROM presence WHERE last_seen < ?').bind(Date.now() - PRESENCE_RETENTION_MS).run();
    return ((r && r.meta && r.meta.changes) || 0);
  } catch (e) { /* reporting-only; swallow */ }
  return 0;
}
// Daily-active ledger for the admin trend charts. One row per (UTC day, id) the first time an id is
// seen that day in an isolate, so distinct counts over any day/week/month/year range are exact from
// the day this shipped (older activity can't be reconstructed: presence only keeps last_seen).
//   CREATE TABLE activity_daily (day INTEGER NOT NULL, id TEXT NOT NULL, PRIMARY KEY (day, id)) WITHOUT ROWID;
// id is 'u:<sub>' for accounts and 'g:<deviceId>' for guests, same as presence.
const ACTIVITY_RETENTION_DAYS = 800;
let activityReady = null;
const activityLastDay = new Map();
function ensureActivity(env) {
  if (!activityReady) {
    activityReady = env.ADS_DB.batch([
      env.ADS_DB.prepare('CREATE TABLE IF NOT EXISTS activity_daily (day INTEGER NOT NULL, id TEXT NOT NULL, PRIMARY KEY (day, id)) WITHOUT ROWID')
    ]).catch((e) => { activityReady = null; throw e; });
  }
  return activityReady;
}
async function recordActivityDay(env, id, now) {
  const day = Math.floor(now / 86400000);
  if (activityLastDay.get(id) === day) return;
  await ensureActivity(env);
  await env.ADS_DB.prepare('INSERT OR IGNORE INTO activity_daily (day, id) VALUES (?, ?)').bind(day, id).run();
  if (activityLastDay.size > 5000) activityLastDay.clear();
  activityLastDay.set(id, day);
}
// Dismissed CSAM report records expire from KV 18 months after dismissal, but their report_index copy
// (slug, reason, times; no details) is otherwise only removed when the admin list happens to load it.
// This sweeps those rows on the same 18-month clock so they can't outlive the record they mirror.
async function pruneReportIndex(env) {
  try {
    await ensureReportIndex(env);
    const r = await env.ADS_DB.prepare('DELETE FROM report_index WHERE is_csam = 1 AND dismissed_at IS NOT NULL AND dismissed_at < ?').bind(Date.now() - CSAM_RETENTION_MS).run();
    return ((r && r.meta && r.meta.changes) || 0);
  } catch (e) { /* reporting-only; swallow */ }
  return 0;
}
async function pruneActivity(env) {
  try {
    await ensureActivity(env);
    const r = await env.ADS_DB.prepare('DELETE FROM activity_daily WHERE day < ?').bind(Math.floor(Date.now() / 86400000) - ACTIVITY_RETENTION_DAYS).run();
    return ((r && r.meta && r.meta.changes) || 0);
  } catch (e) { /* reporting-only; swallow */ }
  return 0;
}

// The four reporting/retention prunes, shared by the nightly cron and the admin purge button.
// Returns the total rows deleted.
async function pruneAll(env) {
  const n = await Promise.all([prunePresence(env), pruneAlerts(env), pruneActivity(env), pruneReportIndex(env)]);
  return n.reduce((a, b) => a + b, 0);
}

function presenceDeviceId(body) {
  return typeof body?.deviceId === 'string' ? body.deviceId.trim().slice(0, MAX_VIEWER_ID_LEN) : '';
}
// Flip a device between guest and signed-in the moment it signs in or out, rather than waiting for the
// next /presence beacon (app restart). Signing out takes the account out of "online" right away (it
// still counts as active in the 24h/7d windows) and makes the device a guest; signing in does the reverse.
async function presenceSwitch(env, deviceId, sub, signedIn) {
  try {
    await ensurePresence(env);
    if (signedIn) {
      if (sub) { presenceLast.delete('u:' + sub); await touchPresence(env, 'u', sub); }
      if (deviceId) {
        presenceLast.delete('g:' + deviceId);
        await env.ADS_DB.prepare('DELETE FROM presence WHERE id = ?').bind('g:' + deviceId).run();
      }
    } else {
      if (sub) {
        presenceLast.delete('u:' + sub);
        await env.ADS_DB.prepare('UPDATE presence SET last_seen = MIN(last_seen, ?) WHERE id = ?')
          .bind(Date.now() - ONLINE_WINDOW_MS - 1, 'u:' + sub).run();
      }
      if (deviceId) { presenceLast.delete('g:' + deviceId); await touchPresence(env, 'g', deviceId); }
    }
  } catch (e) { /* reporting-only; swallow */ }
}
// POST /presence {deviceId}: the app's "I'm open" beacon. A valid session marks the account
// online (via requireSession); otherwise the device counts as a guest. A device that has since
// signed in stops counting as a guest.
async function handlePresence(env, request) {
  let body;
  try { body = await request.json(); } catch (e) { body = {}; }
  const deviceId = presenceDeviceId(body);
  const sub = await requireSession(env, request);
  if (!deviceId) return json({ ok: true });
  if (!sub) await touchPresence(env, 'g', deviceId);
  else await presenceSwitch(env, deviceId, sub, true);
  return json({ ok: true });
}

const PROFILE_NAME_MAX = 30;

// Cosmetic-only display name set from the Log Out
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
// cosmetic display name. This is what lets a second device, or a
// reinstall, pick up a name set elsewhere instead of showing blank.
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
    if (user && (user.pendingDeletionAt || user.suspended)) {
      await env.ACCOUNTS.delete('session:' + tokenHash);
      return null;
    }
  }
  await touchPresence(env, 'u', session.sub);
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
  if (user && user.suspended) return textError(403, 'this account is suspended');
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
  await presenceSwitch(env, presenceDeviceId(body), identity.sub, true);
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
  let sub = null;
  if (typeof token === 'string' && token) {
    const tokenHash = await sha256Hex(token);
    try {
      const raw = await env.ACCOUNTS.get('session:' + tokenHash);
      const sess = raw ? JSON.parse(raw) : null;
      if (sess && sess.sub) { sub = sess.sub; await env.ACCOUNTS.delete('usess:' + sess.sub + ':' + tokenHash); }
    } catch (e) { /* index entry just expires on its own */ }
    await env.ACCOUNTS.delete('session:' + tokenHash);
  }
  await presenceSwitch(env, presenceDeviceId(body), sub, false);
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
  if (listing.objects.length >= MAX_SYNC_IMAGES_PER_ACCOUNT) return json({ error: 'too many backed-up images', limit: MAX_SYNC_IMAGES_PER_ACCOUNT }, 413);
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

async function handleCheckSlug(env, slug, request) {
  if (!validSlug(slug)) return json({ available: false, reason: 'invalid-format' });
  const meta = await getMeta(env, slug);
  // A signed-in owner asking about their OWN live slug: still taken (nothing is ever overwritten), but
  // offer the next free numbered address (my-note-2, -3, ...) so both pages can live side by side.
  if (request && meta && !meta.deletedAt && !meta.adminLocked && meta.ownerSub) {
    const me = await requireSession(env, request);
    if (me && me === meta.ownerSub) {
      for (let n = 2; n <= 20; n++) {
        const suffix = '-' + n;
        const cand = slug.slice(0, 48 - suffix.length).replace(/-+$/, '') + suffix;
        if (!validSlug(cand)) continue;
        const m = await getMeta(env, cand);
        if (!m || (m.deletedAt && !m.adminLocked)) return json({ available: false, yours: true, suggest: cand });
      }
      return json({ available: false, yours: true });
    }
  }
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

// A page published while signed out has no owner, so stories, /my/pages and the page count all
// ignore it. When its holder later signs in and acts on it with the publish token (already
// verified by the caller), the account adopts it: same writes a signed-in publish makes. Returns
// the owner sub, 'cap' if the account is full, or null if there's no valid session. Only ever
// called for an unowned page.
async function adoptAnonymousPage(env, request, slug, meta) {
  const sub = await requireSession(env, request);
  if (!sub) return null;
  if (await ownerAtPageCap(env, sub)) return 'cap';
  meta.ownerSub = sub;
  await env.SLUGS.put('owner:' + sub + ':' + slug, '1');
  await env.ADS_DB.prepare('INSERT OR REPLACE INTO published_notes (slug, author_sub, created_at) VALUES (?, ?, ?)')
    .bind(slug, sub, meta.createdAt || Date.now()).run();
  return sub;
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

// A story is only live in the strip/Stories tab for STORIES_LOOKBACK_MS after it's posted. Once that
// has elapsed the page's showInStories flag is stale, so it counts as OFF (the stories row itself stays
// so followers' Subscribed feed keeps it for its own longer window). Turning it on again then starts a
// fresh cycle, because the toggle sees was=false.
async function storyCycleEnded(env, slug, meta) {
  if (!meta || !meta.showInStories) return false;
  const row = await env.ADS_DB.prepare('SELECT created_at FROM stories WHERE slug = ?').bind(slug).first();
  return !row || row.created_at < Date.now() - STORIES_LOOKBACK_MS;
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
  if (await storyCycleEnded(env, slug, meta)) meta.showInStories = false;

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

  // A page published signed out is adopted by the signed-in account saving it (best-effort: a
  // full account just leaves it unowned). showInStories is then only togglable for an owned
  // page, so for a still-anonymous publish the toggle is a no-op regardless of what's sent.
  if (!meta.ownerSub) await adoptAnonymousPage(env, request, slug, meta);
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
// POST /publish/:slug/relink — a signed-in OWNER re-attaches to their own live page. The app keeps the
// page's private token on the device and in the account backup; if neither has it (the note was
// published but its published state never made it into a backup before the data was cleared) the page
// stays online with no way to edit it. The account itself proves ownership, so this issues a fresh
// token (replacing the stored hash) and the app links it back to the matching note. Never touches the page.
async function handleRelink(env, request, slug) {
  if (!(await checkPublishRateLimit(env, request))) return textError(429, 'too many publishes, slow down');
  if (!validSlug(slug)) return textError(400, 'invalid slug');
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  const meta = await getMeta(env, slug);
  if (!meta || meta.deletedAt || meta.adminLocked) return textError(404, 'not found');
  if (!meta.ownerSub || meta.ownerSub !== sub) return textError(403, 'not your page');
  const token = newToken();
  meta.tokenHash = await sha256Hex(token);
  if (await storyCycleEnded(env, slug, meta)) meta.showInStories = false;
  await putMeta(env, slug, meta);
  return json({ slug, token, title: meta.title || null, createdAt: meta.createdAt, updatedAt: meta.updatedAt, showInStories: !!meta.showInStories });
}

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
  // Stories are per-account. A page published signed out is adopted by the signed-in account
  // presenting its token; with no session there's still no account to attribute a story row to.
  if (!meta.ownerSub) {
    const adopted = await adoptAnonymousPage(env, request, slug, meta);
    if (adopted === 'cap') return textError(403, `page limit reached (max ${MAX_PAGES_PER_ACCOUNT} live pages per account). Unpublish something first`);
    if (!adopted) return textError(403, 'sign-in required to show a note in stories');
  }

  if (await storyCycleEnded(env, slug, meta)) meta.showInStories = false;
  const was = !!meta.showInStories;
  const wants = showInStories;
  if (wants && meta.storyBlocked) return textError(403, 'stories are disabled for this page');
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
  const { token, adminToken, release } = body || {};
  const meta = await getMeta(env, slug);
  if (!meta || meta.deletedAt) return textError(404, 'not found');

  // Admin bypass: non-cooperative takedowns (DMCA, abuse,
  // CSAM) don't have the owner's token, so ADMIN_TOKEN lets a force-unpublish
  // through instead. Checked before the owner-token path so an admin never
  // needs a slug's token at all.
  let isAdminTakedown = false;
  // Admin release: same unpublish, but the slug is NOT locked, so it can be
  // published again right away (for owners who lost their token). Admin token
  // required; only honoured alongside a valid adminToken.
  let isAdminRelease = false;
  if (typeof adminToken === 'string' && adminToken && env.ADMIN_TOKEN) {
    const auth = await adminAuthOk(env, request, adminToken);
    if (auth === 'limited') return textError(429, 'too many failed attempts, try again in 5 minutes');
    if (auth !== 'ok') return textError(403, 'invalid admin token');
    if (release === true) isAdminRelease = true; else isAdminTakedown = true;
    if (isAdminTakedown && !adminReasonOf(body)) return textError(400, 'reason required');
  } else {
    if (typeof token !== 'string' || !token) return textError(401, 'missing token');
    const tokenHash = await sha256Hex(token);
    if (!timingSafeEqual(tokenHash, meta.tokenHash)) return textError(403, 'invalid token');
  }

  // Snapshot the live content to its own retained key *before* unlinking.
  // Soft-delete alone isn't enough to guarantee the 30-day retention window
  // for unpublished pages: the slug becomes reclaimable immediately, and a
  // republish under the same slug would overwrite "<slug>.html" — destroying exactly
  // the content a pending report/takedown investigation might need, before
  // the retention window is up. The snapshot is independent of whatever
  // happens to the live slug afterward; handlePurge() below deletes it once
  // it's past SOFT_DELETE_RETENTION_MS.
  const now = Date.now();
  const liveObj = await env.NOTES_BUCKET.get(slug + '.html');
  if (liveObj) {
    await env.NOTES_BUCKET.put(`deleted/${slug}/${now}.html`, liveObj.body, {
      httpMetadata: { contentType: 'text/html; charset=utf-8' },
      customMetadata: { source: isAdminTakedown ? 'takedown' : isAdminRelease ? 'release' : 'unpublish' }
    });
  }

  // Soft-delete: unlink immediately (slug 404s). A normal owner
  // unpublish also frees the slug for immediate reclaim by design. An admin-
  // forced takedown does not: adminLocked stays true permanently, so the
  // exact same slug can't just be republished right back by whoever it was
  // taken down from (see handleCheckSlug/handlePublish) — someone here has
  // to consciously clear it (e.g. a manual KV edit) once a takedown is
  // resolved, rather than it silently reopening.
  meta.deletedAt = now;
  if (isAdminTakedown) meta.adminLocked = true;
  await putMeta(env, slug, meta);
  if (isAdminTakedown || isAdminRelease) await audit(env, isAdminRelease ? 'release' : 'takedown', slug);
  if (isAdminTakedown) await createAlert(env, meta.ownerSub, 'takedown', 'Your note ' + alertNoteName(meta, slug) + ' was taken down. ' + alertReason(adminReasonOf(body)) + ' Its address can\u2019t be reused. ' + ALERT_REPEAT_NOTE);
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
  // Slugs whose story is still inside its live window; null if the lookup fails (then nothing is changed).
  let liveStories = null;
  try {
    const { results } = await env.ADS_DB.prepare('SELECT slug FROM stories WHERE author_sub = ? AND created_at >= ?')
      .bind(sub, Date.now() - STORIES_LOOKBACK_MS).all();
    liveStories = new Set(results.map(r => r.slug));
  } catch (e) { /* leave flags as they are */ }
  let cursor;
  do {
    const page = await env.SLUGS.list({ prefix, cursor });
    for (const key of page.keys) {
      const slug = key.name.slice(prefix.length);
      const meta = await getMeta(env, slug);
      if (!meta || meta.deletedAt) continue; // stale index entry (e.g. a purge raced this) — skip rather than list a dead page
      if (meta.showInStories && liveStories && !liveStories.has(slug)) { meta.showInStories = false; await putMeta(env, slug, meta); }
      pages.push({ slug, createdAt: meta.createdAt, updatedAt: meta.updatedAt, sizeBytes: meta.sizeBytes, showInStories: !!meta.showInStories, title: meta.title || null, noteCreatedAt: meta.noteCreatedAt ?? null });
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
// client-side. The image is stored in R2 (see storeStoryImage).
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
// D1, which would bloat row size and every /stories response. Returns the value to store in the
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
// (ring state is server-synced, not per-device local state).
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

  // Security hardening: this page is now attacker-reachable at a
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

// Best-effort rate limit for POST /report/:slug. Cloudflare dashboard rate-limit
// rules only cover /publish and /publish/*, and even those require a Cloudflare
// zone/domain, which a bare *.workers.dev deployment doesn't have.
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
    const summary = `Bluebook: new report for /${record.slug}${record.isCsam ? ' — CSAM' : ''}\n`
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
  // CSAM is split into its own category deliberately: it is
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
  const reportedMeta = await getMeta(env, slug);
  if (!reportedMeta) return textError(404, 'page not found');

  const record = { slug, reason, details, isCsam, reportedAt: Date.now() };
  const reportKey = makeReportKey(slug, record.reportedAt);
  await env.REPORTS.put(reportKey, JSON.stringify(record));
  await mirrorReport(env, reportKey, record);
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

  // Tell the page's owner (anonymous pages have no account to tell).
  await createAlert(env, reportedMeta.ownerSub, 'report', reportAlertText(reportedMeta, slug, reason), { ref: slug + ':' + reason, dedupeMs: ALERT_REPORT_DEDUPE_MS });

  if (env.REPORT_WEBHOOK_URL) {
    // Off the reporter's critical path: the response doesn't wait on Slack.
    const task = sendReportAlert(env, request, record);
    if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(task); else await task;
  }
  return json({ ok: true });
}

// Purge job: deletes R2 blobs (and their KV metadata) for
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
  // 30-day grace period has elapsed without the owner signing back in.
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
// elapses. Every session on the account is revoked right away, so each
// signed-in device is signed out the next time it contacts the server.
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
  await env.ACCOUNTS.delete(ALERTS_SEEN_PREFIX + sub);
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
  await ensurePresence(env); // the batch below deletes from presence, so the table must exist
  await env.ADS_DB.batch([
    env.ADS_DB.prepare('DELETE FROM presence WHERE id = ?').bind('u:' + sub),
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
  await ensureAlerts(env);
  await env.ADS_DB.prepare('DELETE FROM alerts WHERE sub = ?').bind(sub).run();
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

// product_id (as configured in Play Console/RevenueCat) -> views granted. Add a row here for every view-package
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
  // as RevenueCat's own anonymous ID.
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

/* ---------------- Alerts ---------------- */
// Automatic, read-only notices shown to the account under Library > Alerts (reports against their
// notes, a profile picture or name removed, takedowns, story/ad actions, suspension changes). Nothing
// here is written by hand: every message is built at the event that causes it. D1 table `alerts`
// (created on first use, like report_index). The person can delete an alert from their own list,
// which only sets dismissed_at; the row stays so the admin page can still show what was sent.
const ALERTS_PAGE = 30;
const ALERT_MAX_LEN = 600;
const ALERT_RETENTION_MS = 365 * 24 * 60 * 60 * 1000;
const ALERT_REPORT_DEDUPE_MS = 24 * 60 * 60 * 1000; // same note + same reason: one alert a day, so a pile of reports can't flood the list
const ALERT_SUSPENSION_NOTE = 'Multiple reports can lead to your account being suspended.';
const ALERT_REPEAT_NOTE = 'Repeated violations can lead to your account being suspended.';
// A "strike" is an enforcement notice sent to an account: takedown, story removal, profile picture or
// name removal, suspension, and an ad being paused or taken down. Reports alone are not strikes, and
// neither are lifts/resumes/refunds. Derived from the alerts table so it also covers past alerts.
const STRIKE_SQL = "kind IN ('takedown','story','profile_picture','profile_name','suspended') OR (kind = 'ad' AND (message LIKE '%was paused%' OR message LIKE '%was taken down%'))";
const STRIKE_KINDS = new Set(['takedown', 'story', 'profile_picture', 'profile_name', 'suspended']);
function isStrikeAlert(kind, message) {
  if (STRIKE_KINDS.has(kind)) return true;
  return kind === 'ad' && /was paused|was taken down/.test(String(message || ''));
}
let alertsReady = null;
function ensureAlerts(env) {
  if (!alertsReady) {
    alertsReady = env.ADS_DB.batch([
      env.ADS_DB.prepare('CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, sub TEXT NOT NULL, kind TEXT NOT NULL, message TEXT NOT NULL, ref TEXT, created_at INTEGER NOT NULL, dismissed_at INTEGER)'),
      env.ADS_DB.prepare('CREATE INDEX IF NOT EXISTS alerts_sub_time ON alerts (sub, dismissed_at, created_at, id)')
    ]).catch((e) => { alertsReady = null; throw e; });
  }
  return alertsReady;
}
// Best-effort: an alert failing to save must never fail the action that caused it.
async function createAlert(env, sub, kind, message, opts) {
  if (!sub) return;
  try {
    await ensureAlerts(env);
    const now = Date.now();
    const ref = (opts && opts.ref) || null;
    if (ref && opts.dedupeMs) {
      const dup = await env.ADS_DB.prepare('SELECT 1 AS x FROM alerts WHERE sub = ? AND kind = ? AND ref = ? AND created_at > ? LIMIT 1')
        .bind(sub, kind, ref, now - opts.dedupeMs).first();
      if (dup) return;
    }
    await env.ADS_DB.prepare('INSERT INTO alerts (id, sub, kind, message, ref, created_at) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(crypto.randomUUID(), sub, kind, String(message).slice(0, ALERT_MAX_LEN), ref, now).run();
  } catch (e) { console.log('alert failed: ' + (e && e.message)); }
}
function alertNoteName(meta, slug) {
  const t = meta && typeof meta.title === 'string' ? meta.title.trim().slice(0, 40) : '';
  return t ? '\u201c' + t + '\u201d' : '/' + slug;
}
// Every alert states what happened and why: "<Action>. Reason: <reason>." For reports the reason is the
// reporter's category (their free-text details are never passed on); for admin actions it's what the
// admin typed, which the admin endpoints require.
const ALERT_REPORT_REASONS = { spam: 'Spam', copyright: 'Copyright', abuse: 'Abuse', csam: 'Child safety concerns', other: 'Other' };
function alertReason(text) { return 'Reason: ' + String(text).trim().replace(/[.\s]+$/, '') + '.'; }
function adminReasonOf(body) { return typeof (body && body.reason) === 'string' ? body.reason.trim().slice(0, 200) : ''; }
function reportAlertText(meta, slug, reason) {
  return 'Your note ' + alertNoteName(meta, slug) + ' was reported. ' + alertReason(ALERT_REPORT_REASONS[reason] || 'Other') + ' ' + ALERT_SUSPENSION_NOTE;
}
async function pruneAlerts(env) {
  try {
    await ensureAlerts(env);
    const r = await env.ADS_DB.prepare('DELETE FROM alerts WHERE created_at < ?').bind(Date.now() - ALERT_RETENTION_MS).run();
    return ((r && r.meta && r.meta.changes) || 0);
  } catch (e) { console.log('alert prune failed: ' + (e && e.message)); }
  return 0;
}

// GET /alerts?cursor=: the signed-in account's own alerts, newest first, keyset-paginated; total on the first page.
async function handleAlertsList(env, request, url) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  await ensureAlerts(env);
  const cur = parseAdminCursor(url.searchParams.get('cursor'));
  const stmts = [
    env.ADS_DB.prepare('SELECT id, kind, message, created_at FROM alerts WHERE sub = ? AND dismissed_at IS NULL' + (cur ? ' AND (created_at, id) < (?, ?)' : '') + ' ORDER BY created_at DESC, id DESC LIMIT ?')
      .bind(sub, ...(cur ? [cur.key, cur.id] : []), ALERTS_PAGE + 1)
  ];
  if (!cur) stmts.unshift(env.ADS_DB.prepare('SELECT COUNT(*) AS t FROM alerts WHERE sub = ? AND dismissed_at IS NULL').bind(sub));
  const res = await env.ADS_DB.batch(stmts);
  const rows = res[res.length - 1].results || [];
  const more = rows.length > ALERTS_PAGE;
  if (more) rows.pop();
  const last = rows[rows.length - 1];
  return json({
    alerts: rows.map(r => ({ id: r.id, kind: r.kind, message: r.message, createdAt: r.created_at })),
    total: cur ? null : res[0].results[0].t,
    nextCursor: more && last ? last.created_at + '|' + last.id : null
  });
}
// GET /alerts/unread: how many of the account's alerts arrived since it last opened Alerts (drives the pill's badge), plus the
// total still on the list (the app only shows the Alerts pill while there is at least one).
// POST /alerts/seen: marks alerts up to {upTo} (or now) as seen. The marker is one KV key per account.
const ALERTS_SEEN_PREFIX = 'alertsseen:';
async function handleAlertsUnread(env, request) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  await ensureAlerts(env);
  const seen = parseInt((await env.ACCOUNTS.get(ALERTS_SEEN_PREFIX + sub)) || '0', 10) || 0;
  const row = await env.ADS_DB.prepare('SELECT COUNT(*) AS t, COALESCE(SUM(CASE WHEN created_at > ? THEN 1 ELSE 0 END), 0) AS n FROM alerts WHERE sub = ? AND dismissed_at IS NULL').bind(seen, sub).first();
  return json({ count: row ? row.n : 0, total: row ? row.t : 0 });
}
async function handleAlertsSeen(env, request) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  // Body {upTo}: the newest alert (created_at, ms) the app actually showed. The marker only moves forward and never
  // past now, so an alert that arrived after the list was fetched stays unread. No body (older app): mark up to now.
  let upTo = 0;
  try { const b = await request.json(); upTo = Number(b && b.upTo) || 0; } catch (e) { /* no body */ }
  const now = Date.now();
  const prev = parseInt((await env.ACCOUNTS.get(ALERTS_SEEN_PREFIX + sub)) || '0', 10) || 0;
  const next = upTo > 0 ? Math.max(prev, Math.min(upTo, now)) : now;
  await env.ACCOUNTS.put(ALERTS_SEEN_PREFIX + sub, String(next));
  return json({ ok: true });
}
// DELETE /alerts/:id: removes it from the account's list (the row is kept for the admin record). Idempotent.
async function handleAlertDelete(env, request, id) {
  const sub = await requireSession(env, request);
  if (!sub) return textError(401, 'sign-in required');
  if (!/^[0-9a-f-]{36}$/.test(id)) return textError(400, 'invalid alert id');
  await ensureAlerts(env);
  await env.ADS_DB.prepare('UPDATE alerts SET dismissed_at = ? WHERE id = ? AND sub = ? AND dismissed_at IS NULL').bind(Date.now(), id, sub).run();
  return json({ ok: true });
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

// D1 mirror of report records. KV stays the source of truth (details, dismissal, TTLs); this table
// only carries what the admin list needs to count, filter and sort past the KV list limits (slug,
// reason, csam flag, time, dismissed). It is written best-effort when a report is filed, dismissed or
// undismissed, and backfilled by POST /admin/reports/reindex in small chunks (subrequest caps). Until
// the backfill has finished (REPORT_INDEX_FLAG in REPORTS) the list keeps using the KV walk below.
const REPORT_INDEX_FLAG = 'admin:reportindex:v1';
const REPORT_INDEX_PAGE = 30;
const REPORT_REINDEX_CHUNK = 20;
let reportIndexReady = null;
let reportIndexFlag = false;
function ensureReportIndex(env) {
  if (!reportIndexReady) {
    reportIndexReady = env.ADS_DB.batch([
      env.ADS_DB.prepare('CREATE TABLE IF NOT EXISTS report_index (key TEXT PRIMARY KEY, slug TEXT NOT NULL, reason TEXT, is_csam INTEGER NOT NULL DEFAULT 0, reported_at INTEGER NOT NULL, dismissed_at INTEGER)'),
      env.ADS_DB.prepare('CREATE INDEX IF NOT EXISTS report_index_time ON report_index (dismissed_at, reported_at, key)'),
      env.ADS_DB.prepare('CREATE INDEX IF NOT EXISTS report_index_slug ON report_index (slug)'),
      env.ADS_DB.prepare('CREATE INDEX IF NOT EXISTS report_index_reason ON report_index (reason)')
    ]).catch((e) => { reportIndexReady = null; throw e; });
  }
  return reportIndexReady;
}
async function reportIndexOn(env) {
  if (reportIndexFlag) return true;
  try { if ((await env.REPORTS.get(REPORT_INDEX_FLAG)) === '1') reportIndexFlag = true; } catch (e) {}
  return reportIndexFlag;
}
function reportIndexStmt(env, key, rec) {
  const m = key.match(REPORT_KEY_RE), l = key.match(REPORT_LEGACY_KEY_RE);
  if (!m && !l) return null;
  const slug = m ? m[2] : l[1];
  const ts = m ? REPORT_TS_MAX - parseInt(m[1], 10) : parseInt(l[2], 10);
  return env.ADS_DB.prepare('INSERT OR REPLACE INTO report_index (key, slug, reason, is_csam, reported_at, dismissed_at) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(key, slug, (rec && rec.reason) || null, rec && rec.isCsam ? 1 : 0, ts, (rec && rec.dismissedAt) || null);
}
async function mirrorReport(env, key, rec) {
  try {
    await ensureReportIndex(env);
    const st = reportIndexStmt(env, key, rec);
    if (st) await st.run();
  } catch (e) {}
}
async function unmirrorReport(env, key) {
  try {
    await ensureReportIndex(env);
    await env.ADS_DB.prepare('DELETE FROM report_index WHERE key = ?').bind(key).run();
  } catch (e) {}
}

// POST /admin/reports/reindex {cursor}: copies one small chunk of KV report records into report_index
// (idempotent upserts) and returns the cursor for the next chunk; done:true sets the flag that switches
// the list over to D1. The admin page drives it automatically the first time it sees the KV list.
async function handleAdminReportsReindex(env, request) {
  const g = await adminGate(env, request); if (g) return g;
  const body = await adminBody(request);
  let phase = 'n', kvCursor;
  const cm = typeof body.cursor === 'string' ? body.cursor.match(/^([nl]):(.*)$/s) : null;
  if (cm) { phase = cm[1]; kvCursor = cm[2] || undefined; }
  await ensureReportIndex(env);
  const page = await env.REPORTS.list({ prefix: phase === 'n' ? REPORT_KEY_PREFIX : 'report:', cursor: kvCursor, limit: REPORT_REINDEX_CHUNK });
  const stmts = (await Promise.all(page.keys.map(async (k) => {
    if (!REPORT_KEY_RE.test(k.name) && !REPORT_LEGACY_KEY_RE.test(k.name)) return null;
    let raw = null;
    try { raw = await env.REPORTS.get(k.name); } catch (e) { return null; }
    if (raw === null) return null;
    let rec = null;
    try { rec = JSON.parse(raw); } catch (e) {}
    return reportIndexStmt(env, k.name, rec);
  }))).filter(Boolean);
  if (stmts.length) await env.ADS_DB.batch(stmts);
  let done = false;
  if (page.list_complete) { if (phase === 'n') { phase = 'l'; kvCursor = undefined; } else done = true; }
  else kvCursor = page.cursor;
  if (done) { await env.REPORTS.put(REPORT_INDEX_FLAG, '1'); reportIndexFlag = true; }
  return json({ ok: true, done, cursor: done ? null : phase + ':' + (kvCursor || ''), indexed: stmts.length });
}

// D1-backed report list. Filters (dismissed, reason, slug substring) and the sort run in SQL; the first
// page also returns exact aggregates (agg) so the counts don't depend on how much is loaded. Status
// (live / taken down / ...) lives in KV metadata, so that one filter stays client-side. Returns null on
// any D1 failure so the caller can fall back to the KV walk.
async function handleAdminReportsIndexed(env, url) {
  try {
    await ensureReportIndex(env);
    const sp = url.searchParams;
    const dis = sp.get('dismissed') === '1';
    const reason = (sp.get('reason') || '').slice(0, 40);
    const q = (sp.get('q') || '').toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 48);
    const sp2 = sp.get('sort');
    const sort = sp2 === 'old' || sp2 === 'most' ? sp2 : 'new';
    const cursorRaw = sp.get('cursor') || '';
    const off = sort === 'most' ? Math.min(100000, Math.max(0, parseInt(cursorRaw, 10) || 0)) : 0;
    const cur = sort === 'most' ? null : parseAdminCursor(cursorRaw);
    const dClause = dis ? 'dismissed_at IS NOT NULL' : 'dismissed_at IS NULL';
    const base = [dClause], bb = [];
    if (q) { base.push('instr(slug, ?) > 0'); bb.push(q); }
    const where = base.slice(), wb = bb.slice();
    if (reason) { where.push('reason = ?'); wb.push(reason); }
    if (cur) { where.push(sort === 'old' ? '(reported_at, key) > (?, ?)' : '(reported_at, key) < (?, ?)'); wb.push(cur.key, cur.id); }
    const order = sort === 'most'
      ? '(SELECT COUNT(*) FROM report_index r2 WHERE r2.slug = report_index.slug AND r2.' + dClause + ') DESC, slug ASC, reported_at DESC, key DESC'
      : sort === 'old' ? 'reported_at ASC, key ASC' : 'reported_at DESC, key DESC';
    const stmts = [
      env.ADS_DB.prepare('SELECT key, slug, reason, is_csam, reported_at FROM report_index WHERE ' + where.join(' AND ') + ' ORDER BY ' + order + ' LIMIT ?' + (sort === 'most' ? ' OFFSET ?' : ''))
        .bind(...wb, REPORT_INDEX_PAGE + 1, ...(sort === 'most' ? [off] : []))
    ];
    const first = !cursorRaw;
    if (first) {
      stmts.unshift(
        env.ADS_DB.prepare('SELECT COUNT(DISTINCT slug) AS pages, COUNT(DISTINCT CASE WHEN is_csam = 1 THEN slug END) AS csam FROM report_index WHERE ' + dClause),
        env.ADS_DB.prepare('SELECT reason, COUNT(*) AS n FROM report_index WHERE ' + base.join(' AND ') + ' GROUP BY reason').bind(...bb)
      );
    }
    const res = await env.ADS_DB.batch(stmts);
    const rows = res[res.length - 1].results || [];
    const more = rows.length > REPORT_INDEX_PAGE;
    if (more) rows.pop();
    const last = rows[rows.length - 1];
    const nextCursor = more && last ? (sort === 'most' ? String(off + REPORT_INDEX_PAGE) : last.reported_at + '|' + last.key) : null;
    const metas = new Map();
    const out = await Promise.all(rows.map(async (r) => {
      const raw = await env.REPORTS.get(r.key);
      if (raw === null) { await unmirrorReport(env, r.key); return null; } // record expired or removed elsewhere
      let rec = null;
      try { rec = JSON.parse(raw); } catch (e) {}
      if (!!(rec && rec.dismissedAt) !== dis) { await mirrorReport(env, r.key, rec); return null; } // mirror drifted: repair, skip
      if (!metas.has(r.slug)) metas.set(r.slug, getMeta(env, r.slug));
      const meta = await metas.get(r.slug);
      return {
        key: r.key, slug: r.slug, reportedAt: r.reported_at,
        reason: rec ? rec.reason : '?', details: rec ? rec.details : '',
        isCsam: !!(rec && rec.isCsam),
        dismissedAt: rec ? rec.dismissedAt || null : null,
        ncmec: (rec && rec.isCsam) ? ((await getNcmec(env, r.slug)).slice(-1)[0] || null) : null,
        status: !meta ? 'missing' : meta.adminLocked ? 'taken down' : meta.deletedAt ? 'unpublished' : 'live'
      };
    }));
    const body = { reports: out.filter(Boolean), nextCursor, indexed: true };
    if (first) {
      const p = (res[0].results || [])[0] || {};
      const byReason = {}; let total = 0;
      (res[1].results || []).forEach((x) => { byReason[x.reason || '?'] = x.n; total += x.n; });
      body.agg = { total, byReason, pages: p.pages || 0, csam: p.csam || 0 };
    }
    return json(body);
  } catch (e) { return null; }
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
  const indexOn = await reportIndexOn(env);
  if (indexOn) { const viaD1 = await handleAdminReportsIndexed(env, url); if (viaD1) return viaD1; }
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
  const wantDismissed = url.searchParams.get('dismissed') === '1';
  const rows = await Promise.all(items.map(async (it) => {
    let rec = null;
    try { rec = JSON.parse(await env.REPORTS.get(it.key)); } catch (e) {}
    if (!!(rec && rec.dismissedAt) !== wantDismissed) return null;
    const meta = await getMeta(env, it.slug);
    return {
      key: it.key, slug: it.slug, reportedAt: it.ts,
      reason: rec ? rec.reason : '?', details: rec ? rec.details : '',
      isCsam: !!(rec && rec.isCsam),
      dismissedAt: rec ? rec.dismissedAt || null : null,
      ncmec: (rec && rec.isCsam) ? ((await getNcmec(env, it.slug)).slice(-1)[0] || null) : null,
      status: !meta ? 'missing' : meta.adminLocked ? 'taken down' : meta.deletedAt ? 'unpublished' : 'live'
    };
  }));
  return json(indexOn ? { reports: rows.filter(Boolean), nextCursor } : { reports: rows.filter(Boolean), nextCursor, indexed: false });
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
    await mirrorReport(env, key, rec);
  } else {
    await env.REPORTS.delete(key);
    await unmirrorReport(env, key);
  }
  const km = key.match(REPORT_KEY_RE);
  await audit(env, 'dismiss', km ? km[2] : ((key.match(REPORT_LEGACY_KEY_RE) || [])[1] || null));
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
  // ?ts=<ms>: restore that specific snapshot instead of the newest copy.
  const tsParam = new URL(request.url).searchParams.get('ts');
  if (tsParam) {
    if (!/^\d{10,16}$/.test(tsParam)) return textError(400, 'invalid timestamp');
    const chosen = await env.NOTES_BUCKET.get('deleted/' + slug + '/' + tsParam + '.html');
    if (!chosen) return textError(404, 'snapshot not found');
    await env.NOTES_BUCKET.put(slug + '.html', chosen.body, { httpMetadata: { contentType: 'text/html; charset=utf-8' } });
  }
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
  await audit(env, 'restore', slug, tsParam ? 'snapshot ' + tsParam : null);
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
  if (cur.hostname.toLowerCase() === url.hostname.toLowerCase()) return textError(400, 'url not allowed'); // no self-fetch loops
  let res = null;
  for (let hop = 0; hop < 4; hop++) {
    if (!adminImgTargetOk(cur) || cur.hostname.toLowerCase() === url.hostname.toLowerCase()) return textError(400, 'url not allowed');
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
      'Cross-Origin-Resource-Policy': 'same-origin',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer'
    }
  });
}

/* ---------------- Admin tools: audit log, lookup, owner, stories, ads, NCMEC ---------------- */
// Audit entries live in the REPORTS namespace under "audit:" (inverted timestamp so the newest
// list first). The record rides in the key's metadata, so listing needs no extra reads. Only
// the action, slug and a short detail are kept: no IPs, no tokens, no email addresses.
const AUDIT_PREFIX = 'audit:';
const AUDIT_TTL_S = 400 * 24 * 60 * 60;
const NCMEC_PREFIX = 'ncmec:'; // SLUGS namespace: NCMEC report record(s) per slug

async function audit(env, action, slug, detail) {
  try {
    const at = Date.now();
    await env.REPORTS.put(
      AUDIT_PREFIX + String(REPORT_TS_MAX - at).padStart(13, '0') + ':' + crypto.randomUUID().slice(0, 8),
      '1',
      { expirationTtl: AUDIT_TTL_S, metadata: { at, action, slug: slug || null, detail: detail || null } }
    );
  } catch (e) { console.log('audit failed: ' + (e && e.message)); }
}

async function adminGate(env, request) {
  const auth = await adminAuthOk(env, request);
  if (auth === 'limited') return textError(429, 'too many failed attempts, try again in 5 minutes');
  if (auth !== 'ok') return textError(403, 'invalid admin token');
  return null;
}
function adminSlugParam(url) {
  const s = (url.searchParams.get('slug') || '').toLowerCase();
  return SLUG_RE.test(s) ? s : null;
}
async function adminBody(request) {
  try { const b = await request.json(); return b && typeof b === 'object' ? b : {}; } catch (e) { return {}; }
}
// How many report records exist per slug (open ones plus dismissed CSAM ones kept for the
// retention window). Scans the key names only; capped at 5 pages of 1000.
async function reportCounts(env) {
  const counts = new Map();
  let cursor;
  for (let i = 0; i < 5; i++) {
    const page = await env.REPORTS.list({ prefix: REPORT_KEY_PREFIX, cursor });
    for (const k of page.keys) {
      const m = k.name.match(REPORT_KEY_RE);
      if (m) counts.set(m[2], (counts.get(m[2]) || 0) + 1);
    }
    if (page.list_complete) break;
    cursor = page.cursor;
  }
  return counts;
}
async function getNcmec(env, slug) {
  try { return JSON.parse(await env.SLUGS.get(NCMEC_PREFIX + slug)) || []; } catch (e) { return []; }
}

// GET /admin/lookup?slug=: everything known about one slug, reported or not.
async function handleAdminLookup(env, request, url) {
  const g = await adminGate(env, request); if (g) return g;
  const slug = adminSlugParam(url);
  if (!slug) return textError(400, 'invalid slug');
  const meta = await getMeta(env, slug);
  const reports = (await reportCounts(env)).get(slug) || 0;
  if (!meta) return json({ found: false, slug, reports });
  const [user, story, likes, ad, head, snaps, hold, ncmec] = await Promise.all([
    meta.ownerSub ? getUser(env, meta.ownerSub) : null,
    env.ADS_DB.prepare('SELECT title, created_at, description, tags, image_url, image_urls FROM stories WHERE slug = ?').bind(slug).first(),
    env.ADS_DB.prepare('SELECT COUNT(*) AS n FROM likes WHERE slug = ?').bind(slug).first(),
    env.ADS_DB.prepare('SELECT views_total, views_used, status FROM ads WHERE slug = ?').bind(slug).first(),
    env.NOTES_BUCKET.head(slug + '.html'),
    env.NOTES_BUCKET.list({ prefix: 'deleted/' + slug + '/' }),
    env.SLUGS.get(CSAM_HOLD_PREFIX + slug),
    getNcmec(env, slug)
  ]);
  const ownerAuthorId = meta.ownerSub ? ((await authorIdsFor(env, [meta.ownerSub]))[meta.ownerSub] || null) : null;
  return json({
    found: true, slug,
    status: meta.adminLocked ? 'taken down' : meta.deletedAt ? 'unpublished' : 'live',
    title: meta.title || null, createdAt: meta.createdAt || null, updatedAt: meta.updatedAt || null,
    deletedAt: meta.deletedAt || null,
    sizeBytes: head ? head.size : (meta.sizeBytes || null),
    hasOwner: !!meta.ownerSub, ownerEmail: user ? user.email : null, ownerAuthorId,
    showInStories: !!meta.showInStories, storyBlocked: !!meta.storyBlocked,
    desc: (story ? story.description : meta.desc) || '',
    tags: story ? parseStoryTags(story.tags) : (Array.isArray(meta.tags) ? meta.tags.filter(x => typeof x === 'string') : []),
    noteCreatedAt: meta.noteCreatedAt || null,
    story: story ? { title: story.title, createdAt: story.created_at, images: adminStoryImageSpecs(story) } : null,
    likes: likes ? likes.n : 0,
    ad: ad ? { status: ad.status, viewsTotal: ad.views_total, viewsUsed: ad.views_used } : null,
    reports, csamHold: hold !== null, snapshots: (snaps.objects || []).length, ncmec
  });
}

// Story preview image specs for the admin Lookup. R2-held blobs are read through
// /admin/media; remote URLs go through the /admin/img proxy (never straight from the browser).
function adminStoryImageSpecs(row) {
  const spec = (e, kind, i) => e === STORY_IMAGE_R2_MARKER ? { r2: true, kind, i } : (typeof e === 'string' && e ? { url: e } : null);
  const ring = row.image_url ? spec(row.image_url, 'ring', 0) : null;
  let parsed;
  try { parsed = JSON.parse(row.image_urls || '[]'); } catch (e) { parsed = []; }
  const entries = Array.isArray(parsed) ? parsed : (parsed && Array.isArray(parsed.e) ? parsed.e : []);
  return { ring, cards: entries.map((e, i) => spec(e, 'card', i)).filter(Boolean).slice(0, 3) };
}

// Counts an account's backed-up images. R2 lists 1000 keys per call, so a second call covers the
// per-account cap (MAX_SYNC_IMAGES_PER_ACCOUNT); "more" is only true if that is somehow exceeded.
async function adminCountSyncImages(env, sub) {
  const prefix = 'sync/' + sub + '/img/';
  let n = 0, cursor, truncated = false;
  for (let i = 0; i < Math.ceil(MAX_SYNC_IMAGES_PER_ACCOUNT / 1000); i++) {
    const page = await env.NOTES_BUCKET.list({ prefix, cursor, limit: 1000 });
    n += (page.objects || []).length;
    truncated = !!page.truncated;
    if (!truncated) break;
    cursor = page.cursor;
  }
  return { n, more: truncated };
}

// GET /admin/media?slug=&kind=ring|card|profile&i=: one stored image, admin token required.
// ring/card are a story's preview images; profile is the slug owner's profile picture (the owner's
// sub never leaves the worker). Raster types only, served inert like /admin/img.
async function handleAdminMedia(env, request, url) {
  const g = await adminGate(env, request); if (g) return g;
  const slug = adminSlugParam(url);
  if (!slug) return textError(400, 'invalid slug');
  const kind = url.searchParams.get('kind');
  let key = null;
  if (kind === 'ring') key = storyImageKey(slug);
  else if (kind === 'card') {
    const i = parseInt(url.searchParams.get('i') || '', 10);
    if (!(i >= 0 && i < 3)) return textError(400, 'invalid index');
    key = storyCardImageKey(slug, i);
  } else if (kind === 'profile') {
    const meta = await getMeta(env, slug);
    if (!meta || !meta.ownerSub) return textError(404, 'not found');
    key = profileImageKey(meta.ownerSub);
  } else return textError(400, 'invalid kind');
  const obj = await env.NOTES_BUCKET.get(key);
  if (!obj) return textError(404, 'not found');
  const type = ((obj.httpMetadata && obj.httpMetadata.contentType) || '').split(';')[0].trim().toLowerCase();
  if (!ADMIN_IMG_TYPES.has(type)) return textError(415, 'not a supported image type');
  return new Response(obj.body, {
    headers: {
      'Content-Type': type,
      'Content-Security-Policy': "default-src 'none'; sandbox",
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer'
    }
  });
}

// GET /admin/owner?slug=: the account behind a slug and everything it has live.
async function handleAdminOwner(env, request, url) {
  const g = await adminGate(env, request); if (g) return g;
  const slug = adminSlugParam(url);
  if (!slug) return textError(400, 'invalid slug');
  const meta = await getMeta(env, slug);
  if (!meta) return textError(404, 'not found');
  if (!meta.ownerSub) return json({ anonymous: true });
  const sub = meta.ownerSub;
  const [user, counts, adsRow, balance, subRow, likeRows, ledgerRows, syncRaw, syncImgs] = await Promise.all([
    getUser(env, sub), reportCounts(env),
    env.ADS_DB.prepare('SELECT COUNT(*) AS n FROM ads WHERE owner_sub = ?').bind(sub).first(),
    getCreditBalance(env, sub),
    // Same tables handleSubscriberCount reads for the owner's own Account sheet.
    env.ADS_DB.prepare('SELECT COUNT(*) AS n FROM subscriptions WHERE author_sub = ?').bind(sub).first(),
    env.ADS_DB.prepare('SELECT slug, COUNT(*) AS n FROM likes WHERE author_sub = ? GROUP BY slug').bind(sub).all(),
    env.ADS_DB.prepare('SELECT delta, reason, slug, created_at FROM view_credits_ledger WHERE owner_sub = ? ORDER BY created_at DESC LIMIT 20').bind(sub).all(),
    env.ACCOUNTS.get('syncmeta:' + sub),
    adminCountSyncImages(env, sub)
  ]);
  let syncMeta = null;
  try { syncMeta = syncRaw ? JSON.parse(syncRaw) : null; } catch (e) {}
  const likesBySlug = new Map(((likeRows && likeRows.results) || []).map(r => [r.slug, r.n]));
  let likesTotal = 0;
  for (const n of likesBySlug.values()) likesTotal += n;
  const prefix = 'owner:' + sub + ':';
  const pages = [];
  const allSlugs = []; // live or not, for the report totals below
  let cursor;
  do {
    const page = await env.SLUGS.list({ prefix, cursor });
    for (const k of page.keys) {
      if (pages.length >= 100) break;
      const s = k.name.slice(prefix.length);
      if (allSlugs.length < 400) allSlugs.push(s);
      const m = await getMeta(env, s);
      if (!m || m.deletedAt) continue;
      pages.push({ slug: s, title: m.title || null, updatedAt: m.updatedAt || null, showInStories: !!m.showInStories, reports: counts.get(s) || 0, likes: likesBySlug.get(s) || 0 });
    }
    cursor = (page.list_complete || pages.length >= 100) ? undefined : page.cursor;
  } while (cursor);
  const authorId = (await authorIdsFor(env, [sub]))[sub] || null;
  const reportStats = await ownerReportStats(env, sub, allSlugs);
  // Every alert ever sent to this account, including ones the person has since deleted from their list.
  let alertRows = [], strikeRows = [], alertTotal = 0;
  try {
    await ensureAlerts(env);
    const ar = await env.ADS_DB.batch([
      env.ADS_DB.prepare('SELECT kind, message, created_at, dismissed_at FROM alerts WHERE sub = ? AND created_at >= ? ORDER BY created_at DESC, id DESC LIMIT 300').bind(sub, TREND_EPOCH),
      env.ADS_DB.prepare('SELECT kind, message, created_at, dismissed_at FROM alerts WHERE sub = ? AND created_at >= ? AND (' + STRIKE_SQL + ') ORDER BY created_at ASC, id ASC LIMIT 300').bind(sub, TREND_EPOCH),
      env.ADS_DB.prepare('SELECT COUNT(*) AS n FROM alerts WHERE sub = ? AND created_at >= ?').bind(sub, TREND_EPOCH)
    ]);
    alertRows = ar[0].results || [];
    strikeRows = ar[1].results || [];
    alertTotal = ((ar[2].results || [])[0] || {}).n || 0;
  } catch (e) { console.log('admin alerts failed: ' + (e && e.message)); }
  return json({
    authorId,
    alerts: alertRows.map(r => ({ kind: r.kind, message: r.message, at: r.created_at, dismissedAt: r.dismissed_at || null, strike: isStrikeAlert(r.kind, r.message) })),
    alertTotal,
    strikes: strikeRows.map(r => ({ kind: r.kind, message: r.message, at: r.created_at, dismissedAt: r.dismissed_at || null })),
    strikeCount: strikeRows.length,
    reportStats,
    email: user ? user.email : null, createdAt: user ? user.createdAt || null : null,
    displayName: user ? user.profileName || null : null, hasProfileImage: !!(user && user.hasProfileImage),
    ledger: ((ledgerRows && ledgerRows.results) || []).map(r => ({ delta: r.delta, reason: r.reason, slug: r.slug || null, at: r.created_at })),
    backup: syncMeta ? { updatedAt: syncMeta.updatedAt || null, sizeBytes: syncMeta.sizeBytes || 0, images: syncImgs.n, imagesMore: syncImgs.more } : null,
    lastSignInAt: user ? user.lastSignInAt || null : null,
    suspended: !!(user && user.suspended), pendingDeletionAt: user ? user.pendingDeletionAt || null : null,
    pages, ads: adsRow ? adsRow.n : 0, creditBalance: balance,
    subscribers: subRow ? subRow.n : 0, likes: likesTotal
  });
}

// POST /admin/owner/action {slug, action}: suspend | unsuspend | delete | cancel-delete | clear-name | clear-picture.
// Suspended accounts are signed out everywhere and can't sign in (handleGoogleAuth).
// "delete" schedules the normal 30-day account deletion AND suspends, so the owner can't
// cancel it just by signing back in; "cancel-delete" undoes that.
async function handleAdminOwnerAction(env, request) {
  const g = await adminGate(env, request); if (g) return g;
  const body = await adminBody(request);
  const slug = typeof body.slug === 'string' ? body.slug.toLowerCase() : '';
  if (!SLUG_RE.test(slug)) return textError(400, 'invalid slug');
  const meta = await getMeta(env, slug);
  if (!meta || !meta.ownerSub) return textError(404, 'no account for this slug');
  const sub = meta.ownerSub;
  const user = await getUser(env, sub);
  if (!user) return textError(404, 'account not found');
  const action = body.action;
  const wasAdminDeleted = !!user.adminDeleted;
  const reason = adminReasonOf(body);
  if (['suspend', 'clear-name', 'clear-picture'].includes(action) && !reason) return textError(400, 'reason required');
  if (action === 'suspend') user.suspended = true;
  else if (action === 'unsuspend') delete user.suspended;
  else if (action === 'clear-name') user.profileName = null;
  else if (action === 'clear-picture') { await env.NOTES_BUCKET.delete(profileImageKey(sub)); user.hasProfileImage = false; }
  else if (action === 'delete') { user.suspended = true; user.adminDeleted = true; user.pendingDeletionAt = Date.now(); }
  else if (action === 'cancel-delete') {
    delete user.pendingDeletionAt;
    if (user.adminDeleted) { delete user.adminDeleted; delete user.suspended; }
  } else return textError(400, 'invalid action');
  await putUser(env, sub, user);
  if (action === 'suspend' || action === 'delete') await revokeAllSessions(env, sub);
  await audit(env, 'owner_' + action, slug);
  const ownerAlert = {
    'clear-picture': ['profile_picture', 'Your profile picture was removed. ' + alertReason(reason) + ' You can upload a new one. ' + ALERT_REPEAT_NOTE],
    'clear-name': ['profile_name', 'Your display name was removed. ' + alertReason(reason) + ' You can set a new one. ' + ALERT_REPEAT_NOTE],
    'suspend': ['suspended', 'Your account was suspended. ' + alertReason(reason)],
    'unsuspend': ['unsuspended', 'Your account suspension was lifted. ' + ALERT_REPEAT_NOTE]
  }[action];
  if (ownerAlert) await createAlert(env, sub, ownerAlert[0], ownerAlert[1]);
  else if (action === 'cancel-delete' && !user.adminDeleted && wasAdminDeleted) await createAlert(env, sub, 'unsuspended', 'Your account deletion was cancelled and your account restored. ' + ALERT_REPEAT_NOTE);
  return json({ ok: true, suspended: !!user.suspended, pendingDeletionAt: user.pendingDeletionAt || null });
}

// POST /admin/story {slug, action}: "remove" pulls a page out of stories (page stays online)
// and blocks re-enabling it; "allow" lifts the block. handleSetStories enforces storyBlocked.
async function handleAdminStory(env, request) {
  const g = await adminGate(env, request); if (g) return g;
  const body = await adminBody(request);
  const slug = typeof body.slug === 'string' ? body.slug.toLowerCase() : '';
  if (!SLUG_RE.test(slug)) return textError(400, 'invalid slug');
  const meta = await getMeta(env, slug);
  if (!meta || meta.deletedAt) return textError(404, 'not live');
  const reason = adminReasonOf(body);
  if (body.action === 'remove' && !reason) return textError(400, 'reason required');
  if (body.action === 'remove') {
    if (meta.showInStories) {
      await Promise.all([
        deleteStoryImage(env, slug),
        deleteStoryCardImages(env, slug),
        env.ADS_DB.batch([
          env.ADS_DB.prepare('DELETE FROM stories WHERE slug = ?').bind(slug),
          env.ADS_DB.prepare('DELETE FROM story_seen WHERE slug = ?').bind(slug)
        ])
      ]);
    }
    meta.showInStories = false;
    meta.storyBlocked = true;
  } else if (body.action === 'allow') {
    delete meta.storyBlocked;
  } else return textError(400, 'invalid action');
  await putMeta(env, slug, meta);
  await audit(env, 'story_' + body.action, slug);
  await createAlert(env, meta.ownerSub, 'story', body.action === 'remove'
    ? 'Your note ' + alertNoteName(meta, slug) + ' was removed from stories. ' + alertReason(reason) + ' Your note is still published. ' + ALERT_REPEAT_NOTE
    : 'Your note ' + alertNoteName(meta, slug) + ' can be shown in stories again.');
  return json({ ok: true });
}

// GET /admin/ads?status=&q=&cursor=: ads across all accounts, newest first, keyset-paginated.
const ADMIN_ADS_PAGE = 30;
async function handleAdminAds(env, request, url) {
  const g = await adminGate(env, request); if (g) return g;
  await ensureAdminIndexes(env);
  const status = url.searchParams.get('status') || '';
  const cur = parseAdminCursor(url.searchParams.get('cursor'));
  const filter = ['active', 'paused', 'exhausted', 'unpublished'].includes(status);
  const q = (url.searchParams.get('q') || '').toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 48);
  const where = [], b = [];
  if (filter) { where.push('a.status = ?'); b.push(status); }
  if (q) { where.push('a.slug LIKE ?'); b.push('%' + q + '%'); }
  const w = where.length ? ' WHERE ' + where.join(' AND ') : '';
  const curSql = cur ? (where.length ? ' AND ' : ' WHERE ') + '(a.created_at, a.slug) < (?, ?)' : '';
  // LIMIT+1 tells us whether another page exists without a second query; the total (first page only)
  // feeds the "of N" count.
  const stmts = [
    env.ADS_DB.prepare(
      'SELECT a.slug, a.owner_sub, a.views_total, a.views_used, a.status, a.created_at, ' +
      '(SELECT COUNT(*) FROM ad_viewers v WHERE v.slug = a.slug) AS unique_viewers ' +
      'FROM ads a' + w + curSql + ' ORDER BY a.created_at DESC, a.slug DESC LIMIT ?'
    ).bind(...b, ...(cur ? [cur.key, cur.id] : []), ADMIN_ADS_PAGE + 1)
  ];
  if (!cur) stmts.unshift(env.ADS_DB.prepare('SELECT COUNT(*) AS t FROM ads a' + w).bind(...b));
  const res = await env.ADS_DB.batch(stmts);
  const rows = res[res.length - 1].results || [];
  const more = rows.length > ADMIN_ADS_PAGE;
  if (more) rows.pop();
  const last = rows[rows.length - 1];
  const emails = {};
  await Promise.all([...new Set(rows.map(r => r.owner_sub))].map(async (sub) => {
    let u = null;
    try { u = await getUserCached(env, sub); } catch (e) {}
    emails[sub] = u ? u.email : null;
  }));
  return json({
    ads: rows.map(r => ({
      slug: r.slug, ownerEmail: emails[r.owner_sub], viewsTotal: r.views_total, viewsUsed: r.views_used,
      status: r.status, createdAt: r.created_at, uniqueViewers: r.unique_viewers
    })),
    total: cur ? null : res[0].results[0].t,
    next: more && last ? last.created_at + '|' + last.slug : null
  });
}

// Credits the unused views of an ad back to its owner, once per slug (rc_event_id is the guard).
async function refundAdViews(env, slug, ad) {
  const remaining = Math.max(0, (ad.views_total || 0) - (ad.views_used || 0));
  if (!remaining) return 0;
  const evt = 'admin_refund:' + slug;
  const r = await env.ADS_DB.prepare(
    "INSERT INTO view_credits_ledger (owner_sub, delta, reason, slug, rc_event_id, created_at) " +
    "SELECT ?, ?, 'refund', ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM view_credits_ledger WHERE rc_event_id = ?)"
  ).bind(ad.owner_sub, remaining, slug, evt, Date.now(), evt).run();
  return (r && r.meta && r.meta.changes) ? remaining : 0;
}

// POST /admin/ad {slug, action, refund}: pause | resume | takedown | refund.
// takedown = the owner's unpublish (page stays up); add refund:true to also return unused views.
// "refund" alone is for ads that are already down (e.g. their page was taken down and the
// views were forfeited).
async function handleAdminAd(env, request) {
  const g = await adminGate(env, request); if (g) return g;
  const body = await adminBody(request);
  const slug = typeof body.slug === 'string' ? body.slug.toLowerCase() : '';
  if (!SLUG_RE.test(slug)) return textError(400, 'invalid slug');
  const ad = await env.ADS_DB.prepare('SELECT owner_sub, views_total, views_used, status FROM ads WHERE slug = ?').bind(slug).first();
  if (!ad) return textError(404, 'ad not found');
  const reason = adminReasonOf(body);
  if ((body.action === 'pause' || body.action === 'takedown') && !reason) return textError(400, 'reason required');
  const now = Date.now();
  const set = (from, to) => env.ADS_DB.prepare('UPDATE ads SET status = ?, updated_at = ? WHERE slug = ? AND status = ?').bind(to, now, slug, from).run();
  let refunded = 0;
  try {
    if (body.action === 'pause') {
      if (ad.status !== 'active') return textError(409, 'ad is not active');
      await set('active', 'paused');
    } else if (body.action === 'resume') {
      if (ad.status !== 'paused') return textError(409, 'ad is not paused');
      await set('paused', 'active');
    } else if (body.action === 'takedown') {
      if (ad.status !== 'active' && ad.status !== 'paused') return textError(409, 'ad is not running');
      await set(ad.status, 'unpublished');
      if (body.refund === true) refunded = await refundAdViews(env, slug, ad);
    } else if (body.action === 'refund') {
      if (ad.status === 'active' || ad.status === 'paused') return textError(409, 'take the ad down first');
      refunded = await refundAdViews(env, slug, ad);
    } else return textError(400, 'invalid action');
  } catch (e) {
    console.log('admin ad action failed: ' + (e && e.message));
    return textError(500, 'ad action failed');
  }
  await audit(env, 'ad_' + body.action, slug, refunded ? 'refunded ' + refunded : null);
  const adRefund = refunded ? ' ' + refunded + ' unused views were refunded to your balance.' : '';
  const adAlert = {
    pause: 'Your ad on /' + slug + ' was paused. ' + alertReason(reason) + ' ' + ALERT_REPEAT_NOTE,
    resume: 'Your ad on /' + slug + ' is running again.',
    takedown: 'Your ad on /' + slug + ' was taken down. ' + alertReason(reason) + adRefund + ' ' + ALERT_REPEAT_NOTE,
    refund: adRefund.trim() ? refunded + ' unused views from your ad on /' + slug + ' were refunded to your balance.' : ''
  }[body.action];
  if (adAlert) await createAlert(env, ad.owner_sub, 'ad', adAlert);
  return json({ ok: true, refunded });
}

// POST /admin/ncmec {slug, reportId, note}: records that the page was reported to NCMEC.
// Kept for the CSAM retention window, independently of the slug's own metadata.
async function handleAdminNcmec(env, request) {
  const g = await adminGate(env, request); if (g) return g;
  const body = await adminBody(request);
  const slug = typeof body.slug === 'string' ? body.slug.toLowerCase() : '';
  if (!SLUG_RE.test(slug)) return textError(400, 'invalid slug');
  if (!(await getMeta(env, slug))) return textError(404, 'not found');
  const reportId = typeof body.reportId === 'string' ? body.reportId.trim().slice(0, 64) : '';
  const note = typeof body.note === 'string' ? body.note.trim().slice(0, 200) : '';
  const list = (await getNcmec(env, slug)).slice(-19);
  list.push({ at: Date.now(), reportId: reportId || null, note: note || null });
  await env.SLUGS.put(NCMEC_PREFIX + slug, JSON.stringify(list), { expirationTtl: REPORT_DISMISSED_CSAM_TTL_S });
  await audit(env, 'ncmec_recorded', slug);
  return json({ ok: true, ncmec: list });
}

// POST /admin/undismiss {key}: brings back a dismissed CSAM report (ordinary reports are
// deleted on dismiss, so there is nothing to bring back for those).
async function handleAdminUndismiss(env, request) {
  const g = await adminGate(env, request); if (g) return g;
  const body = await adminBody(request);
  const key = typeof body.key === 'string' ? body.key : '';
  if (!REPORT_KEY_RE.test(key) && !REPORT_LEGACY_KEY_RE.test(key)) return textError(400, 'invalid report key');
  const raw = await env.REPORTS.get(key);
  if (raw === null) return textError(404, 'report not found');
  let rec = null;
  try { rec = JSON.parse(raw); } catch (e) {}
  if (!rec || !rec.dismissedAt) return json({ ok: true });
  delete rec.dismissedAt;
  await env.REPORTS.put(key, JSON.stringify(rec));
  await mirrorReport(env, key, rec);
  await audit(env, 'undismiss', rec.slug || null);
  return json({ ok: true });
}

// GET /admin/audit?cursor=: newest-first action log.
async function handleAdminAudit(env, request, url) {
  const g = await adminGate(env, request); if (g) return g;
  const page = await env.REPORTS.list({ prefix: AUDIT_PREFIX, cursor: url.searchParams.get('cursor') || undefined, limit: ADMIN_PAGE_SIZE });
  return json({
    entries: page.keys.map(k => k.metadata).filter(Boolean),
    nextCursor: page.list_complete ? null : page.cursor
  });
}

// GET /admin/stats: every headline number on the Overview tab, in one D1 round trip.
// Users come from the authors table (one row per account that has ever signed in); online, active
// and guest figures come from presence (see above); notes are published_notes, i.e. signed-in
// publishers only (anonymous pages have no row to count).
// The scans below grow with the presence table (one row per guest device), so the result is cached
// per isolate for a short while; the admin Refresh button can be up to STATS_TTL_MS behind.
const STATS_TTL_MS = 60 * 1000;
let statsCache = null;
async function handleAdminStats(env, request) {
  const g = await adminGate(env, request); if (g) return g;
  if (statsCache && Date.now() - statsCache.at < STATS_TTL_MS) return json(statsCache.body);
  await ensurePresence(env);
  const now = Date.now(), DAY = 24 * 60 * 60 * 1000;
  const on = now - ONLINE_WINDOW_MS, d1 = now - DAY, d7 = now - 7 * DAY, d30 = now - 30 * DAY;
  const q = (sql, ...b) => env.ADS_DB.prepare(sql).bind(...b);
  const r = await env.ADS_DB.batch([
    q('SELECT COUNT(*) AS t, COALESCE(SUM(created_at >= ?), 0) AS n1, COALESCE(SUM(created_at >= ?), 0) AS n7, COALESCE(SUM(created_at >= ?), 0) AS n30 FROM authors', d1, d7, d30),
    q('SELECT kind, COUNT(*) AS t, COALESCE(SUM(last_seen >= ?), 0) AS o, COALESCE(SUM(last_seen >= ?), 0) AS a1, COALESCE(SUM(last_seen >= ?), 0) AS a7, MIN(first_seen) AS since FROM presence GROUP BY kind', on, d1, d7),
    q('SELECT COUNT(*) AS t, COALESCE(SUM(created_at >= ?), 0) AS n1, COALESCE(SUM(created_at >= ?), 0) AS n7, COUNT(DISTINCT author_sub) AS pubs FROM published_notes', d1, d7),
    q('SELECT COUNT(*) AS t FROM stories'),
    q('SELECT COUNT(*) AS t FROM likes'),
    q('SELECT COUNT(*) AS t FROM subscriptions'),
    q('SELECT status, COUNT(*) AS t, COALESCE(SUM(views_used), 0) AS vu FROM ads GROUP BY status')
  ]);
  const first = (i) => (r[i].results && r[i].results[0]) || {};
  const pres = {};
  (r[1].results || []).forEach((x) => { pres[x.kind] = x; });
  const pu = pres.u || {}, pg = pres.g || {};
  const ads = {};
  (r[6].results || []).forEach((x) => { ads[x.status] = x; });
  const since = [pu.since, pg.since].filter(Boolean);
  const u = first(0), n = first(2);
  const body = {
    stats: {
      users: u.t || 0, usersNew1d: u.n1 || 0, usersNew7d: u.n7 || 0, usersNew30d: u.n30 || 0,
      usersOnline: pu.o || 0, usersActive24h: pu.a1 || 0, usersActive7d: pu.a7 || 0,
      guests: pg.t || 0, guestsOnline: pg.o || 0, guestsActive24h: pg.a1 || 0, guestsActive7d: pg.a7 || 0,
      notes: n.t || 0, notesNew1d: n.n1 || 0, notesNew7d: n.n7 || 0, publishers: n.pubs || 0,
      stories: first(3).t || 0, likes: first(4).t || 0, subscriptions: first(5).t || 0,
      adsActive: (ads.active || {}).t || 0, adsPaused: (ads.paused || {}).t || 0,
      adsExhausted: (ads.exhausted || {}).t || 0, adsUnpublished: (ads.unpublished || {}).t || 0,
      adViewsUsed: Object.values(ads).reduce((sum, x) => sum + (x.vu || 0), 0)
    },
    onlineWindowMin: ONLINE_WINDOW_MS / 60000,
    trackingSince: since.length ? Math.min(...since) : null,
    at: now
  };
  statsCache = { at: now, body };
  return json(body);
}

/* ---------------- Admin trends: growth and decline over time ---------------- */
// GET /admin/trends?bucket=day|week|month|year&from=<ms>&to=<ms>&off=<ms>: per-bucket counts for every
// headline metric between from and to (the page asks for two windows at once so it can show the change
// against the previous one), the count before `from` (so running totals can start at the right number),
// reports split by reason, and all-time report totals. `off` is the admin's UTC offset in ms so days,
// weeks (Monday start), months and years line up with their own calendar. Everything except activity
// comes straight from created_at columns, so history is complete; totals only count rows that still exist.
const TREND_MAX_SPAN_MS = 70 * 366 * 86400000;
// Beta: trends ignore everything before this moment (30 Sep 2026 UTC). Move it earlier to bring older data back.
const TREND_EPOCH = Date.UTC(2026, 8, 30);
const TREND_METRICS = [
  ['signups', 'authors', 'created_at', ''],
  ['notes', 'published_notes', 'created_at', ''],
  ['stories', 'stories', 'created_at', ''],
  ['likes', 'likes', 'created_at', ''],
  ['subs', 'subscriptions', 'created_at', ''],
  ['ads', 'ads', 'created_at', ''],
  ['reports', 'report_index', 'reported_at', ''],
  ['strikes', 'alerts', 'created_at', STRIKE_SQL],
  ['alerts', 'alerts', 'created_at', '']
];
let trendReady = null;
function ensureTrendTables(env) {
  if (!trendReady) {
    trendReady = (async () => {
      await Promise.all([ensureAlerts(env), ensureReportIndex(env), ensureActivity(env)].map((p) => p.catch(() => null)));
      const ix = [
        'CREATE INDEX IF NOT EXISTS trend_likes_created ON likes (created_at)',
        'CREATE INDEX IF NOT EXISTS trend_subs_created ON subscriptions (created_at)',
        'CREATE INDEX IF NOT EXISTS trend_stories_created ON stories (created_at)',
        'CREATE INDEX IF NOT EXISTS trend_alerts_created ON alerts (created_at)',
        'CREATE INDEX IF NOT EXISTS trend_reports_at ON report_index (reported_at)'
      ];
      await Promise.all(ix.map((sql) => env.ADS_DB.prepare(sql).run().catch(() => null)));
    })().catch((e) => { trendReady = null; throw e; });
  }
  return trendReady;
}
// SQL for the bucket a timestamp column falls in. The first bound parameter is the UTC offset.
// Weeks are numbered from the Monday on/before 1970-01-01 so the page can derive the same key.
function trendKeySql(bucket, col) {
  const t = '(' + col + ' + CAST(? AS INTEGER))';
  if (bucket === 'day') return "strftime('%Y-%m-%d', " + t + " / 1000, 'unixepoch')";
  if (bucket === 'month') return "strftime('%Y-%m', " + t + " / 1000, 'unixepoch')";
  if (bucket === 'year') return "strftime('%Y', " + t + " / 1000, 'unixepoch')";
  return 'CAST((' + t + ' / 86400000 + 3) / 7 AS INTEGER)';
}
async function handleAdminTrends(env, request, url) {
  const g = await adminGate(env, request); if (g) return g;
  const sp = url.searchParams;
  const bucket = sp.get('bucket') || 'day';
  if (!['day', 'week', 'month', 'year'].includes(bucket)) return textError(400, 'invalid bucket');
  const from = parseInt(sp.get('from') || '', 10), to = parseInt(sp.get('to') || '', 10), off = parseInt(sp.get('off') || '0', 10);
  if (!Number.isFinite(from) || !Number.isFinite(to) || from < 0 || to <= from || to - from > TREND_MAX_SPAN_MS) return textError(400, 'invalid range');
  if (!Number.isFinite(off) || Math.abs(off) > 15 * 3600000) return textError(400, 'invalid offset');
  try {
    await ensureAdminIndexes(env);
    await ensureTrendTables(env);
    const indexed = await reportIndexOn(env);
    const q = (sql, ...b) => env.ADS_DB.prepare(sql).bind(...b);
    const lo = Math.max(from, TREND_EPOCH);
    const names = [], stmts = [];
    const add = (name, st) => { names.push(name); stmts.push(st); };
    for (const [name, table, col, where] of TREND_METRICS) {
      if (name === 'reports' && !indexed) continue;
      const w = where ? ' AND (' + where + ')' : '';
      add(name, q('SELECT ' + trendKeySql(bucket, col) + ' AS k, COUNT(*) AS n FROM ' + table + ' WHERE ' + col + ' >= ? AND ' + col + ' < ?' + w + ' GROUP BY k', off, lo, to));
      add(name + ':before', q('SELECT COUNT(*) AS n FROM ' + table + ' WHERE ' + col + ' >= ? AND ' + col + ' < ?' + w, TREND_EPOCH, lo));
    }
    const dFrom = Math.floor(lo / 86400000), dTo = Math.floor(to / 86400000) + 1;
    for (const [nm, like] of [['active_u', 'u:%'], ['active_g', 'g:%']]) {
      add(nm, q('SELECT ' + trendKeySql(bucket, '(day * 86400000)') + ' AS k, COUNT(DISTINCT id) AS n FROM activity_daily WHERE day >= ? AND day < ? AND id LIKE ? GROUP BY k', off, dFrom, dTo, like));
    }
    add('active_since', q('SELECT MIN(day) AS d FROM activity_daily'));
    if (indexed) {
      add('rbr', q('SELECT ' + trendKeySql(bucket, 'reported_at') + ' AS k, reason AS r, COUNT(*) AS n FROM report_index WHERE reported_at >= ? AND reported_at < ? GROUP BY k, r', off, lo, to));
      add('rtot', q('SELECT reason AS r, COUNT(*) AS t, COALESCE(SUM(dismissed_at IS NULL), 0) AS o FROM report_index WHERE reported_at >= ? GROUP BY r', TREND_EPOCH));
    }
    const res = await env.ADS_DB.batch(stmts);
    const R = {};
    names.forEach((nm, i) => { R[nm] = (res[i] && res[i].results) || []; });
    const series = {}, before = {};
    for (const m of TREND_METRICS) {
      if (!R[m[0]]) continue;
      series[m[0]] = R[m[0]].map((r) => [r.k, r.n]);
      before[m[0]] = ((R[m[0] + ':before'] || [])[0] || {}).n || 0;
    }
    series.active_u = R.active_u.map((r) => [r.k, r.n]);
    series.active_g = R.active_g.map((r) => [r.k, r.n]);
    const since = (R.active_since[0] || {}).d;
    return json({
      bucket, from, to, off, series, before, epoch: TREND_EPOCH,
      activeSince: since == null ? null : since * 86400000,
      reportsIndexed: indexed,
      reportsByReason: indexed ? R.rbr.map((r) => [r.k, r.r, r.n]) : [],
      reportTotals: indexed ? R.rtot.map((r) => ({ reason: r.r, total: r.t, open: r.o })) : null
    });
  } catch (e) {
    console.log('admin trends failed: ' + (e && e.message));
    return textError(500, 'trends failed');
  }
}
// Reports filed against an account: its live pages, every page it was ever alerted about, and its
// published_notes rows. Returns null until the report index has been built.
async function ownerReportStats(env, sub, slugs0) {
  try {
    if (!(await reportIndexOn(env))) return null;
    await ensureReportIndex(env);
    await ensureAlerts(env);
    const set = new Set(slugs0);
    const [a, n] = await env.ADS_DB.batch([
      env.ADS_DB.prepare("SELECT DISTINCT ref FROM alerts WHERE sub = ? AND kind = 'report' AND ref IS NOT NULL AND created_at >= ? LIMIT 500").bind(sub, TREND_EPOCH),
      env.ADS_DB.prepare('SELECT slug FROM published_notes WHERE author_sub = ? LIMIT 500').bind(sub)
    ]);
    ((a && a.results) || []).forEach((r) => { const s = String(r.ref).split(':')[0]; if (SLUG_RE.test(s)) set.add(s); });
    ((n && n.results) || []).forEach((r) => { if (SLUG_RE.test(r.slug)) set.add(r.slug); });
    const slugs = [...set].slice(0, 400);
    const out = { total: 0, open: 0, pages: slugs.length, byReason: {} };
    if (!slugs.length) return out;
    const stmts = [];
    for (let i = 0; i < slugs.length; i += 80) {
      const chunk = slugs.slice(i, i + 80);
      stmts.push(env.ADS_DB.prepare('SELECT reason AS r, COUNT(*) AS t, COALESCE(SUM(dismissed_at IS NULL), 0) AS o FROM report_index WHERE reported_at >= ? AND slug IN (' + chunk.map(() => '?').join(',') + ') GROUP BY reason').bind(TREND_EPOCH, ...chunk));
    }
    const res = await env.ADS_DB.batch(stmts);
    for (const part of res) {
      for (const r of (part.results || [])) {
        const k = ALERT_REPORT_REASONS[r.r] ? r.r : 'other';
        const cur = out.byReason[k] || (out.byReason[k] = { total: 0, open: 0 });
        cur.total += r.t; cur.open += r.o; out.total += r.t; out.open += r.o;
      }
    }
    return out;
  } catch (e) { console.log('owner report stats failed: ' + (e && e.message)); return null; }
}

// GET /admin/users?cursor=&q=&sort=new|old|active&f=online|active24: accounts, keyset-paginated (no
// OFFSET, so deep pages cost the same as the first). The total is only computed on the first page
// (no cursor); the client keeps it. q matches the start of the account id or author id (emails live
// in KV, so they can't be searched, only shown).
const ADMIN_DIR_PAGE = 30;
// Indexes the admin lists lean on. Created lazily (IF NOT EXISTS) from the handlers that already query
// these tables, and each one is independent and swallowed on failure so a missing table or column can
// never break a request. The NOCASE ones let the case-insensitive prefix LIKE searches use an index.
let adminIndexesReady = null;
function ensureAdminIndexes(env) {
  if (!adminIndexesReady) {
    const ix = [
      'CREATE INDEX IF NOT EXISTS admin_authors_created ON authors (created_at, sub)',
      'CREATE INDEX IF NOT EXISTS admin_authors_sub_nc ON authors (sub COLLATE NOCASE)',
      'CREATE INDEX IF NOT EXISTS admin_authors_aid_nc ON authors (author_id COLLATE NOCASE)',
      'CREATE INDEX IF NOT EXISTS admin_notes_author ON published_notes (author_sub)',
      'CREATE INDEX IF NOT EXISTS admin_notes_created ON published_notes (created_at, slug)',
      'CREATE INDEX IF NOT EXISTS admin_notes_slug_nc ON published_notes (slug COLLATE NOCASE)',
      'CREATE INDEX IF NOT EXISTS admin_ads_created ON ads (created_at, slug)',
      'CREATE INDEX IF NOT EXISTS admin_ads_status_created ON ads (status, created_at, slug)',
      'CREATE INDEX IF NOT EXISTS admin_ads_owner ON ads (owner_sub)',
      'CREATE INDEX IF NOT EXISTS admin_ads_rotation ON ads (status, rotation_order)',
      'CREATE INDEX IF NOT EXISTS admin_viewers_slug ON ad_viewers (slug)'
    ];
    adminIndexesReady = Promise.all(ix.map((sql) => env.ADS_DB.prepare(sql).run().catch(() => null)));
  }
  return adminIndexesReady;
}
// Short-lived per-isolate cache of KV user records for the admin lists, so paging back and forth (or
// reloading) doesn't pay one KV read per row every time.
const ADMIN_USER_TTL_MS = 30 * 1000;
const adminUserCache = new Map();
async function getUserCached(env, sub) {
  const hit = adminUserCache.get(sub), now = Date.now();
  if (hit && now - hit.at < ADMIN_USER_TTL_MS) return hit.u;
  const u = await getUser(env, sub);
  if (adminUserCache.size > 500) adminUserCache.clear();
  adminUserCache.set(sub, { at: now, u });
  return u;
}
// cursor = "<sort key>|<id>"; returns null when malformed so a bad cursor just restarts the list.
function parseAdminCursor(raw) {
  const i = typeof raw === 'string' ? raw.indexOf('|') : -1;
  if (i < 1) return null;
  const key = Number(raw.slice(0, i));
  const id = raw.slice(i + 1).slice(0, 200);
  return Number.isFinite(key) && id ? { key, id } : null;
}
async function handleAdminUsers(env, request, url) {
  const g = await adminGate(env, request); if (g) return g;
  await ensurePresence(env);
  await ensureAdminIndexes(env);
  const sp = url.searchParams, now = Date.now();
  const cur = parseAdminCursor(sp.get('cursor'));
  // Escape (don't strip) LIKE wildcards: author IDs are "a_<32 hex>", so removing '_' made every
  // pasted author ID match nothing.
  const q = (sp.get('q') || '').trim().slice(0, 64).replace(/[%_\\]/g, (c) => '\\' + c);
  const f = sp.get('f'), sort = sp.get('sort');
  const where = [], bind = [];
  if (q) { where.push("(a.sub LIKE ? ESCAPE '\\' OR a.author_id LIKE ? ESCAPE '\\')"); bind.push(q + '%', q + '%'); }
  if (f === 'online') { where.push('p.last_seen >= ?'); bind.push(now - ONLINE_WINDOW_MS); }
  else if (f === 'active24') { where.push('p.last_seen >= ?'); bind.push(now - 24 * 60 * 60 * 1000); }
  const from = " FROM authors a LEFT JOIN presence p ON p.id = 'u:' || a.sub";
  const whereSql = where.length ? ' WHERE ' + where.join(' AND ') : '';
  const asc = sort === 'old';
  const keyExpr = sort === 'active' ? 'COALESCE(p.last_seen, 0)' : 'a.created_at';
  const order = keyExpr + (asc ? ' ASC' : ' DESC') + ', a.sub' + (asc ? ' ASC' : ' DESC');
  const curSql = cur ? (where.length ? ' AND ' : ' WHERE ') + '(' + keyExpr + ', a.sub) ' + (asc ? '>' : '<') + ' (?, ?)' : '';
  const stmts = [
    env.ADS_DB.prepare(
      'SELECT a.sub, a.author_id, a.created_at, p.last_seen, (SELECT COUNT(*) FROM published_notes n WHERE n.author_sub = a.sub) AS notes' +
      from + whereSql + curSql + ' ORDER BY ' + order + ' LIMIT ?'
    ).bind(...bind, ...(cur ? [cur.key, cur.id] : []), ADMIN_DIR_PAGE + 1)
  ];
  if (!cur) stmts.unshift(env.ADS_DB.prepare('SELECT COUNT(*) AS t' + from + whereSql).bind(...bind));
  const res = await env.ADS_DB.batch(stmts);
  const total = cur ? null : res[0].results[0].t;
  const rows = res[res.length - 1].results || [];
  const more = rows.length > ADMIN_DIR_PAGE;
  if (more) rows.pop();
  const last = rows[rows.length - 1];
  const next = more && last ? (sort === 'active' ? (last.last_seen || 0) : last.created_at) + '|' + last.sub : null;
  const users = await Promise.all(rows.map(async (r) => {
    let u = null;
    try { u = await getUserCached(env, r.sub); } catch (e) {}
    return {
      authorId: r.author_id || null,
      email: u ? u.email || null : null, name: u ? u.profileName || null : null, lastSignInAt: u ? u.lastSignInAt || null : null,
      createdAt: r.created_at, lastSeen: r.last_seen || null, notes: r.notes,
      online: !!(r.last_seen && now - r.last_seen < ONLINE_WINDOW_MS),
      suspended: !!(u && u.suspended && !u.pendingDeletionAt), deleting: !!(u && u.pendingDeletionAt)
    };
  }));
  return json({ users, total, next });
}

// GET /admin/notes?cursor=&q=: published notes (signed-in publishers), newest first, keyset-paginated;
// total on the first page only. q matches the start of the slug.
async function handleAdminNotes(env, request, url) {
  const g = await adminGate(env, request); if (g) return g;
  await ensureAdminIndexes(env);
  const sp = url.searchParams;
  const cur = parseAdminCursor(sp.get('cursor'));
  const q = (sp.get('q') || '').toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 48);
  const from = ' FROM published_notes n LEFT JOIN stories s ON s.slug = n.slug';
  const whereSql = q ? ' WHERE n.slug LIKE ?' : '';
  const bind = q ? [q + '%'] : [];
  const curSql = cur ? (q ? ' AND ' : ' WHERE ') + '(n.created_at, n.slug) < (?, ?)' : '';
  const stmts = [
    env.ADS_DB.prepare('SELECT n.slug, n.created_at, s.title, (s.slug IS NOT NULL) AS story' + from + whereSql + curSql + ' ORDER BY n.created_at DESC, n.slug DESC LIMIT ?')
      .bind(...bind, ...(cur ? [cur.key, cur.id] : []), ADMIN_DIR_PAGE + 1)
  ];
  if (!cur) stmts.unshift(env.ADS_DB.prepare('SELECT COUNT(*) AS t' + from + whereSql).bind(...bind));
  const res = await env.ADS_DB.batch(stmts);
  const rows = res[res.length - 1].results || [];
  const more = rows.length > ADMIN_DIR_PAGE;
  if (more) rows.pop();
  const last = rows[rows.length - 1];
  return json({
    notes: rows.map(r => ({ slug: r.slug, title: r.title || null, createdAt: r.created_at, story: !!r.story })),
    total: cur ? null : res[0].results[0].t,
    next: more && last ? last.created_at + '|' + last.slug : null
  });
}

function handleAdminPage() {
  return new Response(ADMIN_PAGE_HTML, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; font-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer'
    }
  });
}

const ADMIN_PAGE_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="robots" content="noindex">
<meta name="color-scheme" content="dark"><meta name="theme-color" content="#0D0F24">
<title>Bluebook Admin</title><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 90 105'%3E%3Crect width='90' height='105' rx='20' fill='%230D0F24'/%3E%3Cg transform='translate(11 13) scale(.75)' fill='none' stroke='%238B9BFF' stroke-width='13'%3E%3Crect x='6' y='28.5' width='54' height='27' rx='6' transform='rotate(55 33 42)'/%3E%3Crect x='30' y='48.5' width='54' height='27' rx='6' transform='rotate(55 57 62)'/%3E%3C/g%3E%3C/svg%3E"><style>
@font-face{font-family:"Bricolage";src:url(data:font/woff2;base64,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) format("woff2");font-weight:400 800;font-style:normal;font-display:swap}
:root{
  --bg:#0D0F24;--s1:#161936;--s2:#1F2347;--s3:#2A2F5E;--well:rgba(6,7,25,.38);
  --line:rgba(150,162,255,.15);--line2:rgba(150,162,255,.28);
  --text:#EEF0FF;--muted:#A3A9DA;--faint:#8188BF;
  --accent:#8B9BFF;--accent2:#B69CFF;--accent-ink:#0D0F24;--accent-bg:rgba(139,155,255,.17);
  --danger:#FF6A86;--danger-bg:rgba(255,106,134,.15);
  --ok:#46E0A8;--ok-bg:rgba(70,224,168,.14);
  --warn:#F7C35B;--warn-bg:rgba(247,195,91,.15);
  --glow:rgba(139,155,255,.20);
  --sev:var(--muted);--sev-bg:var(--s2);
  --halo:0 0 0 0 transparent;
  --lift:inset 0 1px 0 rgba(255,255,255,.06),0 14px 30px -16px rgba(2,3,18,.95);
  --r:20px;
  --dock:calc(78px + env(safe-area-inset-bottom,0px));
  --font:"Bricolage",system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif
}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html{color-scheme:dark}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.45 var(--font);-webkit-font-smoothing:antialiased;overflow-x:hidden}
body[data-alert=csam]{--glow:rgba(255,77,109,.26)}
body[data-auth=out] #app{display:none}
body[data-auth=in] #login{display:none}
button,input,select{font:inherit;color:inherit}
button{cursor:pointer}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.glow{position:fixed;inset:0;z-index:0;pointer-events:none;background:radial-gradient(110% 55% at 50% -12%,var(--glow),transparent 62%)}
.ico{display:inline-grid;place-items:center;width:24px;height:24px;flex:none}
.ico svg{width:100%;height:100%}

/* severity palette: classes only set tokens */
.sev-csam{--sev:#FF4D6D;--sev-bg:rgba(255,77,109,.17)}
.sev-abuse{--sev:#FF9A5C;--sev-bg:rgba(255,154,92,.16)}
.sev-copyright{--sev:#F7C35B;--sev-bg:rgba(247,195,91,.16)}
.sev-spam{--sev:#97A3F0;--sev-bg:rgba(151,163,240,.16)}
.sev-other{--sev:#46D6C8;--sev-bg:rgba(70,214,200,.15)}
.sev-ad{--sev:var(--accent);--sev-bg:var(--accent-bg)}

/* sign in */
.login-in{position:relative;z-index:1;min-height:100vh;min-height:100dvh;display:flex;align-items:center;justify-content:center;padding:28px 24px}
.login-card{width:100%;max-width:380px}
.login-card>*{animation:rise .55s cubic-bezier(.2,.8,.2,1) both;animation-delay:calc(var(--i,0)*70ms)}
.mark{width:64px;height:64px;border-radius:22px;display:grid;place-items:center;margin-bottom:26px;color:var(--accent);background:var(--accent-bg);box-shadow:inset 0 0 0 1px rgba(139,155,255,.32),0 18px 40px -14px rgba(139,155,255,.55)}
.mark .ico{width:30px;height:30px}
.login-card h1{margin:0 0 8px;font-size:40px;line-height:1.05;font-weight:750;letter-spacing:-.03em}
.login-card p{margin:0 0 26px;color:var(--muted);font-size:16px}
.login-card .field{margin-bottom:12px}
.fine{margin-top:16px;font-size:13px;color:var(--faint)}
@keyframes rise{from{opacity:0;transform:translateY(14px)}}

/* app bar */
.bar{--bar-bg:transparent;--bar-line:transparent;--bt:0;position:sticky;top:0;z-index:20;padding-top:env(safe-area-inset-top,0px);background:var(--bar-bg);border-bottom:1px solid var(--bar-line);-webkit-backdrop-filter:blur(18px);backdrop-filter:blur(18px);transition:background .2s,border-color .2s}
.bar[data-solid]{--bar-bg:rgba(13,15,36,.8);--bar-line:var(--line);--bt:1}
.bar-in{max-width:720px;margin:0 auto;height:56px;display:flex;align-items:center;gap:2px;padding:0 10px 0 8px}
.back{align-items:center;gap:0;height:40px;padding:0 12px 0 4px;border:0;border-radius:12px;background:none;color:var(--accent);font-size:16px;font-weight:600}
.back:not([hidden]){display:inline-flex}
.back:active{background:var(--accent-bg)}
.btitle{flex:1;min-width:0;padding:0 8px;font-size:17px;font-weight:650;letter-spacing:-.01em;opacity:var(--bt);transition:opacity .18s;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.icon-btn{width:42px;height:42px;place-items:center;border:0;border-radius:14px;background:none;color:var(--text)}
.icon-btn:not([hidden]){display:grid}
.icon-btn:active{background:var(--s2)}
.icon-btn.spin .ico{animation:spin .8s linear infinite}

main{position:relative;z-index:1;max-width:720px;margin:0 auto;padding:2px 16px calc(112px + env(safe-area-inset-bottom,0px))}
.hero{padding:6px 2px 18px}
.hero h1{margin:0;font-size:34px;line-height:1.08;font-weight:750;letter-spacing:-.03em}
.hero p{margin:6px 0 0;color:var(--muted);font-size:15px;word-break:break-word}
.hero p:empty{display:none}
.brand{display:flex;align-items:center;gap:8px;margin:0 0 10px;font-size:13px;font-weight:650;letter-spacing:.06em;text-transform:uppercase;color:var(--accent)}
.brand .ico{width:16px;height:18px}
.pnl:not(.on){display:none}
.pnl.on{animation:fade .22s ease both}
@keyframes fade{from{opacity:0;transform:translateY(6px)}}

/* controls */
.btn{--bg:var(--s2);--fg:var(--text);--bd:var(--line2);appearance:none;-webkit-appearance:none;align-items:center;justify-content:center;gap:7px;min-height:44px;padding:0 16px;border-radius:14px;border:1px solid var(--bd);background:var(--bg);color:var(--fg);font-size:14.5px;font-weight:650;letter-spacing:-.005em;line-height:1;text-decoration:none;box-shadow:inset 0 1px 0 rgba(255,255,255,.07);transition:transform .12s,filter .15s}
.btn:active{transform:scale(.97);filter:brightness(1.14)}
.btn:disabled{opacity:.5;cursor:default}
.btn.wait::before{content:'';flex:none;width:13px;height:13px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:spin .8s linear infinite}
.btn.busy::before{content:"";width:14px;height:14px;border-radius:50%;border:2px solid currentColor;border-right-color:transparent;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.btn.primary{--bg:linear-gradient(180deg,#A0AEFF,#7F90FF);--fg:var(--accent-ink);--bd:transparent}
.btn.danger{--bg:var(--danger-bg);--fg:var(--danger);--bd:rgba(255,106,134,.36)}
.btn.destroy{--bg:linear-gradient(180deg,#F25673,#DB3A58);--fg:#fff;--bd:transparent}
.btn.quiet{--bg:transparent;--bd:var(--line)}
.btn.sm{min-height:38px;padding:0 13px;font-size:13.5px;border-radius:12px}
.btn:not([hidden]){display:inline-flex}
.btn.block{width:100%}
.field{width:100%;min-height:50px;padding:0 16px;border-radius:14px;border:1px solid var(--line2);background:var(--well);color:var(--text)}
.field::placeholder{color:var(--faint)}
.field:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-bg)}
.search{display:flex;gap:8px;margin-bottom:12px}
.field-wrap{position:relative;flex:1;min-width:0}
.field-wrap .ico{position:absolute;left:15px;top:15px;width:20px;height:20px;color:var(--muted);pointer-events:none}
.field-wrap .field{padding-left:44px}
.clr{position:relative;flex:1;min-width:0}
.clr>.field.has-clr,.field-wrap>.field.has-clr{padding-right:46px}
.clr-x{position:absolute;right:5.25px;top:50%;width:40px;height:40px;margin:-20px 0 0;padding:0;border:0;background:none;color:var(--muted);display:none;place-items:center;border-radius:50%}
.clr-x.on{display:grid}
.field-wrap .clr-x{right:6.5px}
.clr-x svg{width:22px;height:22px;display:block;pointer-events:none}
.clr-x:active{color:var(--text)}
.login-card .clr{margin-bottom:12px;animation:rise .55s cubic-bezier(.2,.8,.2,1) both;animation-delay:calc(var(--i,0)*70ms)}
.login-card .clr .field{margin-bottom:0}
.sheet-field .clr{display:block}

.filters{gap:8px;overflow-x:auto;margin:0 -16px 10px;padding:4px 16px 6px;scrollbar-width:none}
.filters:not([hidden]){display:flex}
.filters::-webkit-scrollbar{display:none}
.filters,.qkeys,.recent{-webkit-mask-image:linear-gradient(90deg,transparent 0,#000 var(--fl,0px),#000 calc(100% - var(--fr,0px)),transparent 100%);mask-image:linear-gradient(90deg,transparent 0,#000 var(--fl,0px),#000 calc(100% - var(--fr,0px)),transparent 100%)}
.sel{position:relative;flex:none}
.sel .pick{display:block;appearance:none;-webkit-appearance:none;height:38px;padding:0 34px 0 14px;border-radius:19px;border:1px solid var(--line2);background:var(--s1);color:var(--text);font-size:14px;font-weight:600;white-space:nowrap}
.ptitle{margin:0 0 12px;font-size:17px;font-weight:700;letter-spacing:-.01em}
.plist{display:grid;gap:6px;margin:0 0 14px}
.popt{display:flex;align-items:center;justify-content:space-between;gap:12px;width:100%;min-height:48px;padding:0 16px;border-radius:14px;border:1px solid var(--line);background:transparent;color:var(--text);font-size:15px;font-weight:600;text-align:left;cursor:pointer}
.popt[aria-selected=true]{border-color:var(--accent);background:var(--accent-bg);color:var(--accent)}
.sel .ico{position:absolute;right:10px;top:10px;width:18px;height:18px;color:var(--muted);pointer-events:none}
.pillck{position:relative;flex:none}
.pillck input{position:absolute;inset:0;width:100%;height:100%;opacity:0;margin:0;cursor:pointer}
.pillck span{--pc:var(--muted);--pb:var(--s1);--pd:var(--line2);display:inline-flex;align-items:center;height:38px;padding:0 14px;border-radius:19px;border:1px solid var(--pd);background:var(--pb);font-size:14px;font-weight:600;color:var(--pc)}
.pillck input:checked+span{--pc:var(--accent);--pb:var(--accent-bg);--pd:rgba(139,155,255,.5)}
.pillck input:focus-visible+span{outline:2px solid var(--accent);outline-offset:2px}

.tog{display:flex;align-items:center;gap:16px;padding:14px 0;border-top:1px solid var(--line)}
.tog-text{flex:1;min-width:0}
.tog-text b{display:block;font-weight:650}
.tog-text small{display:block;margin-top:3px;font-size:13px;line-height:1.4;color:var(--muted)}
.tog input{appearance:none;-webkit-appearance:none;position:relative;flex:none;width:52px;height:31px;margin:0;border-radius:16px;background:var(--s3);transition:background .2s;cursor:pointer}
.tog input::after{content:"";position:absolute;top:3px;left:3px;width:25px;height:25px;border-radius:50%;background:#fff;box-shadow:0 2px 6px rgba(0,0,0,.35);transition:transform .2s}
.tog input:checked{background:var(--accent)}
.tog input:checked::after{transform:translateX(21px)}

/* queue */
.queue{margin:0 0 14px;padding:16px;border-radius:var(--r);border:1px solid var(--line);background:linear-gradient(180deg,rgba(255,255,255,.05),rgba(255,255,255,.015)),var(--s1);box-shadow:var(--lift)}
.queue-t{display:flex;align-items:baseline;justify-content:space-between;margin-bottom:12px;font-size:13px;font-weight:650;color:var(--muted);letter-spacing:.02em;text-transform:uppercase}
.qbar{display:flex;gap:3px;height:12px}
.qbar i{display:block;cursor:pointer;min-width:10px;border-radius:6px;background:var(--sev);box-shadow:0 0 14px -2px var(--sev-bg)}
.qkeys{display:flex;gap:8px;overflow-x:auto;margin:14px -16px -2px;padding:0 16px 2px;scrollbar-width:none}
.qkeys::-webkit-scrollbar{display:none}
.key{--kb:transparent;--kd:var(--line);--kc:var(--muted);display:inline-flex;align-items:center;gap:8px;flex:none;height:36px;padding:0 13px;border-radius:18px;border:1px solid var(--kd);background:var(--kb);color:var(--kc);font-size:14px;font-weight:600;white-space:nowrap}
.key i{width:8px;height:8px;border-radius:50%;background:var(--sev)}
.key b{font-weight:700;color:var(--text)}
.key[aria-pressed=true]{--kb:var(--sev-bg);--kd:var(--sev);--kc:var(--text)}
.key:active{filter:brightness(1.25)}

/* cards */
.card{--edge:var(--line);--rows:0fr;--vis:hidden;--vd:.26s;--rot:0deg;position:relative;margin:0 0 12px;border-radius:var(--r);background:linear-gradient(180deg,rgba(255,255,255,.05),rgba(255,255,255,.015)),var(--s1);border:1px solid var(--edge);box-shadow:var(--lift),var(--halo);overflow:hidden;overflow:clip}
.card.open{--rows:1fr;--vis:visible;--vd:0s;--rot:180deg}
.card.urgent{--edge:rgba(255,77,109,.55);--halo:0 0 0 1px rgba(255,77,109,.16),0 0 42px -10px rgba(255,77,109,.5)}
.card.static{padding:18px}
.card.note{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 16px}
.head{appearance:none;-webkit-appearance:none;display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:12px 14px;align-items:start;width:100%;padding:16px;border:0;background:none;text-align:left;color:inherit}
.head:focus-visible{outline-offset:-3px}
.tile{width:46px;height:46px;border-radius:15px;display:grid;place-items:center;flex:none;color:var(--sev);background:var(--sev-bg);box-shadow:inset 0 0 0 1px rgba(255,255,255,.05)}
.slug{font-size:var(--slug-fs,17px);font-weight:650;letter-spacing:-.015em;line-height:1.25;overflow-wrap:anywhere}
.slug .sl{color:var(--faint);font-weight:500;margin-right:1px}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:var(--cg,9px)}
.wide{--cg:0px;grid-column:1/-1;min-width:0}
.sub{margin-top:4px;font-size:13.5px;color:var(--muted);word-break:break-word}
.trail{display:flex;flex-direction:column;align-items:flex-end;gap:12px;font-size:13px;font-weight:600;color:var(--faint);padding-top:2px}
.chev{transform:rotate(var(--rot));transition:transform .26s;color:var(--muted)}
.body{display:grid;grid-template-rows:var(--rows);transition:grid-template-rows .26s ease}
.inner{min-height:0;overflow:hidden;overflow:clip;visibility:var(--vis);transition:visibility 0s var(--vd)}
.pad{padding:0 16px 16px}
.foot{position:sticky;bottom:calc(var(--dock) + 8px);z-index:2;display:flex;flex-wrap:wrap;gap:8px;padding:12px 16px;background:linear-gradient(var(--well),var(--well)),var(--s1);border-top:1px solid var(--line);box-shadow:0 -14px 16px -14px rgba(2,3,18,.85)}
.foot:empty{display:none}
.foot .btn{flex:1 1 auto}
.static>.foot{margin:18px -18px -18px}
.tools{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
.count{position:absolute;left:0;bottom:0;width:100%;height:3px;background:var(--warn);transform-origin:left;animation:drain 8s linear forwards}
@keyframes drain{to{transform:scaleX(0)}}

.chip{--c:var(--muted);--cb:var(--s2);display:inline-flex;align-items:center;gap:6px;height:26px;padding:0 10px;border-radius:13px;font-size:12.5px;font-weight:650;color:var(--c);background:var(--cb);white-space:nowrap}
.chip.by-sev{--c:var(--sev);--cb:var(--sev-bg)}
.chip.good{--c:var(--ok);--cb:var(--ok-bg)}
.chip.bad{--c:var(--danger);--cb:var(--danger-bg)}
.chip.warn{--c:var(--warn);--cb:var(--warn-bg)}
.chip.st::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}

.rep{padding:12px 14px;border-radius:14px;background:var(--well);margin:0 0 8px}
.rep-top{display:flex;align-items:center;flex-wrap:wrap;gap:8px;font-size:13px;color:var(--muted)}
.rep .d{margin:9px 0 0;white-space:pre-wrap;word-break:break-word}
.rep .d.none{color:var(--faint)}
.rep .was{margin-top:7px;font-size:13px;color:var(--faint)}
.meter{height:8px;border-radius:4px;background:var(--well);margin-top:14px;overflow:hidden}
.meter i{display:block;height:100%;border-radius:4px;background:linear-gradient(90deg,var(--accent),var(--accent2))}
.meter-l{display:flex;justify-content:space-between;margin-top:8px;font-size:13px;color:var(--muted);font-variant-numeric:tabular-nums}

.lk-head{--slug-fs:21px;display:flex;align-items:center;gap:14px}
.lk-head.compact{--slug-fs:17px}
.lk-head>div{min-width:0}
.kvs{margin-top:14px;padding:2px 14px;border-radius:14px;background:var(--well)}
.kv{display:grid;grid-template-columns:112px minmax(0,1fr);gap:12px;align-items:center;padding:11px 0;border-top:1px solid var(--line);font-size:14.5px;font-variant-numeric:tabular-nums}
.kv:first-child{border-top:0}
.kv b{font-weight:500;font-size:13px;color:var(--muted)}
.kv span{word-break:break-word}
.media{display:flex;flex-wrap:wrap;gap:8px;margin-top:4px}
.mtile{appearance:none;-webkit-appearance:none;display:grid;place-items:center;align-content:center;gap:2px;width:96px;height:96px;padding:8px;border:1px dashed var(--line2);border-radius:14px;background:var(--well);color:var(--muted);font:inherit;font-size:13px;font-weight:600;text-align:center;overflow:hidden}
.mtile:active{background:var(--s2)}
.mtile small{font-size:11.5px;font-weight:500}
.mtile.loaded{padding:0;border-style:solid}
.mtile.round{border-radius:50%}
.mtile img{width:100%;height:100%;object-fit:cover;display:block}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:16px}
.stat{padding:12px 6px 11px;border-radius:14px;background:var(--well);text-align:center}
.stat b{display:block;font-size:24px;line-height:1.1;font-weight:750;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.stat span{display:block;margin-top:3px;font-size:12.5px;color:var(--muted);font-weight:550}
.sec-t{margin:18px 2px 8px;font-size:13px;font-weight:650;letter-spacing:.02em;text-transform:uppercase;color:var(--muted)}
.sec-t:empty{display:none}
.tr-card{padding:14px 14px 16px}
.tr-card .filters{margin:0 -14px 8px;padding:2px 14px 4px}
#trbk{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;overflow:visible;margin:0 0 10px;padding:2px 0 4px}
#trbk .key{width:100%;justify-content:center;padding:0 4px}
.tr-nav{display:flex;align-items:center;gap:8px;margin:4px 0 8px}
.tr-btn{width:40px;height:40px;flex:none;border:0;border-radius:12px;background:var(--well);color:var(--text);display:grid;place-items:center}
.tr-btn:active{background:var(--s2)}
.tr-btn[aria-disabled=true]{opacity:.3}
.tr-btn.flip .ico{transform:scaleX(-1)}
.tr-rg{flex:1;min-width:0;text-align:center;font-size:15px;font-weight:650;line-height:1.25}
.tr-rg small{display:block;margin-top:2px;font-size:12px;font-weight:500;color:var(--muted)}
.tr-nav2{display:flex;align-items:center;gap:8px;margin:0 0 10px}
.tr-date{position:relative;flex:1;min-width:0;height:40px;padding:0 12px;color-scheme:dark;display:flex;align-items:center;text-align:left;-webkit-appearance:none;appearance:none}
.tr-date::-webkit-date-and-time-value{text-align:left;margin:0;min-height:0}
.tr-date::-webkit-datetime-edit{padding:0}
.tr-date::-webkit-datetime-edit-fields-wrapper{padding:0}
.tr-date::-webkit-calendar-picker-indicator{position:absolute;top:0;left:0;width:100%;height:100%;margin:0;padding:0;opacity:0;cursor:pointer}
.tr-nav2 .btn{height:40px;flex:none}
.tr-win{display:flex;align-items:center;gap:8px;margin:0 0 10px;font-size:13px;color:var(--muted)}
.tr-win span{flex:none}
.tr-win .filters{flex:1;min-width:0;margin:0;padding:0}
.tr-win .key{height:32px;padding:0 12px;font-size:13px}
.tr-head{display:flex;align-items:baseline;flex-wrap:wrap;gap:4px 10px;margin:8px 2px 0}
.tr-head b{font-size:32px;line-height:1.1;font-weight:750;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.tr-dl{font-size:13.5px;font-weight:650;white-space:nowrap}
.tr-dl.up{color:var(--ok)}.tr-dl.dn{color:var(--danger)}.tr-dl.fl{color:var(--muted)}
.tr-sub{margin:2px 2px 6px;font-size:13px;color:var(--muted)}
.tr-chart{position:relative;margin:0 -4px;min-height:60px;transition:opacity .15s}
.tr-chart.busy{opacity:.45}
.tr-chart svg{display:block;width:100%;height:auto;touch-action:pan-y;user-select:none;-webkit-user-select:none}
.tr-g{stroke:var(--line);stroke-width:1}
.tr-ax{fill:var(--faint);font-size:10px;font-family:var(--font)}
.tr-cur{stroke:var(--line2);stroke-width:1;stroke-dasharray:3 3}
.tr-b{transition:opacity .12s,filter .12s}
.tr-chart svg.sel .tr-b{opacity:.35}
.tr-chart svg.sel .tr-b.on{opacity:1;filter:brightness(1.4) saturate(1.15)}
.tr-pt{stroke:var(--s3);stroke-width:2;pointer-events:none}
#trval,.stat b,.tr-v,.tr-rt b{white-space:nowrap}
.tr-tip{display:none;position:absolute;top:0;z-index:3;min-width:120px;max-width:70%;padding:8px 10px;border-radius:12px;background:var(--s3);border:1px solid var(--line2);box-shadow:0 10px 24px -10px rgba(2,3,18,.9);font-size:12.5px;line-height:1.4;pointer-events:none}
.tr-tip b{font-weight:700}
.tr-tip div{display:flex;align-items:center;gap:6px;white-space:nowrap}
.tr-tip i{width:8px;height:8px;border-radius:50%;flex:none}
.tr-msg{padding:22px 8px;text-align:center;color:var(--muted);font-size:14px}
.tr-leg{display:flex;flex-wrap:wrap;gap:6px 12px;margin:6px 2px 0}
.tr-leg:empty{display:none}
.tr-leg span{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;color:var(--muted)}
.tr-leg i{width:8px;height:8px;border-radius:50%}
.tr-t{font-size:15.5px;font-weight:650}
.tr-sp{display:block;width:72px;height:24px}
.tr-sp svg{display:block;width:72px;height:24px}
.tr-v{font-size:16px;font-weight:750;font-variant-numeric:tabular-nums;min-width:38px;text-align:right}
.tr-rr{padding:12px 14px;margin:0 0 8px;border-radius:14px;background:var(--well)}
.tr-rt{display:flex;align-items:center;justify-content:space-between;gap:10px}
.tr-rn{display:inline-flex;align-items:center;gap:8px;font-size:15px;font-weight:650}
.tr-rn i{width:9px;height:9px;border-radius:50%;background:var(--sev)}
.tr-rt b{font-size:18px;font-weight:750;font-variant-numeric:tabular-nums}
.tr-rr small{display:block;margin-top:3px;font-size:13px;color:var(--muted)}
.tr-bar{height:7px;margin-top:8px;border-radius:4px;background:var(--s2);overflow:hidden}
.tr-bar i{display:block;height:100%;border-radius:4px;background:var(--sev)}
.amsg{font-size:14.5px;line-height:1.4;white-space:pre-wrap;overflow-wrap:anywhere}
.pgrow{--slug-fs:15.5px;appearance:none;-webkit-appearance:none;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:12px;align-items:center;width:100%;padding:12px 14px;margin:0 0 8px;border:0;border-radius:14px;background:var(--well);text-align:left;color:inherit}
.pgrow:active{background:var(--s2)}
.pgrow.stack{grid-template-columns:minmax(0,1fr);gap:8px;align-items:start}
.pgrow.stack .pm{justify-content:flex-start}
.pgrow small{display:block;margin-top:3px;font-size:13px;color:var(--muted);overflow-wrap:anywhere}
.pgrow small.aid{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;color:var(--faint)}
.pgrow .pm{display:flex;align-items:center;gap:6px;flex-wrap:wrap;justify-content:flex-end}
.pgrow .lk{display:inline-flex;align-items:center;gap:4px;font-size:13px;line-height:1;font-weight:650;color:var(--muted);font-variant-numeric:tabular-nums}
.pgrow .lk .ico{width:16px;height:16px;flex:none;display:block}
.pgrow .lk .ico svg{display:block}
.pgrow .lk .n{display:block;line-height:1}
@supports (text-box:trim-both cap alphabetic){.pgrow .lk .n{text-box:trim-both cap alphabetic}}

.snaps{margin-top:14px;padding:2px 14px;border-radius:14px;background:var(--well)}
.snap-row{padding:12px 0;border-top:1px solid var(--line)}
.snap-row:first-child{border-top:0}
.snap-line{display:flex;flex-wrap:wrap;align-items:center;gap:8px}
.snap-line .when{font-size:14.5px;font-weight:600;margin-right:auto}
.snap-meta{margin:7px 0 9px;font-size:12px;color:var(--faint);word-break:break-all}
.snap-none{padding:14px 0;color:var(--muted)}
.snap-frame{width:100%;height:60vh;margin-top:10px;border:1px solid var(--line2);border-radius:14px;background:#fff}

.recent{display:flex;gap:8px;overflow-x:auto;margin:0 -16px 14px;padding:0 16px 2px;scrollbar-width:none}
.recent::-webkit-scrollbar{display:none}
.recent:empty{display:none}
.rc{flex:none;height:34px;padding:0 13px;border-radius:17px;border:1px solid var(--line);background:none;color:var(--muted);font-size:13.5px;font-weight:600}
.rc:active{background:var(--s2)}

.tl{position:relative;padding-left:26px}
.tl::before{content:"";position:absolute;left:7px;top:8px;bottom:8px;width:2px;border-radius:1px;background:var(--line)}
.day{margin:18px 0 10px;font-size:13px;font-weight:650;letter-spacing:.02em;text-transform:uppercase;color:var(--muted)}
.day:first-child{margin-top:4px}
.log{--dot:var(--faint);position:relative;margin:0 0 10px;padding:13px 14px;border-radius:16px;border:1px solid var(--line);background:var(--s1)}
.log::before{content:"";position:absolute;left:-24px;top:17px;width:10px;height:10px;border-radius:50%;background:var(--dot);box-shadow:0 0 0 4px var(--bg)}
.log.bad{--dot:var(--danger)}
.log.good{--dot:var(--ok)}
.log-top{display:flex;align-items:center;justify-content:space-between;gap:8px}
.log-top .ago{font-size:13px;color:var(--faint);font-weight:600}
.log-main{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-top:10px}
.log-main .det{color:var(--muted);font-size:14px;word-break:break-word}
.lnk{appearance:none;-webkit-appearance:none;border:0;background:none;padding:0;color:var(--accent);font-weight:650;font-size:15px}

.empty{text-align:center;padding:52px 20px;color:var(--muted)}
.empty-ico{display:grid;place-items:center;width:64px;height:64px;margin:0 auto 16px;border-radius:22px;background:var(--s1);box-shadow:inset 0 0 0 1px var(--line);color:var(--faint)}
.empty-t{color:var(--text);font-weight:700;font-size:18px;letter-spacing:-.01em}
.empty-s{margin:5px auto 0;max-width:290px;font-size:14.5px}
.skel,.stat.ld b{background:linear-gradient(100deg,var(--s1) 35%,var(--s2) 50%,var(--s1) 65%) 0 0/200% 100%;animation:sweep 1.4s linear infinite}
.skel{height:var(--sh,92px);margin:0 0 12px;border-radius:var(--r);border:1px solid var(--line)}
.skel.row{--sh:64px}
.stat.ld b{width:58%;height:24px;margin:2px auto 0;border-radius:8px;color:transparent}
@keyframes sweep{from{background-position:100% 0}to{background-position:-100% 0}}
.more{margin-top:4px}

.sec-head{display:flex;gap:14px;align-items:flex-start;margin-bottom:14px}
.sec-head .tile{width:42px;height:42px;border-radius:14px}
.card-t{font-weight:700;font-size:17px;letter-spacing:-.01em}
.card-s{margin-top:3px;font-size:14px;color:var(--muted)}

/* floating dock */
.dock{position:fixed;left:0;right:0;bottom:0;z-index:20;padding:0 12px calc(10px + env(safe-area-inset-bottom,0px));pointer-events:none}
.nav{position:relative;pointer-events:auto;max-width:480px;height:68px;margin:0 auto;padding:0 8px;display:grid;grid-template-columns:repeat(6,minmax(0,1fr));border-radius:28px;background:rgba(27,30,66,.8);-webkit-backdrop-filter:blur(22px) saturate(1.4);backdrop-filter:blur(22px) saturate(1.4);border:1px solid var(--line2);box-shadow:0 18px 40px -10px rgba(2,3,18,.85),inset 0 1px 0 rgba(255,255,255,.07)}
.pill{position:absolute;top:0;bottom:0;left:8px;width:calc((100% - 16px) / 6);display:flex;align-items:center;justify-content:center;pointer-events:none;transition:transform .34s cubic-bezier(.3,.9,.3,1)}
.pill::before{content:"";flex:none;width:min(64px,calc(100% - 6px));height:54px;border-radius:20px;background:var(--accent-bg);box-shadow:inset 0 0 0 1px rgba(139,155,255,.3)}
.tab{--tc:var(--muted);min-width:0;position:relative;z-index:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;border:0;background:none;color:var(--tc);font-size:11.5px;font-weight:650}
.tab[aria-current=page]{--tc:var(--accent)}
.ico-wrap{position:relative;display:grid;place-items:center}
.tab .ico{width:24px;height:24px}
.nb{--nbg:var(--accent);--nfg:var(--accent-ink);position:absolute;top:-8px;left:12px;min-width:19px;height:19px;padding:0 5px;border-radius:10px;background:var(--nbg);color:var(--nfg);font-size:11px;font-weight:750;place-items:center;line-height:1;box-shadow:0 0 0 3px rgba(27,30,66,.95)}
.nb:not([hidden]){display:grid}
.nb.hot{--nbg:#FF4D6D;--nfg:#fff}

#msg{--y:10px;--o:0;position:fixed;left:14px;right:14px;bottom:calc(92px + env(safe-area-inset-bottom,0px));z-index:40;max-width:480px;margin:0 auto;padding:13px 16px;border-radius:16px;background:#232853;border:1px solid var(--line2);box-shadow:0 14px 34px rgba(2,3,18,.6);font-size:14.5px;opacity:var(--o);transform:translateY(var(--y));pointer-events:none;transition:opacity .2s,transform .2s}
#msg.show{--o:1;--y:0px;pointer-events:auto}
#msg.err{border-color:rgba(255,106,134,.6);color:#FFD9E0}
#msg .lnk{margin-left:14px}
body[data-auth=out] #msg{bottom:calc(24px + env(safe-area-inset-bottom,0px))}

/* sheets */
.sheet-back{--o:0;--y:36px;position:fixed;inset:0;z-index:60;display:flex;align-items:flex-end;justify-content:center;padding:0 8px calc(8px + env(safe-area-inset-bottom,0px));background:rgba(4,5,20,.64);-webkit-backdrop-filter:blur(6px);backdrop-filter:blur(6px);opacity:var(--o);transition:opacity .22s}
.sheet-back.open{--o:1;--y:0px}
.sheet{display:flex;flex-direction:column;width:100%;max-width:520px;max-height:88vh;max-height:88dvh;padding:10px 22px 22px;border-radius:30px;border:1px solid var(--line2);background:linear-gradient(180deg,rgba(255,255,255,.06),rgba(255,255,255,.02)),var(--s1);box-shadow:0 30px 70px -10px rgba(2,3,18,.9);transform:translateY(var(--y));transition:transform .3s cubic-bezier(.2,.9,.25,1)}
.grab{flex:none;width:38px;height:5px;border-radius:3px;background:var(--s3);margin:0 auto 18px}
.sheet .tile{margin-bottom:14px}
.sheet h2{margin:0;font-size:24px;line-height:1.15;font-weight:750;letter-spacing:-.025em;word-break:break-word}
.sheet-text{margin:8px 0 20px;color:var(--muted);white-space:pre-wrap;font-size:15px}
.sheet-field{display:block;margin:0 0 14px}
.sheet-field span{display:block;margin:0 2px 6px;font-size:13px;font-weight:600;color:var(--muted)}
.sheet-body{flex:1 1 auto;min-height:0;overflow-y:auto;overscroll-behavior:contain}
.sheet-actions{display:grid;gap:10px;flex:none;padding-top:6px}

@media (prefers-reduced-motion:reduce){*,*::before,*::after{transition:none;animation:none}}
</style></head><body data-auth="out">
<div class="glow" aria-hidden="true"></div>

<div id="login">
  <div class="login-in"><div class="login-card">
    <div class="mark" style="--i:0"><span class="ico" data-i="bluebook"></span></div>
    <h1 style="--i:1">Bluebook Admin</h1>
    <p style="--i:2">Sign in with your admin token to review reports and manage pages.</p>
    <input class="field" id="tok" type="password" placeholder="Admin token" autocomplete="off" autocapitalize="off" spellcheck="false" style="--i:3">
    <button class="btn primary block" id="go" style="--i:4">Sign in</button>
    <div class="fine" style="--i:5">The token stays in this tab only and is cleared when the tab closes.</div>
    <div class="fine" style="--i:6">Bluebook by Essential Software</div>
  </div></div>
</div>

<div id="app">
  <header class="bar" id="bar"><div class="bar-in">
    <button class="back" id="back" hidden><span class="ico" data-i="back"></span><span id="backl">Back</span></button>
    <div class="btitle" id="bttl">Reports</div>
    <button class="icon-btn" id="rf" aria-label="Refresh"><span class="ico" data-i="refresh"></span></button>
    <button class="icon-btn" id="so" aria-label="Sign out"><span class="ico" data-i="lock"></span></button>
  </div></header>

  <main>
    <div class="hero"><div class="brand"><span class="ico" data-i="bluebook"></span>Bluebook Admin</div><h1 id="ttl">Reports</h1><p id="sub"></p></div>

    <div id="p-overview" class="pnl">
      <div class="sec-t">Trends</div>
      <div class="card static tr-card" id="trcard">
        <div class="filters" id="trbk">
          <button type="button" class="key sev-ad" data-b="day" aria-pressed="true"><span>Day</span></button>
          <button type="button" class="key sev-ad" data-b="week" aria-pressed="false"><span>Week</span></button>
          <button type="button" class="key sev-ad" data-b="month" aria-pressed="false"><span>Month</span></button>
          <button type="button" class="key sev-ad" data-b="year" aria-pressed="false"><span>Year</span></button>
        </div>
        <div class="tr-nav">
          <button type="button" class="tr-btn" id="trprev" aria-label="Earlier"><span class="ico" data-i="back"></span></button>
          <div class="tr-rg"><span id="trrange">-</span><small id="trcmp"></small></div>
          <button type="button" class="tr-btn flip" id="trnext" aria-label="Later"><span class="ico" data-i="back"></span></button>
        </div>
        <div class="tr-nav2">
          <input class="field tr-date" id="trjump" type="date" aria-label="Jump to date">
          <button type="button" class="btn" id="trnow" hidden>Latest</button>
        </div>
        <div class="filters" id="trmet"></div>
        <div class="tr-win"><span id="trwlab">Show</span><div class="filters" id="trwin"></div></div>
        <div class="filters" id="trmode">
          <button type="button" class="key sev-ad" data-m="flow" aria-pressed="true"><span>Per period</span></button>
          <button type="button" class="key sev-ad" data-m="total" aria-pressed="false"><span>Running total</span></button>
        </div>
        <div class="tr-head"><b id="trval">-</b><span class="tr-dl fl" id="trdl"></span></div>
        <div class="tr-sub" id="trsub"></div>
        <div class="tr-chart" id="trchart"></div>
        <div class="tr-leg" id="trleg"></div>
      </div>
      <div class="sec-t">All metrics, this range vs previous</div>
      <div id="trrows"></div>
      <div class="sec-t">Reports by reason</div>
      <div id="rpbox"></div>
      <div id="ovstats"></div>
      <div class="fine" id="ovnote"></div>
      <div class="sec-t">Directory</div>
      <div class="filters" id="ovseg">
        <button type="button" class="key" data-v="users" aria-pressed="true"><span>Users</span></button>
        <button type="button" class="key" data-v="notes" aria-pressed="false"><span>Notes</span></button>
      </div>
      <div class="search"><div class="field-wrap"><span class="ico" data-i="search"></span><input class="field" id="ovq" placeholder="Search by author ID" autocomplete="off" autocapitalize="off" spellcheck="false"></div></div>
      <div class="filters" id="ovfil">
        <span class="sel"><button type="button" class="pick" id="ovsort" aria-label="Sort" aria-haspopup="listbox" value="new">Newest first</button><span class="ico" data-i="chev"></span></span>
        <span class="sel"><button type="button" class="pick" id="ovfilter" aria-label="Show" aria-haspopup="listbox" value="">All users</button><span class="ico" data-i="chev"></span></span>
      </div>
      <div class="sec-t" id="ovcount"></div>
      <div id="ovlist"></div>
      <button class="btn block more" id="ovmore" hidden>Load more</button>
    </div>

    <div id="p-reports" class="pnl on">
      <section class="queue" id="queue" hidden>
        <div class="queue-t"><span>Queue</span><span id="qn"></span></div>
        <div class="qbar" id="qbar"></div>
        <div class="qkeys" id="qkeys"></div>
      </section>
      <input type="hidden" id="freason" value="">
      <div class="search"><div class="field-wrap"><span class="ico" data-i="search"></span><input class="field" id="fq" placeholder="Filter by slug" autocomplete="off" autocapitalize="off" spellcheck="false"></div></div>
      <div class="filters">
        <span class="sel"><button type="button" class="pick" id="fstatus" aria-label="Status" aria-haspopup="listbox" value="">Any status</button><span class="ico" data-i="chev"></span></span>
        <span class="sel"><button type="button" class="pick" id="fsort" aria-label="Sort" aria-haspopup="listbox" value="new">Newest first</button><span class="ico" data-i="chev"></span></span>
        <label class="pillck"><input type="checkbox" id="fgroup" checked><span>Group by slug</span></label>
        <label class="pillck"><input type="checkbox" id="fdis"><span>Dismissed</span></label>
      </div>
      <div id="list"></div>
      <button class="btn block more" id="more" hidden>Load more</button>
    </div>

    <div id="p-lookup" class="pnl">
      <div class="search">
        <div class="field-wrap"><span class="ico" data-i="search"></span><input class="field" id="lkslug" placeholder="Slug or link" autocomplete="off" autocapitalize="off" spellcheck="false"></div>
        <button class="btn primary" id="lkgo">Look up</button>
      </div>
      <div class="recent" id="lkrec"></div>
      <div id="lkout"></div>
      <div id="lkowner"></div>
    </div>

    <div id="p-ads" class="pnl">
      <div class="search"><div class="field-wrap"><span class="ico" data-i="search"></span><input class="field" id="adq" placeholder="Filter by slug" autocomplete="off" autocapitalize="off" spellcheck="false"></div></div>
      <div class="filters">
        <span class="sel"><button type="button" class="pick" id="adst" aria-label="Ad status" aria-haspopup="listbox" value="">All ads</button><span class="ico" data-i="chev"></span></span>
      </div>
      <div id="adlist"></div>
      <button class="btn block more" id="admore" hidden>Load more</button>
    </div>

    <div id="p-audit" class="pnl">
      <div class="filters" id="aukeys"></div>
      <div class="tl" id="aulist"></div>
      <button class="btn block more" id="aumore" hidden>Load more</button>
    </div>

    <div id="p-tools" class="pnl">
      <div class="card static">
        <div class="sec-head"><span class="tile sev-ad"><span class="ico" data-i="image"></span></span><div><div class="card-t">Snapshot previews</div><div class="card-s">Choose which images load when you view a snapshot.</div></div></div>
        <label class="tog"><span class="tog-text"><b>Embedded images</b><small>Load embedded (data:) images in snapshot previews. Off by default.</small></span><input type="checkbox" id="imgs"></label>
        <label class="tog"><span class="tog-text"><b>External images</b><small>Load external (https) images, fetched through the worker so the image hosts see the worker, not your IP. Off by default.</small></span><input type="checkbox" id="ext"></label>
      </div>
      <div class="card static">
        <div class="sec-head"><span class="tile sev-other"><span class="ico" data-i="unlock"></span></span><div><div class="card-t">Release a slug</div><div class="card-s">Unpublishes without locking, so the slug can be reused right away.</div></div></div>
        <div class="search"><input class="field" id="relslug" placeholder="Slug or link" autocomplete="off" autocapitalize="off" spellcheck="false"></div>
        <button class="btn block" id="relgo">Release slug</button>
      </div>
      <div class="card static">
        <div class="sec-head"><span class="tile sev-csam"><span class="ico" data-i="trash"></span></span><div><div class="card-t">Purge</div><div class="card-s">The same jobs the cron runs: deletes expired unpublished pages, accounts past their deletion window, stale like/follow timestamps, unreferenced backup images, and old presence, alert, activity and report-index records.</div></div></div>
        <button class="btn danger block" id="purgego">Run purge now</button>
      </div>
    </div>
  </main>

  <div class="dock"><nav class="nav" aria-label="Sections">
    <i class="pill" id="pill"></i>
    <button class="tab" data-t="overview"><span class="ico-wrap"><span class="ico" data-i="chart"></span></span>Overview</button>
    <button class="tab" data-t="reports"><span class="ico-wrap"><span class="ico" data-i="reports"></span><span class="nb" id="nb-reports" hidden></span></span>Reports</button>
    <button class="tab" data-t="lookup"><span class="ico-wrap"><span class="ico" data-i="search"></span></span>Lookup</button>
    <button class="tab" data-t="ads"><span class="ico-wrap"><span class="ico" data-i="ads"></span></span>Ads</button>
    <button class="tab" data-t="audit"><span class="ico-wrap"><span class="ico" data-i="audit"></span></span>Audit</button>
    <button class="tab" data-t="tools"><span class="ico-wrap"><span class="ico" data-i="tools"></span></span>Tools</button>
  </nav></div>
</div>

<div id="msg" role="status" aria-live="polite"></div>

<script>
function $(i){return document.getElementById(i)}
var P='fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"';
function svg(b){return '<svg viewBox="0 0 24 24" '+P+'>'+b+'</svg>'}
var ICON={
  back:svg('<path d="m14.5 5.5-6.5 6.5 6.5 6.5"/>'),
  clear:svg('<circle cx="12" cy="12" r="9" fill="currentColor" fill-opacity=".22" stroke="none"/><path d="m9 9 6 6M15 9l-6 6"/>'),
  chev:svg('<path d="m6 9.5 6 6 6-6"/>'),
  refresh:svg('<g transform="translate(12 12) scale(.8) translate(-12 -12)" stroke-width="2.25"><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/><polyline points="23 4 23 10 17 10"/></g>'),
  lock:svg('<rect x="5" y="10.5" width="14" height="10" rx="2.5"/><path d="M8.5 10.5V8a3.5 3.5 0 0 1 7 0v2.5"/>'),
  unlock:svg('<rect x="5" y="10.5" width="14" height="10" rx="2.5"/><path d="M8.5 10.5V8a3.5 3.5 0 0 1 6.6-1.6"/>'),
  bluebook:'<svg viewBox="0 0 90 105" fill="none" stroke="currentColor" stroke-width="13" aria-hidden="true"><rect x="6" y="28.5" width="54" height="27" rx="6" transform="rotate(55 33 42)"/><rect x="30" y="48.5" width="54" height="27" rx="6" transform="rotate(55 57 62)"/></svg>',
  shield:svg('<path d="M12 3.5 5 6v5.5c0 4.2 2.8 7.8 7 9 4.2-1.2 7-4.8 7-9V6l-7-2.5Z"/><path d="m9 12 2 2 4-4"/>'),
  shieldAlert:svg('<path d="M12 3.5 5 6v5.5c0 4.2 2.8 7.8 7 9 4.2-1.2 7-4.8 7-9V6l-7-2.5Z"/><path d="M12 8.5v4"/><path d="M12 15.4v.1"/>'),
  alert:svg('<path d="M12 4.5 3.8 18.5h16.4L12 4.5Z"/><path d="M12 10v4"/><path d="M12 16.6v.1"/>'),
  ban:svg('<circle cx="12" cy="12" r="8.5"/><path d="m6 6 12 12"/>'),
  dots:svg('<circle cx="6.5" cy="12" r="1.3"/><circle cx="12" cy="12" r="1.3"/><circle cx="17.5" cy="12" r="1.3"/>'),
  reports:svg('<path d="M6 20V4"/><path d="M6 4.5h11.5L15 8.5l2.5 4H6"/>'),
  search:svg('<circle cx="10.5" cy="10.5" r="6.5"/><path d="m20 20-4.9-4.9"/>'),
  copy:svg('<rect x="9" y="9" width="11" height="11" rx="2.5"/><path d="M15 9V6.5A2.5 2.5 0 0 0 12.5 4h-6A2.5 2.5 0 0 0 4 6.5v6A2.5 2.5 0 0 0 6.5 15H9"/>'),
  ads:svg('<path d="M4 13.5v-4l10-4.5v13l-10-4.5Z"/><path d="M17.5 9.5a3.5 3.5 0 0 1 0 5"/><path d="m6.5 14.5 1.5 4.5h2.5l-1-3.7"/>'),
  audit:svg('<circle cx="12" cy="12" r="8"/><path d="M12 7.6V12l2.9 1.9"/>'),
  tools:svg('<path d="M4 7h8M17 7h3M4 17h3M12 17h8"/><circle cx="14.5" cy="7" r="2.5"/><circle cx="9.5" cy="17" r="2.5"/>'),
  chart:svg('<path d="M5 20v-9"/><path d="M12 20V4"/><path d="M19 20v-6"/>'),
  check:svg('<circle cx="12" cy="12" r="9"/><path d="m8 12.5 3 3 5-6"/>'),
  heart:svg('<path d="M12 18.9s-7.3-4.4-7.3-9.9A4.2 4.2 0 0 1 12 6.5a4.2 4.2 0 0 1 7.3 2.5c0 5.5-7.3 9.9-7.3 9.9Z"/>'),
  users:svg('<circle cx="9" cy="8.5" r="3.2"/><path d="M3.5 19c.5-3.2 2.8-5 5.5-5s5 1.8 5.5 5"/><path d="M16 5.5a3.2 3.2 0 0 1 0 6"/><path d="M17.5 14.2c1.8.5 3 2.3 3.3 4.8"/>'),
  image:svg('<rect x="4" y="5" width="16" height="14" rx="3"/><circle cx="9" cy="10" r="1.6"/><path d="m5 17 4.5-4.5 3 3L15 13l4 4"/>'),
  trash:svg('<path d="M5 7h14"/><path d="M9.5 7V5h5v2"/><path d="M7 7l.8 12h8.4L17 7"/>'),
  user:svg('<circle cx="12" cy="8.5" r="3.5"/><path d="M5 20c.6-3.6 3.3-5.5 7-5.5s6.4 1.9 7 5.5"/>')
};
function ico(n,c){var s=document.createElement('span');s.className='ico'+(c?' '+c:'');s.innerHTML=ICON[n];return s}
[].forEach.call(document.querySelectorAll('[data-i]'),function(n){n.innerHTML=ICON[n.getAttribute('data-i')]});
/* Clear (x) button for text fields: shows while the field has text, also when code sets .value, and fires 'input' so existing handlers run */
var VALD=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value');
function clearable(i){
  if(!i||i._clr)return;i._clr=1;
  var host=i.parentNode;
  if(!host.classList.contains('field-wrap')){var w=el('div','clr');if(i.hasAttribute('style')){w.setAttribute('style',i.getAttribute('style'));i.removeAttribute('style')}host.insertBefore(w,i);w.appendChild(i);host=w}
  i.classList.add('has-clr');
  var b=document.createElement('button');b.type='button';b.className='clr-x';b.tabIndex=-1;b.setAttribute('aria-label','Clear');b.innerHTML=ICON.clear;
  host.appendChild(b);
  function sync(){b.classList.toggle('on',!!VALD.get.call(i))}
  Object.defineProperty(i,'value',{configurable:true,get:function(){return VALD.get.call(i)},set:function(v){VALD.set.call(i,v);sync()}});
  i.addEventListener('input',sync);
  b.onmousedown=function(e){e.preventDefault()};
  b.onclick=function(){VALD.set.call(i,'');sync();i.dispatchEvent(new Event('input',{bubbles:true}));i.focus()};
  sync()
}
function clearableAll(){['tok','ovq','fq','adq','lkslug','relslug'].forEach(function(id){clearable($(id))})}

/* ---------- Snapshot preview (sandboxed) ---------- */
function toDataUrl(b){return new Promise(function(res){var r=new FileReader();r.onload=function(){res(r.result)};r.onerror=function(){res(null)};r.readAsDataURL(b)})}
var imgCache={},imgBytes=0,IMG_BUDGET=30*1024*1024;
function csp(want,ext){return "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; img-src "+((want||ext)?'data:':"'none'")}
function fetchExt(u){
  if(imgCache[u])return imgCache[u];
  return imgCache[u]=fetch('/admin/img?u='+encodeURIComponent(u),{headers:{'X-Admin-Token':tok}}).then(function(x){return x.ok?x.blob():null}).then(function(b){if(!b||imgBytes+b.size>IMG_BUDGET)return null;imgBytes+=b.size;return toDataUrl(b)}).catch(function(){return null}).then(function(du){if(!du)delete imgCache[u];return du})
}
function buildDoc(t){
  var want=$('imgs').checked,ext=$('ext').checked;
  var head='<!doctype html><meta http-equiv="Content-Security-Policy" content="'+csp(want,ext)+'">';
  var d=new DOMParser().parseFromString(t,'text/html');
  [].slice.call(d.querySelectorAll('meta,link,base,script,iframe,frame,frameset,object,embed,audio,video,source,track')).forEach(function(n){n.remove()});
  var seen={},urls=[];
  [].slice.call(d.querySelectorAll('img')).forEach(function(im){
    var s=(im.getAttribute('src')||'').trim();
    if(s.indexOf('//')===0)s='https:'+s;
    var l=s.toLowerCase();
    im.removeAttribute('srcset');
    if(ext&&l.indexOf('https:')===0){im.removeAttribute('src');if(!seen[s]){seen[s]=[];urls.push(s)}seen[s].push(im)}
    else if(want&&l.indexOf('data:')===0){}
    else im.removeAttribute('src')
  });
  urls=urls.slice(0,40);
  var i=0;
  function worker(){
    if(i>=urls.length)return Promise.resolve();
    var u=urls[i++];
    return fetchExt(u).then(function(du){if(du)seen[u].forEach(function(im){im.setAttribute('src',du)})}).then(worker)
  }
  return Promise.all([worker(),worker(),worker(),worker()]).then(function(){return head+d.documentElement.outerHTML})
}
function setFrame(f,t){var g=f._g=(f._g||0)+1;f._t=t;buildDoc(t).then(function(doc){if(f._g===g)f.srcdoc=doc})}
function refreshFrames(){document.querySelectorAll('iframe').forEach(function(f){if(f._t!=null)setFrame(f,f._t)})}

/* ---------- Core state and helpers ---------- */
var tok=sessionStorage.getItem('adm')||'',next=null,all=[],cur='reports',adCur='',adTotal=0,auNext=null,auAll=[],auFilter='',lkSlug='',lkOwner=false,lkShown='',lkGen=0,navI=(history.state&&history.state.i)||0,navLog=[],sheetH=false,ignorePop=false,openSet={},mt=null,recents=[],curSheet=null,repSub='',fullBusy=false,rIdx=false,rAgg=null,rGen=0,reindexing=false,qT=null;
var TABS=['overview','reports','lookup','ads','audit','tools'];
var TITLES={overview:'Overview',reports:'Reports',lookup:'Lookup',ads:'Ads',audit:'Audit',tools:'Tools'};
var SUBS={overview:'Trends over time, totals and directories',lookup:'Find a page, its owner and history',ads:'Campaigns running on published pages',audit:'Every admin action, newest first',tools:'Previews and maintenance'};
function parseNav(h){
  h=String(h||'');if(h.charAt(0)==='#')h=h.slice(1);if(h.charAt(0)==='/')h=h.slice(1);
  var p=h.split('/'),slug='';
  if(TABS.indexOf(p[0])<0)return null;
  if(p[0]==='lookup'&&p[1]){try{slug=slugFrom(decodeURIComponent(p[1]))}catch(e){slug=''}}
  return{t:p[0],slug:slug,o:(slug&&p[2]==='owner')?1:0}
}
function hashOf(s){return '#'+s.t+(s.t==='lookup'&&s.slug?'/'+encodeURIComponent(s.slug)+(s.o?'/owner':''):'')}
var NAV0=parseNav(location.hash)||parseNav(sessionStorage.getItem('admT'))||{t:'reports',slug:'',o:0};
cur=NAV0.t;lkSlug=NAV0.slug;lkOwner=!!NAV0.o;
try{history.scrollRestoration='manual'}catch(e){}
function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e}
function fmt(t){return t?new Date(t).toLocaleString():'-'}
function num(n){return Number(n||0).toLocaleString()}
/* Shrink a big number's font until it fits its box (long totals). */
function fitNum(e){
  e.style.fontSize='';
  var p=e.parentNode,max=parseFloat(getComputedStyle(e).fontSize),min=Math.max(10,Math.round(max*.45)),w=0,r,cs;
  if(e.id==='trval')w=p.clientWidth-6;
  else if(e.classList.contains('tr-v')){r=e.closest('.pgrow');w=r?r.clientWidth*.3:0}
  else if(e.closest('.tr-rt'))w=p.clientWidth*.5;
  else{cs=getComputedStyle(p);w=p.clientWidth-(parseFloat(cs.paddingLeft)||0)-(parseFloat(cs.paddingRight)||0)-2}
  if(!(w>0))return;
  var sz=max;while(sz>min&&e.scrollWidth>w){sz-=.5;e.style.fontSize=sz+'px'}
  var tx=e.textContent;
  if(e.scrollWidth>w&&/^-?[\\d,]+(\\.\\d+)?$/.test(tx)){
    var n=Math.abs(Number(tx.replace(/,/g,''))),u=[[1e12,'T'],[1e9,'B'],[1e6,'M'],[1e3,'k']],k,sh=null;
    for(k=0;k<u.length;k++)if(n>=u[k][0]){sh=(n/u[k][0]).toFixed(n/u[k][0]>=100?0:n/u[k][0]>=10?1:2).replace(/(\\.\\d*?)0+$/,'$1').replace(/\\.$/,'')+u[k][1];break}
    if(sh){e.setAttribute('data-full',tx);e.title=tx;e.textContent=(tx.charAt(0)==='-'?'-':'')+sh;e.style.fontSize='';
      sz=max;while(sz>min&&e.scrollWidth>w){sz-=.5;e.style.fontSize=sz+'px'}}
  }
}
var fitT=0,fitMO;
function fitAll(){fitT=0;fitMO.disconnect();
  [].forEach.call(document.querySelectorAll('#trval,.stat b,.tr-v,.tr-rt b'),function(e){
    var f=e.getAttribute('data-full');if(f!=null){e.textContent=f;e.removeAttribute('data-full');e.removeAttribute('title')}
    fitNum(e)});
  fitMO.observe(document.body,{childList:true,characterData:true,subtree:true})}
function fitSoon(){if(!fitT)fitT=requestAnimationFrame(fitAll)}
function agoS(t){if(!t)return'-';var s=Math.max(0,(Date.now()-t)/1000);if(s<60)return'now';var m=s/60;if(m<60)return Math.floor(m)+'m';var h=m/60;if(h<24)return Math.floor(h)+'h';var d=h/24;if(d<14)return Math.floor(d)+'d';if(d<60)return Math.floor(d/7)+'w';return Math.floor(d/30)+'mo'}
function ago(t){if(!t)return'-';var s=Math.max(0,(Date.now()-t)/1000);if(s<60)return'just now';var m=s/60;if(m<60)return Math.floor(m)+'m ago';var h=m/60;if(h<24)return Math.floor(h)+'h ago';var d=h/24;if(d<30)return Math.floor(d)+'d ago';return new Date(t).toLocaleDateString()}
function dayLabel(t){var d=new Date(t),n=new Date(),a=new Date(d.getFullYear(),d.getMonth(),d.getDate()),b=new Date(n.getFullYear(),n.getMonth(),n.getDate()),diff=Math.round((b-a)/864e5);if(diff===0)return'Today';if(diff===1)return'Yesterday';return d.toLocaleDateString(undefined,{weekday:'long',month:'short',day:'numeric'})}
function msg(t,k,act){
  var m=$('msg');clearTimeout(mt);
  if(!t){m.className='';m.textContent='';return}
  t=String(t).replace(/[.\\s]+$/,'');t=t.charAt(0).toUpperCase()+t.slice(1);
  k=k||(/fail|error|invalid|denied|too many|not live|enter a slug|enter your|cannot|could not|required|not authorized|turn on/i.test(t)?'err':'ok');
  m.textContent=t;m.className='show '+k;
  if(act){var b=el('button','lnk',act.label);b.type='button';b.onclick=function(e){e.stopPropagation();m.className='';act.fn()};m.appendChild(b)}
  mt=setTimeout(function(){m.className=''},act?act.ms||8000:k==='err'?7000:4000)
}
var inflight=0;
function spin(d){inflight=Math.max(0,inflight+d);$('rf').classList.toggle('spin',inflight>0)}
function api(path,o){o=o||{};var h={'X-Admin-Token':tok};if(o.body)h['Content-Type']='application/json';
  spin(1);
  return fetch(path,{method:o.method||'GET',headers:h,body:o.body?JSON.stringify(o.body):undefined}).then(function(r){return r.json().catch(function(){return{}}).then(function(j){spin(-1);if(r.ok&&o.method&&o.method!=='GET'&&path.indexOf('/admin/reports/reindex')<0)staleViews();return{ok:r.ok,s:r.status,j:j}})},function(e){spin(-1);msg('Network error, check your connection');throw e})}
// A change made here (dismiss, take down, restore, story, owner, ad, NCMEC) leaves the other tabs showing old
// numbers until a reload. Clear what they cached so each one refetches the next time it is opened.
var repStale=false;
function staleViews(){
  ovS.loaded=false;
  if(cur!=='ads'){$('adlist').textContent='';adCur=''}
  auAll=[];auNext=null;$('aulist').textContent='';
  if(cur!=='reports')repStale=true
}
function btn(label,cls,fn){var b=document.createElement('button');b.type='button';b.className='btn'+(cls?' '+cls:'');b.textContent=label;b.onclick=function(){var r=fn(b);if(r&&r.then){b.disabled=true;b.classList.add('wait');var d=function(){b.disabled=false;b.classList.remove('wait')};r.then(d,d)}};return b}
function link(label,href){var a=el('a','btn',label);a.href=href;a.target='_blank';a.rel='noopener';return a}
function chip(text,cls){return el('span','chip'+(cls?' '+cls:''),text)}
function aidRow(c,id){if(!id)return;var d=el('div','kv');d.appendChild(el('b',null,'Author ID'));var v=el('span','aid',id);v.style.cssText='font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;cursor:pointer';v.onclick=function(){try{navigator.clipboard.writeText(id).then(function(){msg('Author ID copied')},function(){msg(id)})}catch(e){msg(id)}};d.appendChild(v);c.appendChild(d)}
function kv(c,k,v){var d=el('div','kv');d.appendChild(el('b',null,k));d.appendChild(el('span',null,v));c.appendChild(d)}
function slugFrom(v){v=(v||'').trim().toLowerCase();var q=v.indexOf('?');if(q>-1)v=v.slice(0,q);var p=v.split('/').filter(Boolean);v=p.length?p[p.length-1]:'';return v.charAt(0)==='@'?v.slice(1):v}
function slugEl(s){var d=el('div','slug');d.appendChild(el('span','sl','/'));d.appendChild(document.createTextNode(s));return d}
function tile(sev,icon){var t=el('span','tile sev-'+sev);t.appendChild(ico(icon));return t}
function empty(title,text,icon){var d=el('div','empty'),w=el('div','empty-ico');w.appendChild(ico(icon||'check'));d.appendChild(w);d.appendChild(el('div','empty-t',title));if(text)d.appendChild(el('div','empty-s',text));return d}
function skel(c,n,k){for(var i=0;i<n;i++)c.appendChild(el('div','skel'+(k?' '+k:'')))}
function moreBusy(b,on){b.disabled=!!on;b.classList.toggle('busy',!!on);if(on){b._t=b.textContent;b.textContent='Loading'}else if(b._t){b.textContent=b._t;b._t=null}}
function unskel(c){[].forEach.call(c.querySelectorAll('.skel'),function(n){n.remove()})}

/* ---------- Tap-to-view stored images (story previews, profile picture) ---------- */
function mediaTile(label,load,round){
  var b=el('button','mtile'+(round?' round':''));b.type='button';
  b.appendChild(el('span',null,'Tap to view'));b.appendChild(el('small',null,label));
  b.onclick=function(){
    if(b._ld)return;b._ld=1;b.firstChild.textContent='Loading';
    load().then(function(du){
      if(!du){b._ld=0;b.firstChild.textContent='Tap to retry';return}
      b.textContent='';b.classList.add('loaded');b.disabled=true;
      var im=document.createElement('img');im.alt=label;im.src=du;b.appendChild(im)
    })
  }
  return b
}
function loadMedia(slug,kind,i){
  return fetch('/admin/media?slug='+encodeURIComponent(slug)+'&kind='+kind+(i!=null?'&i='+i:''),{headers:{'X-Admin-Token':tok}}).then(function(x){return x.ok?x.blob():null}).then(function(b){return b?toDataUrl(b):null}).catch(function(){return null})
}
function storyMedia(slug,imgs){
  var w=el('div','media');
  function add(spec,label){
    if(!spec)return;
    if(spec.r2){w.appendChild(mediaTile(label,function(){return loadMedia(slug,spec.kind,spec.kind==='card'?spec.i:null)}));return}
    w.appendChild(mediaTile(label+' (external)',function(){
      if(!$('ext').checked){msg('Turn on External images in Tools first','err');return Promise.resolve(null)}
      return fetchExt(spec.url)
    }))
  }
  add(imgs.ring,'Ring');
  imgs.cards.forEach(function(x,i){add(x,'Card '+(i+1))});
  return w.children.length?w:null
}

var KNOWN=['csam','abuse','copyright','spam','other'];
var LABEL={csam:'CSAM',abuse:'Abuse',copyright:'Copyright',spam:'Spam',other:'Other'};
var RICON={csam:'shieldAlert',abuse:'alert',copyright:'reports',spam:'ban',other:'dots'};
function sevOf(r){return KNOWN.indexOf(r)<0?'other':r}
function topSev(g){var best='spam',bi=99;g.items.forEach(function(x){var s=sevOf(x.reason),i=KNOWN.indexOf(s);if(i<bi){bi=i;best=s}});return best}
function stChip(s){var m={'live':'good','taken down':'bad','unpublished':'','missing':'','active':'good','paused':'warn','exhausted':''};return chip(s,'st '+(m[s]||''))}
function reasonChip(r,isCsam){var s=isCsam?'csam':sevOf(r);return chip(r,'by-sev sev-'+s)}

/* ---------- Sheets (replace native confirm/prompt) ---------- */
function ask(o){
  return new Promise(function(res){
    if(curSheet)curSheet.done(false,true);
    var prev=document.activeElement,back=el('div','sheet-back'),sh=el('div','sheet');
    sh.setAttribute('role','dialog');sh.setAttribute('aria-modal','true');sh.setAttribute('aria-label',o.title);
    sh.appendChild(el('div','grab'));
    var sb=el('div','sheet-body');sh.appendChild(sb);
    sb.appendChild(tile(o.danger?'csam':'ad',o.danger?'alert':'shield'));
    sb.appendChild(el('h2',null,o.title));
    if(o.text)sb.appendChild(el('div','sheet-text',o.text));
    var inputs=[];
    (o.fields||[]).forEach(function(f){
      var l=el('label','sheet-field');l.appendChild(el('span',null,f.label));
      var i=el('input','field');i.placeholder=f.ph||'';i.autocomplete='off';if(f.max)i.maxLength=f.max;
      l.appendChild(i);sb.appendChild(l);clearable(i);inputs.push(i)
    });
    var acts=el('div','sheet-actions');
    var okb=btn(o.ok||'Confirm',o.danger?'destroy block':'primary block',function(){fin(inputs.length?inputs.map(function(i){return i.value}):true)});
    var cb=btn('Cancel','quiet block',function(){fin(false)});
    acts.appendChild(okb);acts.appendChild(cb);sh.appendChild(acts);
    back.appendChild(sh);document.body.appendChild(back);
    function kd(e){if(e.key==='Escape')fin(false);else if(e.key==='Enter'&&inputs.length&&e.target.tagName==='INPUT')okb.click()}
    function fin(v,keep){
      if(curSheet!==api2)return;
      curSheet=null;document.removeEventListener('keydown',kd);
      back.classList.remove('open');
      setTimeout(function(){back.remove()},240);
      if(prev&&prev.focus)try{prev.focus()}catch(e){}
      sheetClose(keep);
      res(v)
    }
    var api2={done:fin};curSheet=api2;sheetOpen();
    back.onclick=function(e){if(e.target===back)fin(false)};
    document.addEventListener('keydown',kd);
    requestAnimationFrame(function(){back.classList.add('open');(inputs[0]||cb).focus()})
  })
}

var PICKS={ovsort:[['new', 'Newest first'], ['old', 'Oldest first'], ['active', 'Last active']],ovfilter:[['', 'All users'], ['online', 'Online now'], ['active24', 'Active 24h']],fstatus:[['', 'Any status'], ['live', 'live'], ['taken down', 'taken down'], ['unpublished', 'unpublished'], ['missing', 'missing']],fsort:[['new', 'Newest first'], ['most', 'Most reported'], ['old', 'Oldest first']],adst:[['', 'All ads'], ['active', 'Active'], ['paused', 'Paused'], ['exhausted', 'Used up'], ['unpublished', 'Down']]};
function pickSet(id,v){
  var b=$(id),o=PICKS[id].filter(function(x){return x[0]===v})[0]||PICKS[id][0];
  b.value=o[0];b.textContent=o[1]
}
function pick(id,fn){
  if(curSheet)curSheet.done(false,true);
  var b=$(id),back=el('div','sheet-back'),sh=el('div','sheet'),list=el('div','plist');
  sh.setAttribute('role','dialog');sh.setAttribute('aria-modal','true');sh.setAttribute('aria-label',b.getAttribute('aria-label'));
  sh.appendChild(el('div','grab'));
  var sb=el('div','sheet-body');sh.appendChild(sb);
  sb.appendChild(el('div','ptitle',b.getAttribute('aria-label')));
  PICKS[id].forEach(function(o){
    var ob=el('button','popt',o[1]);ob.type='button';ob.setAttribute('role','option');
    ob.setAttribute('aria-selected',o[0]===b.value?'true':'false');
    ob.onclick=function(){var ch=o[0]!==b.value;fin();if(ch){pickSet(id,o[0]);fn()}};
    list.appendChild(ob)
  });
  sb.appendChild(list);
  var acts=el('div','sheet-actions');acts.appendChild(btn('Cancel','quiet block',function(){fin()}));sh.appendChild(acts);
  back.appendChild(sh);document.body.appendChild(back);
  function kd(e){if(e.key==='Escape')fin()}
  function fin(v,keep){
    if(curSheet!==me)return;
    curSheet=null;document.removeEventListener('keydown',kd);
    back.classList.remove('open');setTimeout(function(){back.remove()},240);
    try{b.focus()}catch(e){}
    sheetClose(keep)
  }
  var me={done:fin};curSheet=me;sheetOpen();
  back.onclick=function(e){if(e.target===back)fin()};
  document.addEventListener('keydown',kd);
  requestAnimationFrame(function(){back.classList.add('open')})
}

/* collapsible card */
function mkCard(o){
  var c=el('article','card sev-'+o.sev+(o.urgent?' urgent':'')),h=el('button','head');h.type='button';h.setAttribute('aria-expanded','false');
  h.appendChild(tile(o.sev,o.icon));
  var m=el('div');m.appendChild(slugEl(o.slug));
  if(o.sub)m.appendChild(el('div','sub',o.sub));
  h.appendChild(m);
  var tr=el('span','trail');if(o.trail)tr.appendChild(el('span',null,o.trail));tr.appendChild(ico('chev','chev'));h.appendChild(tr);
  var w=el('div','wide'),cr=el('div','chips');o.chips.forEach(function(x){cr.appendChild(x)});w.appendChild(cr);
  if(o.extra)w.appendChild(o.extra);
  h.appendChild(w);
  var body=el('div','body'),inner=el('div','inner'),pad=el('div','pad'),foot=el('div','foot');
  inner.appendChild(pad);inner.appendChild(foot);body.appendChild(inner);
  function set(v){c.classList.toggle('open',v);h.setAttribute('aria-expanded',v?'true':'false');if(o.key)openSet[o.key]=v}
  h.onclick=function(){set(!c.classList.contains('open'))};
  if(o.key&&openSet[o.key])set(true);
  c.appendChild(h);c.appendChild(body);
  return{c:c,pad:pad,foot:foot}
}

/* ---------- Navigation ---------- */
function state(){return{t:cur,slug:cur==='lookup'?lkSlug:'',o:(cur==='lookup'&&lkSlug&&lkOwner)?1:0}}
function navChrome(){
  var p=navI>0?navLog[navI-1]:null;
  $('back').hidden=navI<=0;
  $('backl').textContent=p?TITLES[p.t]:'Back'
}
function navSave(s){try{sessionStorage.setItem('admT',hashOf(s).slice(1))}catch(e){}}
function navRec(s,push){
  s.i=navI;navLog[navI]=s;navSave(s);
  if(push)history.pushState(s,'',hashOf(s));else history.replaceState(s,'',hashOf(s));
  navChrome()
}
/* Scroll position per history entry. curY is tracked on every scroll event because a screen's content can
   shrink (and the browser clamp the scroll offset) before navPush runs, so window.scrollY may already be wrong. */
var navY={},curY=window.scrollY||0,navRT=0;
window.addEventListener('scroll',function(){curY=window.scrollY},{passive:true});
['touchstart','wheel','keydown'].forEach(function(ev){window.addEventListener(ev,function(){navRT++},{passive:true})});
function navRestore(y){
  var id=++navRT,n=0;window.scrollTo(0,y);
  (function again(){if(id!==navRT||Math.abs(window.scrollY-y)<2||n++>14)return;setTimeout(function(){if(id!==navRT)return;window.scrollTo(0,y);again()},80)})()
}
function navPush(){
  var s=state(),c=navLog[navI];
  if(c&&c.t===s.t&&c.slug===s.slug&&c.o===s.o)return;
  navY[navI]=curY;
  navI++;navLog.length=navI;
  Object.keys(navY).forEach(function(k){if(+k>=navI)delete navY[k]});
  navRec(s,true)
}
function navSync(){navRec(state(),false)}
function applyNav(s,y){
  if(s.t==='lookup'){lkSlug=s.slug||'';lkOwner=!!s.o}
  showTab(s.t);
  if(s.t==='lookup'){
    $('lkslug').value=lkSlug;
    if(!lkSlug){lkShown='';lookupHint();$('lkowner').textContent=''}
    else if(lkShown===lkSlug){if(lkOwner){if(!$('lkowner').firstChild)loadOwner(lkSlug)}else $('lkowner').textContent=''}
    else doLookup(lkSlug,lkOwner)
  }
  if(y!=null)navRestore(y);else window.scrollTo(0,0)
}
/* Sheets take one history entry while open, so the device Back button closes the sheet instead of leaving the page behind it */
function sheetOpen(){if(!sheetH){history.pushState(Object.assign({},history.state||{},{sh:1}),'',location.href);sheetH=true}}
function sheetClose(keep){if(sheetH&&!keep){sheetH=false;ignorePop=true;history.back()}}
window.addEventListener('popstate',function(e){
  if(ignorePop){ignorePop=false;return}
  if(curSheet){sheetH=false;curSheet.done(false);return}
  if(document.body.dataset.auth!=='in')return;
  var s=e.state;
  if(!s||s.t==null){s=parseNav(location.hash);if(!s)return;navI++;navLog.length=navI;applyNav(s);navSync();return}
  navY[navI]=curY;
  navI=s.i||0;navLog[navI]=s;navSave(s);
  applyNav(s,navY[navI]);navChrome()
});
function setSub(){
  var s=cur==='reports'?repSub:(cur==='lookup'&&lkSlug)?'/'+lkSlug:SUBS[cur]||'';
  $('sub').textContent=s
}
function xHint(e){var l=e.scrollLeft,m=e.scrollWidth-e.clientWidth;e.style.setProperty('--fl',l>4?'28px':'0px');e.style.setProperty('--fr',m-l>4?'28px':'0px')}
function xHintAll(){[].forEach.call(document.querySelectorAll('.filters,.qkeys,.recent'),function(e){
  if(!e._xh){e._xh=1;e.addEventListener('scroll',function(){xHint(e)},{passive:true});if(window.MutationObserver)new MutationObserver(function(){requestAnimationFrame(function(){xHint(e)})}).observe(e,{childList:true,subtree:true})}
  xHint(e)})}
window.addEventListener('resize',xHintAll);
function showTab(t){
  cur=t;
  TABS.forEach(function(n){$('p-'+n).classList.toggle('on',n===t)});
  [].forEach.call(document.querySelectorAll('.tab'),function(b){if(b.getAttribute('data-t')===t)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current')});
  $('pill').style.transform='translateX('+(TABS.indexOf(t)*100)+'%)';
  $('ttl').textContent=TITLES[t];$('bttl').textContent=TITLES[t];document.title=TITLES[t]+' - Bluebook Admin';
  navChrome();
  $('rf').hidden=t==='tools';
  setSub();
  if(t==='reports'&&repStale){repStale=false;loadReports(true)}
  if(t==='overview'&&!ovS.loaded){ovS.loaded=true;loadOverview();ovList(true)}
  if(t==='ads'&&!$('adlist').firstChild)loadAds(true);
  if(t==='audit'&&!auAll.length&&!$('aulist').firstChild)loadAudit(true);
  requestAnimationFrame(xHintAll)
}
function goTab(t){showTab(t);navPush();window.scrollTo(0,0)}
function goBack(){if(navI>0)history.back()}
function loggedIn(ok){
  document.body.dataset.auth=ok?'in':'out';
  if(!ok)return;
  showTab(cur);navSync();
  if(cur==='lookup'&&lkSlug){$('lkslug').value=lkSlug;doLookup(lkSlug,lkOwner)}
}
function bad(o){if(o.s===403||o.s===429){sessionStorage.removeItem('adm');loggedIn(false)}msg(o.j.error||(o.s===403?'Not authorized, check your admin token':o.s===429?'Too many attempts, try again shortly':'Request failed ('+o.s+')'))}

/* ---------- Reports ---------- */
function fqv(){return $('fq').value.trim().toLowerCase().replace(/^\\/?@?/,'')}
function repQuery(first){
  var p=[];
  if($('fdis').checked)p.push('dismissed=1');
  if(rIdx){
    var r=$('freason').value,q=fqv(),so=$('fsort').value;
    if(r)p.push('reason='+encodeURIComponent(r));
    if(q)p.push('q='+encodeURIComponent(q));
    if(so&&so!=='new')p.push('sort='+so)
  }
  if(next&&!first)p.push('cursor='+encodeURIComponent(next));
  return p.join('&')
}
function repFilter(){if(rIdx)loadReports(true);else renderAll()}
function startReindex(){
  if(reindexing)return;reindexing=true;msg('Indexing reports for search\u2026');
  (function step(c){
    api('/admin/reports/reindex',{method:'POST',body:{cursor:c}}).then(function(o){
      if(!o.ok){reindexing=false;bad(o);return}
      if(o.j.done){reindexing=false;msg('');loadReports(true);return}
      step(o.j.cursor)
    }).catch(function(){reindexing=false;msg('Network error, check your connection')})
  })('')
}
function loadReports(reset){
  var L=$('list'),g;
  if(reset){g=++rGen;all=[];next=null;L.textContent='';skel(L,3)}else{g=rGen;moreBusy($('more'),true)}
  return api('/admin/reports?'+repQuery()).then(function(o){
    if(g!==rGen)return;
    unskel(L);moreBusy($('more'),false);
    if(!o.ok){bad(o);return}
    sessionStorage.setItem('adm',tok);if(document.body.dataset.auth!=='in'){msg('');loggedIn(true)}
    rIdx=o.j.indexed===true;
    if(o.j.agg||reset)rAgg=o.j.agg||null;
    all=all.concat(o.j.reports);next=o.j.nextCursor;
    $('more').hidden=!next;
    if(o.j.indexed===false)startReindex();
    if(!o.j.reports.length&&next){return loadReports(false)}
    renderAll()
  }).catch(function(){if(g!==rGen)return;unskel(L);moreBusy($('more'),false);msg('Network error, check your connection')})
}
function setBadge(n,hot,exact){var b=$('nb-reports');if(!n){b.hidden=true;return}b.hidden=false;b.textContent=n>99?'99+':String(n)+(next&&!exact?'+':'');b.className='nb'+(hot?' hot':'')}
function hasCsam(g){return g.items.some(function(x){return x.isCsam})}
function renderQueue(base){
  var q=$('queue'),useAgg=!!(rIdx&&rAgg&&!$('fstatus').value);
  q.hidden=useAgg?!rAgg.total:!all.length;if(q.hidden)return;
  var cnt={},order=[],tot=base.length;
  if(useAgg){tot=rAgg.total;Object.keys(rAgg.byReason).forEach(function(k){cnt[k]=rAgg.byReason[k];order.push(k)})}
  else base.forEach(function(r){if(cnt[r.reason]==null){cnt[r.reason]=0;order.push(r.reason)}cnt[r.reason]++});
  order.sort(function(a,b){var x=KNOWN.indexOf(a),y=KNOWN.indexOf(b);if(x<0)x=50;if(y<0)y=50;return x-y||(a<b?-1:1)});
  $('qn').textContent=num(tot)+(!useAgg&&next?'+':'')+(tot===1&&(useAgg||!next)?' report':' reports');
  var bar=$('qbar');bar.textContent='';
  order.forEach(function(r){var s=el('i','sev-'+sevOf(r));s.style.flexGrow=cnt[r];s.onclick=function(){msg(r+': '+cnt[r])};bar.appendChild(s)});
  var keys=$('qkeys');keys.textContent='';
  var sel=$('freason').value;
  function key(v,label,n,sev){
    var b=el('button','key'+(sev?' sev-'+sev:''));b.type='button';b.setAttribute('aria-pressed',sel===v?'true':'false');
    if(sev)b.appendChild(el('i'));
    b.appendChild(el('span',null,label));b.appendChild(el('b',null,String(n)));
    b.onclick=function(){$('freason').value=v;repFilter()};keys.appendChild(b)
  }
  key('','All',tot,'');
  if(sel&&order.indexOf(sel)<0)order.push(sel);
  order.forEach(function(r){key(r,LABEL[r]||r,cnt[r]||0,sevOf(r))})
}
function repBase(){
  var fs=$('fstatus').value,fq=fqv();
  return all.filter(function(r){return(!fs||r.status===fs)&&(!fq||r.slug.indexOf(fq)>=0)})
}
function repGroups(base){
  var fr=$('freason').value,grp=$('fgroup').checked,so=$('fsort').value;
  var items=base.filter(function(r){return!fr||r.reason===fr});
  var groups=[],idx={};
  items.forEach(function(r){var k=grp?r.slug:r.key;if(idx[k]==null){idx[k]=groups.length;groups.push({slug:r.slug,key:k,items:[]})}groups[idx[k]].items.push(r)});
  groups.sort(function(a,b){
    var x=hasCsam(a),y=hasCsam(b);if(x!==y)return x?-1:1;
    var an=a.items[0].reportedAt,bn=b.items[0].reportedAt;
    if(so==='most'&&a.items.length!==b.items.length)return b.items.length-a.items.length;
    if(so==='old')return an-bn;
    return bn-an
  });
  return groups
}
// Subtitle, reason chips and tab badge. Split out of renderAll so a dismiss can refresh them without
// rebuilding the list (which would wipe the Undo note).
function repCounts(groups,base){
  var dis=$('fdis').checked;
  renderQueue(base);
  var n=groups.length,nc=groups.filter(hasCsam).length;
  repSub=n?(num(n)+(n===1?' page ':' pages ')+(dis?'dismissed':'to review')+(nc&&!dis?', '+nc+' with a CSAM report':'')+(next?'. More to load':'')):'';
  if(!dis){var s={},h=false;all.forEach(function(r){s[r.slug]=1;if(r.isCsam)h=true});
    if(rIdx&&rAgg){h=rAgg.csam>0;setBadge(rAgg.pages,h,true)}else setBadge(Object.keys(s).length,h);
    document.body.dataset.alert=h?'csam':''}
  else{setBadge(0);document.body.dataset.alert=''}
  if(cur==='reports')setSub()
}
function repRefresh(){var b=repBase();repCounts(repGroups(b),b)}
// Instant counts: take the dismissed reports off the server totals (rAgg) straight away; syncReportAgg
// then replaces them with the exact figures.
function repAggDrop(removed){
  if(!rIdx||!rAgg)return;
  var left={};all.forEach(function(r){left[r.slug]=1});
  var gone={};removed.forEach(function(r){
    rAgg.total=Math.max(0,rAgg.total-1);
    var k=r.reason||'?';if(rAgg.byReason[k]){rAgg.byReason[k]--;if(rAgg.byReason[k]<=0)delete rAgg.byReason[k]}
    gone[r.slug]=r.isCsam||gone[r.slug]||0
  });
  Object.keys(gone).forEach(function(sl){if(!left[sl]){rAgg.pages=Math.max(0,rAgg.pages-1);if(gone[sl])rAgg.csam=Math.max(0,rAgg.csam-1)}})
}
// Indexed mode shows server-side totals (rAgg); after a dismiss they are fetched again so the badge and
// chips drop straight away.
function syncReportAgg(){
  if(!rIdx)return;var g=rGen;
  api('/admin/reports?'+repQuery(true)).then(function(o){if(g!==rGen||!o.ok||!o.j.agg)return;rAgg=o.j.agg;repRefresh()}).catch(function(){})
}
function renderAll(){
  var fr=$('freason').value,fs=$('fstatus').value,so=$('fsort').value,dis=$('fdis').checked,fq=fqv();
  var base=repBase(),groups=repGroups(base);
  var L=$('list');L.textContent='';groups.forEach(renderGroup);
  var n=groups.length;
  repCounts(groups,base);
  if(!n){
    if(all.length||(rIdx&&(fr||fq)))L.appendChild(empty('Nothing matches','Change the filters above to see more reports.','search'));
    else L.appendChild(empty(dis?'No dismissed reports':'All clear',dis?'Dismissed reports show up here.':'There are no open reports.','check'))
  }
  // Filters, the reason chips and "Most reported" only see what's loaded, so pull the remaining pages
  // (up to 1000 reports) before they apply. Stops if a page fails to load or adds nothing.
  if(next&&!fullBusy&&all.length<1000&&(fs||(!rIdx&&(fr||fq||so==='most')))){
    var n0=all.length;fullBusy=true;
    loadReports(false).then(function(){fullBusy=false;if(next&&all.length>n0)renderAll()})
  }
}
function setSlugStatus(slug,st){all.forEach(function(r){if(r.slug===slug)r.status=st});renderAll()}
function renderGroup(g){
  var first=g.items[0],csam=hasCsam(g),sev=csam?'csam':topSev(g);
  var nc=null;g.items.forEach(function(x){if(x.ncmec&&!nc)nc=x.ncmec});
  var chips=[],seen={};
  g.items.forEach(function(x){if(!seen[x.reason]){seen[x.reason]=1;chips.push(reasonChip(x.reason,x.isCsam))}});
  chips.push(stChip(first.status));
  if(g.items.length>1)chips.push(chip(g.items.length+' reports'));
  if(csam)chips.push(chip(nc?'NCMEC '+new Date(nc.at).toLocaleDateString():'NCMEC not recorded',nc?'good':'bad'));
  var card=mkCard({sev:sev,urgent:csam,icon:RICON[sev],slug:g.slug,chips:chips,sub:'Latest report '+ago(first.reportedAt),trail:agoS(first.reportedAt),key:'rep:'+g.key});
  var pad=card.pad;
  g.items.forEach(function(x){
    var r=el('div','rep'),top=el('div','rep-top');
    top.appendChild(reasonChip(x.reason,x.isCsam));
    top.appendChild(el('span',null,fmt(x.reportedAt)));
    r.appendChild(top);
    r.appendChild(el('div','d'+(x.details?'':' none'),x.details||'(no details)'));
    if(x.dismissedAt)r.appendChild(el('div','was','Dismissed '+fmt(x.dismissedAt)));
    pad.appendChild(r)
  });
  var done=function(st){setSlugStatus(g.slug,st)};
  var tools=el('div','tools');
  tools.appendChild(link('View page','/@'+g.slug));
  tools.appendChild(btn('Lookup',null,function(){openLookup(g.slug)}));
  tools.appendChild(mkSnaps(g.slug,first.status,first.reportedAt,pad,csam,done));
  pad.appendChild(tools);
  var foot=card.foot;
  if(first.status==='live'){foot.appendChild(btn('Take down','destroy',function(){return takedown(g.slug,csam,done)}));if(!csam)foot.appendChild(btn('Release slug',null,function(){return release(g.slug,function(){done('unpublished')})}))}
  if(first.status==='taken down')foot.appendChild(btn('Restore',null,function(){return restore(g.slug,csam,0,done)}));
  if(csam)foot.appendChild(btn(nc?'Add NCMEC record':'Record NCMEC report',null,function(){return recordNcmec(g.slug,function(){all.forEach(function(r){if(r.slug===g.slug)r.ncmec={at:Date.now()}});renderAll()})}));
  if($('fdis').checked)foot.appendChild(btn('Undo dismiss',null,function(b){undismiss(g,b)}));
  else foot.appendChild(btn('Dismiss',null,function(){dismissGroup(g,csam,nc,card.c)}));
  $('list').appendChild(card.c)
}
function sendKeys(path,keys){return Promise.all(keys.map(function(k){return api(path,{method:'POST',body:{key:k}})})).then(function(rs){return rs.every(function(r){return r.ok})})}
function dropKeys(keys){all=all.filter(function(r){return keys.indexOf(r.key)<0})}
function dismissGroup(g,csam,nc,card){
  var keys=g.items.map(function(x){return x.key}),slug=g.slug,removed=g.items.slice();
  if(csam){
    ask({title:'Dismiss /'+slug+'?',text:'CSAM report: only dismiss once the page is handled and NCMEC has been notified.'+(nc?'':'\\n\\nNO NCMEC REPORT IS RECORDED for this page.')+'\\n\\nThe record is hidden but kept for 18 months and can be brought back from Dismissed.',ok:'Dismiss',danger:true}).then(function(ok){
      if(!ok)return;
      sendKeys('/admin/dismiss',keys).then(function(ok2){if(!ok2){msg('Could not dismiss /'+slug);return}dropKeys(keys);repAggDrop(removed);repRefresh();syncReportAgg();var r=el('div','card note');r.appendChild(el('span',null,'Dismissed /'+slug));r.appendChild(btn('Undo',null,function(){sendKeys('/admin/undismiss',keys).then(function(){loadReports(true)})}));card.replaceWith(r)})
    });
    return}
  // Instant: the card and the counts change on tap. The request goes out after a short Undo window,
  // because an ordinary report is deleted for good once dismissed.
  var prevAgg=rAgg?JSON.parse(JSON.stringify(rAgg)):null;
  dropKeys(keys);repAggDrop(removed);renderAll();
  var t=setTimeout(function(){sendKeys('/admin/dismiss',keys).then(function(ok){
    if(ok){syncReportAgg();return}
    msg('Could not dismiss /'+slug);all=all.concat(removed);rAgg=prevAgg;renderAll()
  })},8000);
  msg('Dismissed /'+slug,'ok',{label:'Undo',fn:function(){clearTimeout(t);all=all.concat(removed);rAgg=prevAgg;renderAll();msg('Dismissal undone','ok')}})
}
function undismiss(g,b){
  var keys=g.items.map(function(x){return x.key}),removed=g.items.slice();
  var prevAgg=rAgg?JSON.parse(JSON.stringify(rAgg)):null;
  dropKeys(keys);repAggDrop(removed);renderAll();
  sendKeys('/admin/undismiss',keys).then(function(ok){
    if(ok){syncReportAgg();msg('Report restored to the open list');return}
    msg('Could not restore the report');all=all.concat(removed);rAgg=prevAgg;renderAll()
  })
}

/* ---------- Actions shared by Reports and Lookup ---------- */
var REASON_F={label:'Reason (shown to the user)',ph:'e.g. spam, impersonation, hateful content',max:200};
function reasonOf(v){var r=String(v&&v[0]||'').trim();if(!r)msg('A reason is required');return r}
function takedown(slug,csam,done){
  return ask({title:'Take down /'+slug+'?',text:csam?'CSAM report: the page is preserved under deleted/ for 18 months. You must still report to NCMEC.':'The slug will be permanently locked.',ok:'Take down',danger:true,fields:[REASON_F]}).then(function(v){
    if(!v)return;var reason=reasonOf(v);if(!reason)return;
    return api('/publish/'+encodeURIComponent(slug),{method:'DELETE',body:{adminToken:tok,reason:reason}}).then(function(o){
      if(o.ok){msg('Taken down /'+slug);done('taken down')}else if(o.s===404){msg('Page /'+slug+' is not live');done('missing')}else msg('Could not take down /'+slug+' ('+o.s+')')}).catch(function(){msg('Network error, check your connection')})
  })
}
function release(slug,done){
  if(!slug){msg('Enter a slug or link');return}
  return ask({title:'Release /'+slug+'?',text:'The page goes offline and its likes, story and ad are removed, but the slug is NOT locked: anyone can publish to it again right away. A copy is kept for 30 days.',ok:'Release slug',danger:true}).then(function(ok){
    if(!ok)return;
    return api('/publish/'+encodeURIComponent(slug),{method:'DELETE',body:{adminToken:tok,release:true}}).then(function(o){
      if(o.ok){msg('Released /'+slug+', it can be published again');if(done)done()}
      else if(o.s===404)msg('Page /'+slug+' is not live, nothing to release');
      else msg('Could not release /'+slug+' ('+o.s+')')}).catch(function(){msg('Network error, check your connection')})
  })
}
function restore(slug,csam,ts,done){
  var w=csam?'WARNING: this page was reported as CSAM. Restoring puts it back online. Only continue if you have confirmed the report was mistaken.':'It returns as a plain page (story status and likes are not recovered).';
  if(ts)w+='\\n\\nThe copy from '+fmt(ts)+' will be used.';
  return ask({title:'Restore /'+slug+'?',text:w,ok:'Restore',danger:csam}).then(function(ok){
    if(!ok)return;
    return api('/admin/restore/'+encodeURIComponent(slug)+(ts?'?ts='+ts:''),{method:'POST'}).then(function(o){
      if(o.ok){msg('Restored /'+slug);done('live')}else msg(o.j.error||'Could not restore /'+slug)}).catch(function(){msg('Network error, check your connection')})
  })
}
function recordNcmec(slug,done){
  return ask({title:'Record NCMEC report',text:'For /'+slug+'. Leave the report ID blank if there is none.',ok:'Save record',fields:[{label:'CyberTipline report ID',ph:'Report ID'},{label:'Note',ph:'Optional, up to 200 characters',max:200}]}).then(function(v){
    if(!v)return;
    return api('/admin/ncmec',{method:'POST',body:{slug:slug,reportId:v[0],note:v[1]||''}}).then(function(o){
      if(o.ok){msg('NCMEC report recorded for /'+slug);if(done)done()}else msg(o.j.error||'Could not save the NCMEC record')})
  })
}
function mkView(r,s,row){
  var fr=null;
  var b=btn('View','sm',function(){
    if(fr){fr.remove();fr=null;b.textContent='View';return}
    function open(){
      b.disabled=true;
      fetch('/admin/snapshot/'+encodeURIComponent(r.slug)+'/'+s.ts,{headers:{'X-Admin-Token':tok}}).then(function(x){return x.text().then(function(t){return{ok:x.ok,t:t}})}).then(function(o){
        b.disabled=false;
        if(!o.ok){msg('Could not load the snapshot');return}
        fr=document.createElement('iframe');fr.setAttribute('sandbox','');fr.referrerPolicy='no-referrer';
        fr.className='snap-frame';
        row.appendChild(fr);setFrame(fr,o.t);b.textContent='Hide'
      }).catch(function(){b.disabled=false;msg('Network error, check your connection')})
    }
    if(r.isCsam)ask({title:'Open CSAM snapshot?',text:'This snapshot is from a CSAM report. It opens as text and styling only unless an images toggle is on in Tools.',ok:'Open',danger:true}).then(function(ok){if(ok)open()});
    else open()
  });
  return b
}
function mkSnaps(slug,status,hitTs,card,csam,done){
  var box=null;
  var t=btn('Snapshots',null,function(){
    if(box){box.remove();box=null;return}
    t.disabled=true;
    api('/admin/snapshots/'+encodeURIComponent(slug)).catch(function(){t.disabled=false;return null}).then(function(o){
      if(!o)return;
      t.disabled=false;
      if(!o.ok){msg(o.j.error||'Could not load snapshots');return}
      box=el('div','snaps');
      if(!o.j.snapshots.length)box.appendChild(el('div','snap-none','No snapshots for /'+slug));
      o.j.snapshots.forEach(function(s){
        var d=el('div','snap-row'+(s.ts===hitTs?' hit':'')),line=el('div','snap-line');
        line.appendChild(el('span','when',fmt(s.ts)));
        line.appendChild(chip(s.source));
        if(s.ts===hitTs)line.appendChild(chip('this report','warn'));
        line.appendChild(mkView({slug:slug,isCsam:csam},s,d));
        if(status==='taken down')line.appendChild(btn('Restore this copy','sm',function(){return restore(slug,csam,s.ts,done)}));
        d.appendChild(line);
        var m=el('div','snap-meta');m.appendChild(el('code',null,new Date(s.ts).toISOString()+' / '+s.ts+' / '+Math.round(s.size/1024)+' KB'));
        d.insertBefore(m,line.nextSibling);
        box.appendChild(d)
      });
      card.appendChild(box)
    }).catch(function(){t.disabled=false;msg('Network error, check your connection')})
  });
  return t
}

/* ---------- Lookup and owner ---------- */
function lookupHint(){lkShown='';var o=$('lkout');o.textContent='';o.appendChild(empty('Look up a page','Enter a slug or paste a link to see its status, owner and history.','search'))}
function renderRecents(){
  var r=$('lkrec');r.textContent='';
  recents.forEach(function(s){var b=el('button','rc','/'+s);b.type='button';b.onclick=function(){$('lkslug').value=s;doLookup(s)};r.appendChild(b)})
}
function openLookup(slug){
  lkSlug=slug;lkOwner=false;showTab('lookup');navPush();$('lkslug').value=slug;window.scrollTo(0,0);doLookup(slug)
}
function openOwner(slug){lkOwner=true;navPush();loadOwner(slug)}
function doLookup(v,owner){
  var slug=slugFrom(v);if(!slug){msg('Enter a slug or link');return}
  lkSlug=slug;lkOwner=!!owner;setSub();var g=++lkGen;
  api('/admin/lookup?slug='+encodeURIComponent(slug)).then(function(o){
    if(g!==lkGen)return;
    if(!o.ok){bad(o);return}
    msg('');
    recents=[slug].concat(recents.filter(function(s){return s!==slug})).slice(0,8);renderRecents();
    renderLookup(o.j);navSync();
    if(owner&&o.j.found&&o.j.hasOwner)loadOwner(slug)
  }).catch(function(){msg('Network error, check your connection')})
}
function renderLookup(d){
  var out=$('lkout');out.textContent='';$('lkowner').textContent='';lkShown=d.slug;
  var sev=d.csamHold?'csam':(d.found?(d.status==='live'?'ad':'spam'):'spam');
  var c=el('div','card static sev-'+sev+(d.csamHold?' urgent':''));
  var hd=el('div','lk-head');hd.appendChild(tile(sev,d.csamHold?'shieldAlert':'search'));
  var hm=el('div');hm.appendChild(slugEl(d.slug));
  if(d.found){var cr=el('div','chips');cr.appendChild(stChip(d.status));if(d.csamHold)cr.appendChild(chip('CSAM hold','bad'));hm.appendChild(cr)}
  hd.appendChild(hm);c.appendChild(hd);
  var k=el('div','kvs');c.appendChild(k);
  if(!d.found){kv(k,'Published','never');kv(k,'Reports on file',String(d.reports));out.appendChild(c);return}
  var refresh=function(){doLookup(d.slug)};
  kv(k,'Title',d.title||'-');
  if(d.desc)kv(k,'Description',d.desc);
  if(d.tags&&d.tags.length)kv(k,'Tags',d.tags.join(', '));
  kv(k,'Created',fmt(d.createdAt));kv(k,'Updated',fmt(d.updatedAt));
  if(d.noteCreatedAt)kv(k,'Note written',fmt(d.noteCreatedAt));
  if(d.deletedAt)kv(k,'Went offline',fmt(d.deletedAt));
  kv(k,'Size',d.sizeBytes!=null?Math.round(d.sizeBytes/1024)+' KB':'-');
  kv(k,'Owner',d.hasOwner?(d.ownerEmail||'account missing'):'anonymous (no account)');
  aidRow(k,d.ownerAuthorId);
  kv(k,'Stories',(d.showInStories?'showing':'not showing')+(d.storyBlocked?' (blocked by admin)':''));
  if(d.story)kv(k,'Story',(d.story.title||'untitled')+' ('+fmt(d.story.createdAt)+')');
  kv(k,'Likes',num(d.likes));
  kv(k,'Ad',d.ad?d.ad.status+', '+d.ad.viewsUsed+' of '+d.ad.viewsTotal+' views':'none');
  kv(k,'Reports on file',String(d.reports));kv(k,'Snapshots',String(d.snapshots));
  if(d.csamHold)kv(k,'CSAM hold','yes (kept out of purge)');
  if(d.ncmec.length){d.ncmec.forEach(function(n){kv(k,'NCMEC',fmt(n.at)+(n.reportId?' - '+n.reportId:'')+(n.note?' - '+n.note:''))})}
  else if(d.csamHold)kv(k,'NCMEC','not recorded');
  if(d.story&&d.story.images){var sm=storyMedia(d.slug,d.story.images);if(sm){c.appendChild(el('div','sec-t','Story images'));c.appendChild(sm)}}
  var tools=el('div','tools');
  if(d.status==='live')tools.appendChild(link('View page','/@'+d.slug));
  tools.appendChild(mkSnaps(d.slug,d.status,0,c,d.csamHold,refresh));
  if(d.hasOwner)tools.appendChild(btn('Owner',null,function(){openOwner(d.slug)}));
  if(d.ad)tools.appendChild(btn('Ads tab',null,function(){openAd(d.slug)}));
  c.appendChild(tools);
  var foot=el('div','foot');
  if(d.status==='live'){
    foot.appendChild(btn('Take down','destroy',function(){return takedown(d.slug,d.csamHold,refresh)}));
    if(!d.csamHold)foot.appendChild(btn('Release slug',null,function(){return release(d.slug,refresh)}));
    if(d.showInStories)foot.appendChild(btn('Remove from stories',null,function(){return storyAct(d.slug,'remove',refresh)}))}
  if(d.storyBlocked)foot.appendChild(btn('Allow stories again',null,function(){return storyAct(d.slug,'allow',refresh)}));
  if(d.status==='taken down')foot.appendChild(btn('Restore',null,function(){return restore(d.slug,d.csamHold,0,refresh)}));
  if(d.csamHold||d.reports)foot.appendChild(btn(d.ncmec.length?'Add NCMEC record':'Record NCMEC report',null,function(){return recordNcmec(d.slug,refresh)}));
  out.appendChild(c);
  if(foot.children.length)c.appendChild(foot)
}
function storyAct(slug,action,done){
  var rm=action==='remove';
  return ask({title:rm?'Remove /'+slug+' from stories?':'Show /'+slug+' in stories again?',text:rm?'The page stays online. The owner cannot turn stories back on until you allow it.':'',ok:rm?'Remove':'Allow',danger:rm,fields:rm?[REASON_F]:undefined}).then(function(v){
    if(!v)return;var reason='';if(rm){reason=reasonOf(v);if(!reason)return}
    return api('/admin/story',{method:'POST',body:{slug:slug,action:action,reason:reason}}).then(function(o){if(o.ok){msg(rm?'Removed /'+slug+' from stories':'Stories allowed again for /'+slug);done()}else msg(o.j.error||(rm?'Could not remove /'+slug+' from stories':'Could not allow stories for /'+slug))})
  })
}
function loadOwner(slug){
  api('/admin/owner?slug='+encodeURIComponent(slug)).then(function(o){
    if(!o.ok){msg(o.j.error||'Could not load the account');return}
    var d=o.j,out=$('lkowner');out.textContent='';
    var c=el('div','card static sev-other');
    if(d.anonymous){c.appendChild(el('div',null,'Anonymous page: no account to act on.'));out.appendChild(c);return}
    var hd=el('div','lk-head compact');hd.appendChild(tile(d.suspended?'csam':'other','user'));
    var hm=el('div');hm.appendChild(el('div','slug',d.email||'(account missing)'));
    var cr=el('div','chips');
    cr.appendChild(chip(d.suspended?'suspended':'active','st '+(d.suspended?'bad':'good')));
    if(d.pendingDeletionAt)cr.appendChild(chip('deletion '+new Date(d.pendingDeletionAt+2592000000).toLocaleDateString(),'bad'));
    hm.appendChild(cr);hd.appendChild(hm);c.appendChild(hd);
    var st=el('div','stats');
    [['Subscribers',d.subscribers],['Likes',d.likes],['Live pages',d.pages.length],['Strikes',d.strikeCount],['Reports',d.reportStats?d.reportStats.total:null],['Alerts',d.alertTotal]].forEach(function(x){var s=el('div','stat');s.appendChild(el('b',null,x[1]==null?'-':num(x[1])));s.appendChild(el('span',null,x[0]));st.appendChild(s)});
    c.appendChild(st);
    var k=el('div','kvs');c.appendChild(k);
    aidRow(k,d.authorId);
    kv(k,'Signed up',fmt(d.createdAt));kv(k,'Last sign-in',fmt(d.lastSignInAt));kv(k,'Ads',String(d.ads));kv(k,'Credit balance',num(d.creditBalance));
    kv(k,'Display name',d.displayName||'-');
    kv(k,'Backup',d.backup?num(d.backup.images)+(d.backup.imagesMore?'+':'')+' images - '+Math.round(d.backup.sizeBytes/1024)+' KB - '+ago(d.backup.updatedAt):'none');
    c.appendChild(el('div','sec-t','Reports against this account'));
    var rs=d.reportStats;
    if(!rs)c.appendChild(el('div','fine','Report totals are unavailable until the report index is built (open the Reports tab once).'));
    else{
      var rl=el('div','fine',num(rs.total)+(rs.total===1?' report':' reports')+' total - '+num(rs.open)+' open - '+num(rs.total-rs.open)+' dismissed - across '+num(rs.pages)+(rs.pages===1?' page':' pages'));rl.style.margin='0 2px 8px';c.appendChild(rl);
      var rc=el('div','chips');
      ['csam','abuse','copyright','spam','other'].forEach(function(k){var v=rs.byReason[k]||{total:0,open:0};rc.appendChild(chip(trRL[k]+' '+num(v.total)+(v.open?' ('+num(v.open)+' open)':''),'by-sev sev-'+k))});
      c.appendChild(rc)
    }
    c.appendChild(el('div','sec-t','Strikes ('+num(d.strikeCount||0)+')'));
    if(!d.strikes||!d.strikes.length)c.appendChild(el('div','fine','No strikes. Reports alone are not strikes; takedowns, story or ad removals, profile removals and suspensions are.'));
    else d.strikes.forEach(function(x,i){
      var r=el('div','pgrow stack'),l=el('div');
      l.appendChild(el('div','amsg',x.message));
      l.appendChild(el('small',null,fmt(x.at)+' - '+ago(x.at)+(x.dismissedAt?' - deleted by user '+ago(x.dismissedAt):'')));
      var m=el('div','pm');m.appendChild(chip('strike #'+(i+1),'bad'));m.appendChild(chip(x.kind.replace(/_/g,' ')));r.appendChild(m);r.appendChild(l);c.appendChild(r)
    });
    if(d.hasProfileImage){c.appendChild(el('div','sec-t','Profile picture'));var pw=el('div','media');pw.appendChild(mediaTile('Profile picture',function(){return loadMedia(slug,'profile')},true));c.appendChild(pw)}
    if(d.ledger&&d.ledger.length){
      c.appendChild(el('div','sec-t','Credit ledger'));
      d.ledger.forEach(function(x){var r=el('div','pgrow'),l=el('div');l.appendChild(el('div','slug',(x.delta>0?'+':'')+num(x.delta)+' views'));l.appendChild(el('small',null,x.reason+(x.slug?' - /'+x.slug:'')+' - '+ago(x.at)));r.appendChild(l);c.appendChild(r)})
    }
    if(d.alerts&&d.alerts.length){
      c.appendChild(el('div','sec-t','Alerts sent ('+num(d.alertTotal||d.alerts.length)+')'));
      if(d.alertTotal>d.alerts.length)c.appendChild(el('div','fine','Showing the latest '+num(d.alerts.length)+'. Word for word what the account received.'));
      d.alerts.forEach(function(x){
        var r=el('div','pgrow stack'),l=el('div');
        l.appendChild(el('div','amsg',x.message));
        l.appendChild(el('small',null,fmt(x.at)+' - '+ago(x.at)+(x.dismissedAt?' - deleted by user '+ago(x.dismissedAt):'')));
        var m=el('div','pm');if(x.strike)m.appendChild(chip('strike','bad'));m.appendChild(chip(x.kind.replace(/_/g,' ')));r.appendChild(m);r.appendChild(l);c.appendChild(r)
      })
    }
    if(d.pages.length){
      c.appendChild(el('div','sec-t','Live pages'));
      d.pages.forEach(function(p){
        var r=el('button','pgrow');r.type='button';r.onclick=function(){openLookup(p.slug)};
        var l=el('div');l.appendChild(slugEl(p.slug));
        l.appendChild(el('small',null,(p.title||'Untitled')+(p.updatedAt?' - updated '+ago(p.updatedAt):'')));
        r.appendChild(l);
        var m=el('div','pm');
        if(p.likes!=null){var lk=el('span','lk');lk.appendChild(ico('heart'));lk.appendChild(el('span','n',num(p.likes)));m.appendChild(lk)}
        if(p.reports)m.appendChild(chip(p.reports+(p.reports===1?' report':' reports'),'bad'));
        if(p.showInStories)m.appendChild(chip('story'));
        if(m.children.length>1){r.className='pgrow stack';r.insertBefore(m,l)}else r.appendChild(m);
        c.appendChild(r)
      })
    }
    var again=function(){loadOwner(slug)};
    var foot=el('div','foot');
    foot.appendChild(d.suspended?btn('Unsuspend',null,function(){return ownerAct(slug,'unsuspend','Unsuspend this account?','',false,'Unsuspend',again)}):btn('Suspend','danger',function(){return ownerAct(slug,'suspend','Suspend this account?','It is signed out everywhere and cannot sign in. Pages stay online.',true,'Suspend',again)}));
    foot.appendChild(d.pendingDeletionAt?btn('Cancel deletion',null,function(){return ownerAct(slug,'cancel-delete','Cancel the scheduled deletion?','',false,'Cancel deletion',again)}):btn('Delete account','danger',function(){return ownerAct(slug,'delete','Delete this account?','Schedules the account for deletion in 30 days and suspends it. The owner cannot cancel by signing in.',true,'Schedule deletion',again)}));
    if(d.displayName)foot.appendChild(btn('Clear name',null,function(){return ownerAct(slug,'clear-name','Clear this display name?','Removes the name from their stories and Subscribed feed cards. They can set a new one.',true,'Clear name',again)}));
    if(d.hasProfileImage)foot.appendChild(btn('Remove picture',null,function(){return ownerAct(slug,'clear-picture','Remove this profile picture?','Deletes it from storage. They can upload a new one.',true,'Remove picture',again)}));
    if(d.pages.length)foot.appendChild(btn('Take down all live pages','destroy',function(){return takedownAll(d.pages,again)}));
    c.appendChild(foot);out.appendChild(c);
    if(c.scrollIntoView)c.scrollIntoView({behavior:'smooth',block:'start'})
  })
}
var OWNER_ACT={suspend:['Account suspended','suspend the account'],unsuspend:['Account unsuspended','unsuspend the account'],'cancel-delete':['Deletion cancelled','cancel the deletion'],'delete':['Account scheduled for deletion','schedule the deletion'],'clear-name':['Display name cleared','clear the display name'],'clear-picture':['Profile picture removed','remove the profile picture']};
function ownerAct(slug,action,title,text,danger,okLabel,done){
  var needs=action==='suspend'||action==='clear-name'||action==='clear-picture';
  return ask({title:title,text:text,ok:okLabel,danger:danger,fields:needs?[REASON_F]:undefined}).then(function(v){
    if(!v)return;var reason='';if(needs){reason=reasonOf(v);if(!reason)return}
    return api('/admin/owner/action',{method:'POST',body:{slug:slug,action:action,reason:reason}}).then(function(o){var OA=OWNER_ACT[action]||['Done','complete the account action'];
      if(o.ok){msg(OA[0]);done()}else msg(o.j.error||'Could not '+OA[1])})
  })
}
function takedownAll(pages,done){
  return ask({title:'Take down all '+pages.length+' live pages?',text:'Takes down every live page of this account and permanently locks their slugs.',ok:'Take down all',danger:true,fields:[REASON_F]}).then(function(v){
    if(!v)return;var reason=reasonOf(v);if(!reason)return;
    var i=0,fails=0;
    return new Promise(function(res){(function step(){
      if(i>=pages.length){msg(fails?fails+(fails===1?' takedown failed':' takedowns failed'):'All pages taken down');done();res();return}
      var s=pages[i++].slug;
      api('/publish/'+encodeURIComponent(s),{method:'DELETE',body:{adminToken:tok,reason:reason}}).then(function(o){if(!o.ok&&o.s!==404)fails++;step()}).catch(function(){fails++;step()})
    })()})
  })
}

/* ---------- Ads ---------- */
var adT=null,adFocus='';
function adqv(){return $('adq').value.trim().toLowerCase().replace(/^[/@]+/,'')}
// Lookup's "Ads tab": show the ad of one note, opened, in the Ads screen (status filter reset so it cannot be hidden).
function openAd(slug){
  openSet['ad:'+slug]=true;adFocus=slug;
  $('adq').value=slug;pickSet('adst','');
  $('adlist').textContent='';adCur='';
  goTab('ads');if(cur==='ads'&&!$('adlist').firstChild)loadAds(true)
}
function loadAds(reset){
  var L=$('adlist');
  if(reset){adCur='';adTotal=0;L.textContent='';skel(L,3)}else moreBusy($('admore'),true);
  return api('/admin/ads?status='+encodeURIComponent($('adst').value)+'&q='+encodeURIComponent(adqv())+'&cursor='+encodeURIComponent(adCur)).then(function(o){
    unskel(L);moreBusy($('admore'),false);
    if(!o.ok){bad(o);return}
    if(o.j.total!=null)adTotal=o.j.total;SUBS.ads=num(adTotal)+(adTotal===1?' campaign':' campaigns')+($('adst').value?' - '+$('adst').textContent.toLowerCase():'');if(cur==='ads')setSub();
    o.j.ads.forEach(renderAd);
    if(adFocus){var f=o.j.ads.filter(function(x){return x.slug===adFocus})[0];adFocus='';if(f&&f._c&&f._c.scrollIntoView)f._c.scrollIntoView({behavior:'smooth',block:'start'})}
    adCur=o.j.next;$('admore').hidden=adCur==null;
    if(!L.firstChild)L.appendChild(empty('No ads','No ads match this search or filter.','ads'))
  }).catch(function(){unskel(L);moreBusy($('admore'),false);msg('Network error, check your connection')})
}
// The server's result applied to the card on screen: no list reload. Under a status filter a card that no
// longer matches leaves the list, and the campaign count follows.
function adApplied(a,action){
  var to={pause:'paused',resume:'active',takedown:'unpublished'}[action];
  if(to)a.status=to;
  var f=$('adst').value;
  if(f&&a.status!==f){
    if(a._c)a._c.remove();
    adTotal=Math.max(0,adTotal-1);
    SUBS.ads=num(adTotal)+(adTotal===1?' campaign':' campaigns')+' - '+$('adst').textContent.toLowerCase();if(cur==='ads')setSub();
    if(!$('adlist').firstChild)$('adlist').appendChild(empty('No ads','No ads match this filter.','ads'))
  }else renderAd(a)
}
var AD_DONE={pause:'Ad paused',resume:'Ad resumed',takedown:'Ad taken down',refund:'No views to refund'},AD_VERB={pause:'pause',resume:'resume',takedown:'take down',refund:'refund'};
function adAct(a,action,refund,o){
  o.ok=o.ok||'Confirm';
  var needs=action==='pause'||action==='takedown';
  if(needs)o.fields=[REASON_F];
  return ask(o).then(function(v){
    if(!v)return;var reason='';if(needs){reason=reasonOf(v);if(!reason)return}
    return api('/admin/ad',{method:'POST',body:{slug:a.slug,action:action,refund:!!refund,reason:reason}}).then(function(r){
      if(r.ok){msg(r.j.refunded?r.j.refunded+(r.j.refunded===1?' view refunded':' views refunded'):AD_DONE[action]||'Done');adApplied(a,action)}else msg(r.j.error||'Could not '+(AD_VERB[action]||'update')+' the ad')})
  })
}
function renderAd(a){
  var left=a.viewsTotal-a.viewsUsed;
  var pct=a.viewsTotal?Math.min(100,Math.round(a.viewsUsed/a.viewsTotal*100)):0;
  var m=el('div'),bar=el('div','meter'),i=document.createElement('i');i.style.width=pct+'%';bar.appendChild(i);m.appendChild(bar);
  var ml=el('div','meter-l');ml.appendChild(el('span',null,num(a.viewsUsed)+' of '+num(a.viewsTotal)+' views'));ml.appendChild(el('span',null,pct+'%'));m.appendChild(ml);
  var card=mkCard({sev:'ad',icon:'ads',slug:a.slug,chips:[stChip(a.status)],sub:a.ownerEmail||'account missing',extra:m,key:'ad:'+a.slug});
  var k=el('div','kvs');
  kv(k,'Unique viewers',num(a.uniqueViewers));kv(k,'Views left',num(left));kv(k,'Created',fmt(a.createdAt));
  card.pad.appendChild(k);
  var tools=el('div','tools');tools.appendChild(btn('Lookup',null,function(){openLookup(a.slug)}));card.pad.appendChild(tools);
  var foot=card.foot;
  if(a.status==='active')foot.appendChild(btn('Pause',null,function(){return adAct(a,'pause',0,{title:'Pause /'+a.slug+'?',text:'It stops being served until resumed.',ok:'Pause'})}));
  if(a.status==='paused')foot.appendChild(btn('Resume',null,function(){return adAct(a,'resume',0,{title:'Resume /'+a.slug+'?',ok:'Resume'})}));
  if(a.status==='active'||a.status==='paused'){
    foot.appendChild(btn('Take down','danger',function(){return adAct(a,'takedown',0,{title:'Take the ad down?',text:'/'+a.slug+' stays online and the '+num(left)+' unused views are forfeited.',ok:'Take down',danger:true})}));
    if(left>0)foot.appendChild(btn('Take down + refund','danger',function(){return adAct(a,'takedown',1,{title:'Take down and refund?',text:'The ad on /'+a.slug+' comes down and '+num(left)+' unused views are refunded to the owner.',ok:'Take down + refund',danger:true})}))}
  else if(a.status==='unpublished'&&left>0)foot.appendChild(btn('Refund unused','danger',function(){return adAct(a,'refund',0,{title:'Refund '+num(left)+' unused views?',text:'They go back to the owner of /'+a.slug+'. This can only be done once.',ok:'Refund',danger:true})}));
  if(a._c&&a._c.parentNode)a._c.replaceWith(card.c);else $('adlist').appendChild(card.c);
  a._c=card.c
}

/* ---------- Audit ---------- */
function actTone(a){a=String(a||'');if(/take|purge|suspend|delete|ban/.test(a)&&!/unsuspend/.test(a))return'bad';if(/restore|release|unsuspend|allow|refund|resume/.test(a))return'good';return''}
function loadAudit(reset){
  var L=$('aulist');
  if(reset){auNext=null;auAll=[];L.textContent='';skel(L,4)}else moreBusy($('aumore'),true);
  return api('/admin/audit'+(auNext?'?cursor='+encodeURIComponent(auNext):'')).then(function(o){
    unskel(L);moreBusy($('aumore'),false);
    if(!o.ok){bad(o);return}
    auAll=auAll.concat(o.j.entries);auNext=o.j.nextCursor;$('aumore').hidden=!auNext;
    renderAudit()
  }).catch(function(){unskel(L);moreBusy($('aumore'),false);msg('Network error, check your connection')})
}
function renderAudit(){
  var keys=$('aukeys');keys.textContent='';
  var seen=[],cnt={};auAll.forEach(function(e){if(cnt[e.action]==null){cnt[e.action]=0;seen.push(e.action)}cnt[e.action]++});
  if(seen.length>1||auFilter){
    var mk=function(v,label,n){var b=el('button','key');b.type='button';b.setAttribute('aria-pressed',auFilter===v?'true':'false');b.appendChild(el('span',null,label));b.appendChild(el('b',null,String(n)));b.onclick=function(){auFilter=v;renderAudit()};keys.appendChild(b)};
    mk('','All',auAll.length);seen.forEach(function(a){mk(a,a,cnt[a])})
  }
  var L=$('aulist');L.textContent='';
  var lastDay='';
  auAll.filter(function(e){return!auFilter||e.action===auFilter}).forEach(function(e){
    var dl=dayLabel(e.at);if(dl!==lastDay){lastDay=dl;L.appendChild(el('div','day',dl))}
    var d=el('div','log '+actTone(e.action)),top=el('div','log-top');
    top.appendChild(chip(e.action,actTone(e.action)));top.appendChild(el('span','ago',ago(e.at)));
    d.appendChild(top);
    if(e.slug||e.detail){
      var main=el('div','log-main');
      if(e.slug){var lb=el('button','lnk','/'+e.slug);lb.type='button';lb.onclick=function(){openLookup(e.slug)};main.appendChild(lb)}
      if(e.detail)main.appendChild(el('span','det',e.detail));
      d.appendChild(main)
    }
    L.appendChild(d)
  });
  if(!L.firstChild)L.appendChild(empty('No audit entries yet','Takedowns, releases and other admin actions are logged here.','audit'))
}

/* ---------- Overview ---------- */
var OV=[
  ['People',[['users','Users'],['usersOnline','Online now'],['guests','Guests'],['usersActive24h','Active 24h'],['usersNew7d','New this week'],['guestsOnline','Guests online']]],
  ['Content',[['notes','Published notes'],['notesNew1d','New today'],['notesNew7d','New this week'],['publishers','Publishers'],['stories','In stories'],['likes','Likes']]],
  ['Ads and follows',[['adsActive','Active ads'],['adsPaused','Paused ads'],['adViewsUsed','Ad views used'],['adsExhausted','Used up'],['adsUnpublished','Taken down'],['subscriptions','Subscriptions']]]
];
var ovS={view:'users',cur:'',total:0,shown:0,gen:0,loaded:false,fil:'',sort:'new',q:'',t:null};
function ovShell(){
  var C=$('ovstats');C.textContent='';
  OV.forEach(function(sec){
    C.appendChild(el('div','sec-t',sec[0]));
    var g=el('div','stats');
    sec[1].forEach(function(f){var s=el('div','stat ld');s.setAttribute('data-k',f[0]);s.appendChild(el('b',null,'0'));s.appendChild(el('span',null,f[1]));g.appendChild(s)});
    C.appendChild(g)
  })
}
function loadOverview(){
  trLoad();
  if(!$('ovstats').firstChild)ovShell();
  var S=[].slice.call($('ovstats').querySelectorAll('.stat'));
  S.forEach(function(s){s.classList.add('ld')});
  function fail(){ovS.loaded=false;S.forEach(function(s){s.firstChild.textContent='-';s.classList.remove('ld')})}
  return api('/admin/stats').then(function(o){
    if(!o.ok){fail();bad(o);return}
    var st=o.j.stats;
    S.forEach(function(s){var v=st[s.getAttribute('data-k')];s.firstChild.textContent=v==null?'-':num(v);s.classList.remove('ld')});
    $('ovnote').textContent='Online means active in the last '+o.j.onlineWindowMin+' minutes. '+(o.j.trackingSince?'Activity tracked since '+new Date(o.j.trackingSince).toLocaleDateString()+'. ':'No activity recorded yet. ')+'Notes cover signed-in publishers only.'
  }).catch(function(){fail();msg('Network error, check your connection')})
}
function ovSync(){
  var users=ovS.view==='users';
  [].forEach.call($('ovseg').children,function(b){b.setAttribute('aria-pressed',b.getAttribute('data-v')===ovS.view?'true':'false')});
  $('ovfil').hidden=!users;
  $('ovq').placeholder=users?'Search by author ID':'Search by slug'
}
function ovUser(u){
  var r=el('button','pgrow'),l=el('div');r.type='button';
  r.onclick=function(){if(!u.authorId)return;try{navigator.clipboard.writeText(u.authorId).then(function(){msg('Author ID copied')},function(){msg(u.authorId)})}catch(e){msg(u.authorId)}};
  l.appendChild(el('div','slug',u.email||'Account missing'));
  l.appendChild(el('small',null,(u.name?u.name+' - ':'')+'Joined '+ago(u.createdAt)+' - '+num(u.notes)+(u.notes===1?' note':' notes')+' - '+(u.lastSeen?'seen '+ago(u.lastSeen):'not seen yet')+(u.lastSignInAt?' - signed in '+ago(u.lastSignInAt):'')));
  if(u.authorId)l.appendChild(el('small','aid',u.authorId));
  r.appendChild(l);
  var m=el('div','pm');
  if(u.authorId){var cp=el('span','lk');cp.setAttribute('aria-label','Copy author ID');cp.appendChild(ico('copy'));m.appendChild(cp)}
  if(u.online)m.appendChild(chip('online','st good'));
  if(u.suspended)m.appendChild(chip('suspended','bad'));
  if(u.deleting)m.appendChild(chip('deleting','warn'));
  if(m.children.length>1){r.className='pgrow stack';r.insertBefore(m,l)}else r.appendChild(m);
  $('ovlist').appendChild(r)
}
function ovNote(n){
  var r=el('button','pgrow');r.type='button';r.onclick=function(){openLookup(n.slug)};
  var l=el('div');l.appendChild(slugEl(n.slug));
  l.appendChild(el('small',null,(n.title||'Untitled')+' - published '+ago(n.createdAt)));
  r.appendChild(l);
  var m=el('div','pm');if(n.story)m.appendChild(chip('story'));
  r.appendChild(m);$('ovlist').appendChild(r)
}
function ovList(reset){
  var L=$('ovlist'),m=$('ovmore'),users=ovS.view==='users',g=++ovS.gen;
  if(reset){ovS.cur='';ovS.total=0;ovS.shown=0;L.textContent='';moreBusy(m,false);m.hidden=true;$('ovcount').textContent='';skel(L,4,'row')}
  else moreBusy(m,true);
  var qs='cursor='+encodeURIComponent(ovS.cur)+'&q='+encodeURIComponent(ovS.q)+(users?'&sort='+ovS.sort+'&f='+ovS.fil:'');
  return api('/admin/'+ovS.view+'?'+qs).then(function(o){
    if(g!==ovS.gen)return;
    unskel(L);moreBusy(m,false);
    if(!o.ok){bad(o);return}
    var rows=users?o.j.users:o.j.notes;
    rows.forEach(users?ovUser:ovNote);
    ovS.cur=o.j.next;if(o.j.total!=null)ovS.total=o.j.total;ovS.shown+=rows.length;
    m.hidden=ovS.cur==null;
    $('ovcount').textContent=ovS.total?'Showing '+num(ovS.shown)+' of '+num(ovS.total):'';
    if(!L.firstChild)L.appendChild(empty(users?'No users':'No notes','Nothing matches this search.',users?'users':'reports'))
  }).catch(function(){if(g!==ovS.gen)return;unskel(L);moreBusy(m,false);msg('Network error, check your connection')})
}

/* ---------- Trends: growth and decline over time ---------- */
var trWIN={day:30,week:12,month:12,year:5},trOPT={day:[7,14,30,90],week:[4,8,12,26],month:[3,6,12,24],year:[2,3,5,10]},trMINV='30 Sep 2026',trUNIT={day:'days',week:'weeks',month:'months',year:'years'},trOFF=-new Date().getTimezoneOffset()*60000,trMIN=Date.UTC(2015,0,1);
var trRL={csam:'Child safety',abuse:'Abuse',copyright:'Copyright',spam:'Spam',other:'Other'},trRO=['csam','abuse','copyright','spam','other'],trRC={csam:'#FF4D6D',abuse:'#FF9A5C',copyright:'#F7C35B',spam:'#97A3F0',other:'#46D6C8'};
var trM=[
  {k:'signups',l:'New accounts',t:'Accounts',c:'#8B9BFF',cum:1,good:1},
  {k:'active_u',l:'Active accounts',c:'#46E0A8',level:1,good:1},
  {k:'active_g',l:'Active guests',c:'#B69CFF',level:1,good:1},
  {k:'notes',l:'Notes published',t:'Notes',c:'#46D6C8',cum:1,good:1},
  {k:'stories',l:'Stories',t:'Stories',c:'#F7C35B',cum:1,good:1},
  {k:'likes',l:'Likes',t:'Likes',c:'#FF8FB1',cum:1,good:1},
  {k:'subs',l:'Subscriptions',t:'Subscriptions',c:'#97A3F0',cum:1,good:1},
  {k:'ads',l:'Ads created',t:'Ads',c:'#B69CFF',cum:1,good:1},
  {k:'reports',l:'Reports',t:'Reports',c:'#FF9A5C',cum:1,good:0},
  {k:'strikes',l:'Strikes issued',t:'Strikes',c:'#FF6A86',cum:1,good:0},
  {k:'alerts',l:'Alerts sent',t:'Alerts',c:'#A3A9DA',cum:1,good:0}
];
var trS={bk:'day',end:null,metric:'signups',mode:'flow',data:null,plan:null,M:null,RS:null,gen:0,ready:false};
function trEsc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function trRgba(h,a){var n=parseInt(h.slice(1),16);return 'rgba('+(n>>16&255)+','+(n>>8&255)+','+(n&255)+','+a+')'}
/* All bucket math runs on "shifted" time (real ms + the admin's UTC offset) read back with UTC getters. */
function trStart(bk,s){
  var d=new Date(s);
  if(bk==='day')return Date.UTC(d.getUTCFullYear(),d.getUTCMonth(),d.getUTCDate());
  if(bk==='month')return Date.UTC(d.getUTCFullYear(),d.getUTCMonth(),1);
  if(bk==='year')return Date.UTC(d.getUTCFullYear(),0,1);
  var day=Math.floor(s/864e5);return (Math.floor((day+3)/7)*7-3)*864e5
}
function trNext(bk,s,n){
  var d=new Date(s);
  if(bk==='day')return s+n*864e5;
  if(bk==='week')return s+n*7*864e5;
  if(bk==='month')return Date.UTC(d.getUTCFullYear(),d.getUTCMonth()+n,1);
  return Date.UTC(d.getUTCFullYear()+n,0,1)
}
function trKey(bk,s){
  var d=new Date(s);
  if(bk==='day')return d.toISOString().slice(0,10);
  if(bk==='month')return d.toISOString().slice(0,7);
  if(bk==='year')return String(d.getUTCFullYear());
  return String(Math.floor((Math.floor(s/864e5)+3)/7))
}
function trLab(bk,s,full){
  var o={timeZone:'UTC'},d=new Date(s);
  if(bk==='year')return String(d.getUTCFullYear());
  if(bk==='month'){o.month='short';if(full||d.getUTCMonth()===0)o.year='numeric';return d.toLocaleDateString(undefined,o)}
  o.month='short';o.day='numeric';if(full)o.year='numeric';
  var t=d.toLocaleDateString(undefined,o);
  return bk==='week'&&full?'Week of '+t:t
}
function trPlan(){
  var bk=trS.bk,N=trWIN[bk],nowStart=trStart(bk,Date.now()+trOFF);
  var last=trS.end==null?nowStart:Math.min(trStart(bk,trS.end),nowStart),starts=[],ends=[],i;
  for(i=-(2*N-1);i<=0;i++){starts.push(trNext(bk,last,i));ends.push(trNext(bk,last,i+1))}
  return {bk:bk,N:N,starts:starts,ends:ends,live:last===nowStart,from:starts[0]-trOFF,to:ends[2*N-1]-trOFF}
}
function trNice(m){if(!(m>0))return 1;var e=Math.pow(10,Math.floor(Math.log10(m))),f=m/e;return (f<=1?1:f<=2?2:f<=5?5:10)*e}
function trShort(n){n=Math.round(n*10)/10;var a=Math.abs(n);if(a>=1e6)return (n/1e6).toFixed(1).replace('.0','')+'M';if(a>=1e3)return (n/1e3).toFixed(1).replace('.0','')+'k';return String(n)}
function trSum(a,from,to){var s=0,n=0,i;for(i=from;i<to;i++)if(a[i]!=null){s+=a[i];n++}return {s:s,n:n}}
function trDelta(cur,prev,good){
  if(cur==null||prev==null)return {t:'no earlier data',c:'fl'};
  var diff=cur-prev;
  if(Math.abs(diff)<1e-9)return {t:'no change',c:'fl'};
  var sg=diff>0?'+':'-',t=sg+num(Math.round(Math.abs(diff)*10)/10);
  t+=prev?' ('+sg+(Math.round(Math.abs(diff)/prev*1000)/10)+'%)':' (new)';
  return {t:t,c:(diff>0)===!!good?'up':'dn'}
}
function trSpark(vals,color){
  var w=72,h=24,a=vals.filter(function(v){return v!=null});
  if(a.length<2)return '<svg viewBox="0 0 72 24"></svg>';
  var mn=Math.min.apply(null,a),mx=Math.max.apply(null,a),rg=mx-mn||1,n=vals.length,d='',pen=false;
  vals.forEach(function(v,i){
    if(v==null){pen=false;return}
    var x=2+(w-4)*i/(n-1),y=mx===mn?h/2:h-3-(h-6)*(v-mn)/rg;
    d+=(pen?'L':'M')+x.toFixed(1)+' '+y.toFixed(1);pen=true
  });
  return '<svg viewBox="0 0 72 24"><path d="'+d+'" fill="none" stroke="'+color+'" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>'
}
/* Bar or line chart as inline SVG; drag or tap to read a bucket. ser: [{name,color,vals}] (null = no data). */
function trDraw(host,labels,full,ser,o){
  o=o||{};
  var W=340,H=200,L=40,R=10,Tp=12,B=26,iw=W-L-R,ih=H-Tp-B,n=labels.length,stack=!!o.stack,line=o.type==='line',i;
  var hi=0,lo=o.zoom?Infinity:0;
  for(i=0;i<n;i++){
    var tot=0;
    ser.forEach(function(x){var v=x.vals[i];if(v==null)return;if(stack)tot+=v;else{if(v>hi)hi=v;if(v<lo)lo=v}});
    if(stack&&tot>hi)hi=tot
  }
  if(lo===Infinity)lo=0;
  var step=Math.max(1,trNice((hi-lo)/4)),base=o.zoom?Math.floor(lo/step)*step:0;
  var top=base+step*Math.max(1,Math.ceil((hi-base)/step)),ticks=Math.round((top-base)/step);
  function Y(v){return Tp+ih-(v-base)/(top-base)*ih}
  var slot=iw/n;function X(k){return L+slot*(k+.5)}
  var s='<svg viewBox="0 0 '+W+' '+H+'" role="img">';
  for(i=0;i<=ticks;i++){var gy=Y(base+step*i);s+='<line x1="'+L+'" x2="'+(W-R)+'" y1="'+gy.toFixed(1)+'" y2="'+gy.toFixed(1)+'" class="tr-g"/><text x="'+(L-6)+'" y="'+(gy+3.5).toFixed(1)+'" text-anchor="end" class="tr-ax">'+trShort(base+step*i)+'</text>'}
  if(!line){
    var bw=Math.max(2,Math.min(28,slot*.72));
    for(i=0;i<n;i++){
      var acc=0;
      ser.forEach(function(x){
        var v=x.vals[i];if(v==null||v<=0)return;
        var y0=Y(acc),y1=Y(acc+v);
        s+='<rect class="tr-b" data-i="'+i+'" x="'+(X(i)-bw/2).toFixed(1)+'" y="'+y1.toFixed(1)+'" width="'+bw.toFixed(1)+'" height="'+Math.max(1,y0-y1).toFixed(1)+'" rx="'+Math.min(3,bw/3).toFixed(1)+'" style="fill:'+x.color+'"'+(o.partial&&i===n-1?' opacity=".55"':'')+'/>';
        if(stack)acc+=v
      })
    }
  }else{
    ser.forEach(function(x){
      var d='',pen=false,holes=false,k;
      for(k=0;k<n;k++){var v=x.vals[k];if(v==null){pen=false;holes=true;continue}d+=(pen?'L':'M')+X(k).toFixed(1)+' '+Y(v).toFixed(1);pen=true}
      if(!d)return;
      if(!holes)s+='<path d="'+d+' L'+X(n-1).toFixed(1)+' '+Y(base).toFixed(1)+' L'+X(0).toFixed(1)+' '+Y(base).toFixed(1)+'Z" style="fill:'+x.color+';fill-opacity:.13"/>';
      s+='<path d="'+d+'" fill="none" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="stroke:'+x.color+'"/>';
      if(n<=31)for(k=0;k<n;k++){var w2=x.vals[k];if(w2!=null)s+='<circle cx="'+X(k).toFixed(1)+'" cy="'+Y(w2).toFixed(1)+'" r="2.4" style="fill:'+x.color+'"/>'}
    })
  }
  var kx=Math.max(1,Math.ceil(n/6));
  for(i=0;i<n;i+=kx)s+='<text x="'+X(i).toFixed(1)+'" y="'+(H-8)+'" text-anchor="middle" class="tr-ax">'+trEsc(labels[i])+'</text>';
  s+='<g class="tr-pts"></g><line class="tr-cur" x1="0" x2="0" y1="'+Tp+'" y2="'+(Tp+ih)+'" style="display:none"/></svg><div class="tr-tip"></div>';
  host.innerHTML=s;
  var sv=host.firstChild,cur=sv.querySelector('.tr-cur'),tip=host.querySelector('.tr-tip');
  var bars=sv.querySelectorAll('.tr-b'),pts=sv.querySelector('.tr-pts'),last=-1;
  function hide(){last=-1;cur.style.display='none';tip.style.display='none';sv.classList.remove('sel');[].forEach.call(bars,function(b){b.classList.remove('on')});pts.innerHTML=''}
  function hv(e){
    var r=sv.getBoundingClientRect(),px=(e.clientX-r.left)/r.width*W,idx=Math.floor((px-L)/slot);
    if(idx<0||idx>=n){hide();return}
    var cx=X(idx);
    if(idx!==last){last=idx;
      if(line){cur.setAttribute('x1',cx);cur.setAttribute('x2',cx);cur.style.display='';var pc='';ser.forEach(function(x){var v=x.vals[idx];if(v!=null)pc+='<circle class="tr-pt" cx="'+cx.toFixed(1)+'" cy="'+Y(v).toFixed(1)+'" r="4.6" style="fill:'+x.color+'"/>'});pts.innerHTML=pc}
      else{sv.classList.add('sel');[].forEach.call(bars,function(b){b.classList.toggle('on',+b.getAttribute('data-i')===idx)})}
    }
    var h='<b>'+trEsc(full[idx])+'</b>',sum=0;
    ser.forEach(function(x){var v=x.vals[idx];if(v!=null)sum+=v;h+='<div><i style="background:'+x.color+'"></i>'+trEsc(x.name)+' <b>'+(v==null?'-':num(v))+'</b></div>'});
    if(stack&&ser.length>1)h+='<div>Total <b>'+num(sum)+'</b></div>';
    tip.innerHTML=h;tip.style.display='block';
    tip.style.left=Math.min(Math.max(cx/W*100,24),76)+'%';tip.style.transform='translateX(-50%)'
  }
  sv.addEventListener('pointerdown',hv);sv.addEventListener('pointermove',hv);sv.addEventListener('pointerleave',hide);sv.addEventListener('pointercancel',hide)
}
function trMetric(k){return trM.filter(function(m){return m.k===k})[0]}
function trInit(){
  if(trS.ready)return;trS.ready=true;
  var box=$('trmet');
  trM.forEach(function(x){
    var b=el('button','key');b.type='button';b.setAttribute('data-k',x.k);b.setAttribute('aria-pressed','false');
    b.style.setProperty('--sev',x.c);b.style.setProperty('--sev-bg',trRgba(x.c,.17));
    b.appendChild(document.createElement('i'));b.appendChild(el('span',null,x.l));
    b.onclick=function(){trS.metric=x.k;if(!x.cum)trS.mode='flow';trMetSync();if(trS.M)trChartRender()};
    box.appendChild(b)
  });
  [].forEach.call($('trbk').children,function(b){b.onclick=function(){var v=b.getAttribute('data-b');if(trS.bk===v)return;trS.bk=v;trLoad()}});
  [].forEach.call($('trmode').children,function(b){b.onclick=function(){trS.mode=b.getAttribute('data-m');trMetSync();if(trS.M)trChartRender()}});
  $('trprev').onclick=function(){if(this.getAttribute('aria-disabled')==='true'){msg('No earlier data, trends start on '+trMINV,'ok');return}var p=trPlan();trS.end=trNext(p.bk,p.starts[2*p.N-1],-p.N);trLoad()};
  $('trnext').onclick=function(){if(this.getAttribute('aria-disabled')==='true'){msg('Already showing the latest '+trS.bk,'ok');return}var p=trPlan(),c=trNext(p.bk,p.starts[2*p.N-1],p.N);trS.end=c>=trStart(p.bk,Date.now()+trOFF)?null:c;trLoad()};
  $('trnow').onclick=function(){trS.end=null;trLoad()};
  $('trjump').onchange=function(){
    var v=$('trjump').value;if(!v){trS.end=null;trLoad();return}
    var a=v.split('-'),s=Date.UTC(+a[0],+a[1]-1,+a[2]);
    trS.end=s>=trStart(trS.bk,Date.now()+trOFF)?null:s;trLoad()
  };
  trMetSync()
}
function trMetSync(){
  var x=trMetric(trS.metric);
  [].forEach.call($('trmet').children,function(b){b.setAttribute('aria-pressed',b.getAttribute('data-k')===trS.metric?'true':'false')});
  [].forEach.call($('trbk').children,function(b){b.setAttribute('aria-pressed',b.getAttribute('data-b')===trS.bk?'true':'false')});
  [].forEach.call($('trmode').children,function(b){b.setAttribute('aria-pressed',b.getAttribute('data-m')===trS.mode?'true':'false')});
  $('trmode').hidden=!x.cum;
  var bk=trS.bk,w=$('trwin'),os=trOPT[bk],u=trUNIT[bk];
  if(w.getAttribute('data-bk')!==bk){
    w.textContent='';w.setAttribute('data-bk',bk);
    os.forEach(function(n){var b=el('button','key sev-ad');b.type='button';b.setAttribute('data-n',n);b.appendChild(el('span',null,String(n)));
      b.onclick=function(){if(trWIN[bk]===n)return;trWIN[bk]=n;trLoad()};w.appendChild(b)})
  }
  $('trwlab').textContent='Last '+(bk==='day'?'days':u);
  [].forEach.call(w.children,function(b){b.setAttribute('aria-pressed',+b.getAttribute('data-n')===trWIN[bk]?'true':'false')})
}
function trLoad(){
  trInit();
  var g=++trS.gen,p=trPlan();
  trS.plan=p;trNavSync();trMetSync();
  $('trchart').classList.add('busy');
  return api('/admin/trends?bucket='+p.bk+'&from='+p.from+'&to='+p.to+'&off='+trOFF).then(function(o){
    if(g!==trS.gen)return;
    $('trchart').classList.remove('busy');
    if(!o.ok){bad(o);return}
    trS.data=o.j;trBuild();trRender()
  }).catch(function(){if(g!==trS.gen)return;$('trchart').classList.remove('busy');msg('Network error, check your connection')})
}
function trNavSync(){
  var p=trS.plan,N=p.N;
  $('trrange').textContent=trLab(p.bk,p.starts[N],true)+(N>1?' - '+trLab(p.bk,p.starts[2*N-1],true):'');
  var ep=trS.data&&trS.data.epoch,noData=ep&&p.from<ep;
  $('trcmp').textContent='Compared with the previous '+N+' '+(N===1?trUNIT[p.bk].replace(/s$/,''):trUNIT[p.bk])+': '+trLab(p.bk,p.starts[0],true)+(N>1?' - '+trLab(p.bk,p.starts[N-1],true):'')+(noData?' (no data before '+trMINV+')':'');
  var offP=p.starts[0]-N*864e5<=trMIN||(trS.data&&p.from<=trS.data.epoch);
  $('trprev').setAttribute('aria-disabled',offP?'true':'false');
  $('trnext').setAttribute('aria-disabled',p.live?'true':'false');
  $('trnow').hidden=p.live;
  var j=$('trjump');j.max=new Date(Date.now()+trOFF).toISOString().slice(0,10);
  j.value=new Date(p.ends[2*N-1]-864e5).toISOString().slice(0,10)
}
function trBuild(){
  var d=trS.data,p=trS.plan,keys=p.starts.map(function(s){return trKey(p.bk,s)}),M={},RS={},kix={};
  keys.forEach(function(k,i){kix[k]=i});
  var ep=(d.epoch||0)+trOFF;
  function pre(i){return p.ends[i]<=ep}
  function col(name){var m={};(d.series[name]||[]).forEach(function(r){m[String(r[0])]=r[1]});return keys.map(function(k,i){return pre(i)?null:(m[k]||0)})}
  trM.forEach(function(x){
    if(x.level){
      var a=col(x.k),since=d.activeSince;
      M[x.k]={flow:a.map(function(v,i){return v==null||since==null||p.ends[i]-trOFF<=since?null:v})};return
    }
    if(x.k==='reports'&&!d.reportsIndexed){M[x.k]=null;return}
    var f=col(x.k),run=(d.before||{})[x.k]||0;
    M[x.k]={flow:f,cum:f.map(function(v){if(v==null)return null;run+=v;return run})}
  });
  trRO.forEach(function(r){RS[r]=keys.map(function(k,i){return pre(i)?null:0})});
  (d.reportsByReason||[]).forEach(function(r){var i=kix[String(r[0])];if(i==null)return;var k=RS[r[1]]?r[1]:'other';if(RS[k][i]!=null)RS[k][i]+=r[2]});
  trS.M=M;trS.RS=RS
}
function trRender(){
  trNavSync();trMetSync();trChartRender();trRowsRender();rpRender();
}
function trChartRender(){
  var x=trMetric(trS.metric),Mx=trS.M[x.k],p=trS.plan,N=p.N,host=$('trchart'),leg=$('trleg');
  host.textContent='';leg.textContent='';
  if(!Mx){
    $('trval').textContent='-';$('trdl').textContent='';$('trsub').textContent='';
    host.appendChild(el('div','tr-msg','Reports are still being indexed. Open the Reports tab once, then refresh.'));return
  }
  var total=trS.mode==='total'&&!!x.cum,labels=p.starts.slice(N).map(function(s){return trLab(p.bk,s,false)}),full=p.starts.slice(N).map(function(s){return trLab(p.bk,s,true)});
  var val,dl,sub,ser,o={partial:p.live};
  if(total){
    var endV=Mx.cum[2*N-1],startV=Mx.cum[N-1];
    val=endV==null?'-':num(endV);dl=trDelta(endV,startV,x.good);sub='Total at end of range, change across the range';
    ser=[{name:x.t||x.l,color:x.c,vals:Mx.cum.slice(N)}];o.type='line';o.zoom=true
  }else if(x.level){
    var c=trSum(Mx.flow,N,2*N),pv=trSum(Mx.flow,0,N),ca=c.n?c.s/c.n:null,pa=pv.n?pv.s/pv.n:null;
    val=ca==null?'-':num(Math.round(ca*10)/10);dl=trDelta(ca,pa,x.good);sub='Average per '+p.bk+', vs previous '+N+' '+trUNIT[p.bk];
    ser=[{name:x.l,color:x.c,vals:Mx.flow.slice(N)}];o.type='line'
  }else{
    var cq=trSum(Mx.flow,N,2*N),pq=trSum(Mx.flow,0,N),cs=cq.n?cq.s:null,ps=pq.n?pq.s:null;
    val=cs==null?'-':num(cs);dl=trDelta(cs,ps,x.good);sub=x.l+' in this range, vs previous '+N+' '+trUNIT[p.bk];
    if(x.k==='reports'){
      ser=trRO.map(function(r){return {name:trRL[r],color:trRC[r],vals:trS.RS[r].slice(N)}});o.stack=true;
      trRO.forEach(function(r){var s=el('span');var i=document.createElement('i');i.style.background=trRC[r];s.appendChild(i);s.appendChild(document.createTextNode(trRL[r]));leg.appendChild(s)})
    }else ser=[{name:x.l,color:x.c,vals:Mx.flow.slice(N)}];
    o.type='bar'
  }
  $('trval').textContent=val;$('trdl').textContent=dl.t;$('trdl').className='tr-dl '+dl.c;$('trsub').textContent=sub;
  trDraw(host,labels,full,ser,o)
}
function trRowsRender(){
  var C=$('trrows'),p=trS.plan,N=p.N;C.textContent='';
  trM.forEach(function(x){
    var Mx=trS.M[x.k],r=el('button','pgrow'),l=el('div'),m=el('div','pm');r.type='button';
    l.appendChild(el('div','tr-t',x.l));
    var sm=el('small'),v,dl,vals;
    if(!Mx){sm.textContent='Waiting for the report index';v='-';vals=[]}
    else if(x.level){
      var c=trSum(Mx.flow,N,2*N),pv=trSum(Mx.flow,0,N),ca=c.n?c.s/c.n:null,pa=pv.n?pv.s/pv.n:null;
      dl=trDelta(ca,pa,x.good);v=ca==null?'-':num(Math.round(ca*10)/10);vals=Mx.flow.slice(N)
    }else{
      var cq=trSum(Mx.flow,N,2*N),pq=trSum(Mx.flow,0,N),cs=cq.n?cq.s:null,ps=pq.n?pq.s:null;
      dl=trDelta(cs,ps,x.good);v=cs==null?'-':num(cs);vals=Mx.flow.slice(N)
    }
    if(dl){sm.appendChild(el('span','tr-dl '+dl.c,dl.t));sm.appendChild(document.createTextNode(' vs previous'))}
    l.appendChild(sm);r.appendChild(l);
    var sk=el('span','tr-sp');sk.innerHTML=trSpark(vals,x.c);m.appendChild(sk);m.appendChild(el('b','tr-v',v));r.appendChild(m);
    r.onclick=function(){trS.metric=x.k;if(!x.cum)trS.mode='flow';trMetSync();trChartRender();$('trcard').scrollIntoView({behavior:'smooth',block:'start'})};
    C.appendChild(r)
  })
}
function rpRender(){
  var d=trS.data,C=$('rpbox'),p=trS.plan,N=p.N;C.textContent='';
  if(!d.reportsIndexed){C.appendChild(el('div','fine','Report totals need the report index, which is still being built. Open the Reports tab once, then refresh.'));return}
  var tot={},open={},all=0,op=0;
  (d.reportTotals||[]).forEach(function(r){var k=trRL[r.reason]?r.reason:'other';tot[k]=(tot[k]||0)+r.total;open[k]=(open[k]||0)+r.open;all+=r.total;op+=r.open});
  var st=el('div','stats');
  [['Total reports',all],['Open',op],['Dismissed',all-op]].forEach(function(x){var s=el('div','stat');s.appendChild(el('b',null,num(x[1])));s.appendChild(el('span',null,x[0]));st.appendChild(s)});
  C.appendChild(st);
  var gap=el('div');gap.style.height='10px';C.appendChild(gap);
  trRO.forEach(function(k){
    var t=tot[k]||0,o=open[k]||0,inR=trSum(trS.RS[k],N,2*N).s;
    var r=el('div','tr-rr sev-'+k),h=el('div','tr-rt'),n=el('span','tr-rn');
    n.appendChild(document.createElement('i'));n.appendChild(document.createTextNode(trRL[k]));h.appendChild(n);h.appendChild(el('b',null,num(t)));r.appendChild(h);
    r.appendChild(el('small',null,num(o)+' open - '+num(t-o)+' dismissed - '+num(inR)+' in this range'));
    var bar=el('div','tr-bar'),fi=document.createElement('i');fi.style.width=(all?Math.round(t/all*100):0)+'%';bar.appendChild(fi);r.appendChild(bar);
    C.appendChild(r)
  })
}

/* ---------- Wiring ---------- */
fitMO=new MutationObserver(fitSoon);fitMO.observe(document.body,{childList:true,characterData:true,subtree:true});
window.addEventListener('resize',fitSoon);
(function(){var f=showTab;showTab=function(){var r=f.apply(this,arguments);fitSoon();return r}})();
window.addEventListener('scroll',function(){var b=$('bar');if(window.scrollY>36)b.setAttribute('data-solid','');else b.removeAttribute('data-solid')},{passive:true});
[].forEach.call(document.querySelectorAll('.tab'),function(b){b.onclick=function(){showTab(b.getAttribute('data-t'));navPush();window.scrollTo(0,0)}});
$('back').onclick=goBack;
$('rf').onclick=function(){
  if(cur==='overview'){loadOverview();ovList(true)}
  else if(cur==='reports')loadReports(true);
  else if(cur==='lookup'){if(lkSlug)doLookup(lkSlug);else msg('Enter a slug or link first')}
  else if(cur==='ads')loadAds(true);
  else if(cur==='audit')loadAudit(true)
};
$('so').onclick=function(){
  sessionStorage.removeItem('adm');tok='';all=[];next=null;rIdx=false;rAgg=null;rGen++;navLog=[];lkSlug='';lkOwner=false;cur='reports';openSet={};auAll=[];auFilter='';recents=[];repSub='';
  ['list','lkowner','adlist','aulist','aukeys','qbar','qkeys','ovstats','ovlist','trchart','trleg','trrows','rpbox'].forEach(function(i){$(i).textContent=''});trS.data=null;trS.M=null;trS.end=null;trS.gen++;
  ovS.loaded=false;ovS.view='users';ovS.q='';ovS.fil='';ovS.sort='new';ovS.gen++;$('ovq').value='';pickSet('ovsort','new');pickSet('ovfilter','');$('ovcount').textContent='';$('ovnote').textContent='';ovSync();
  $('queue').hidden=true;$('freason').value='';$('fq').value='';$('adq').value='';
  lookupHint();renderRecents();setBadge(0);document.body.dataset.alert='';$('tok').value='';
  navSync();loggedIn(false);msg('Signed out','ok')
};
$('go').onclick=function(){
  var v=$('tok').value.trim();
  if(!v){msg('Enter your admin token');return}
  tok=v;var b=$('go');b.disabled=true;b.textContent='Checking';
  loadReports(true).then(function(){b.disabled=false;b.textContent='Sign in'})
};
clearableAll();
$('tok').onkeydown=function(e){if(e.key==='Enter')$('go').onclick()};
$('more').onclick=function(){loadReports(false)};
$('admore').onclick=function(){loadAds(false)};
$('aumore').onclick=function(){loadAudit(false)};
$('ovmore').onclick=function(){ovList(false)};
$('ovsort').onclick=function(){pick('ovsort',function(){ovS.sort=$('ovsort').value;ovList(true)})};
$('ovfilter').onclick=function(){pick('ovfilter',function(){ovS.fil=$('ovfilter').value;ovList(true)})};
$('ovq').oninput=function(){clearTimeout(ovS.t);ovS.t=setTimeout(function(){ovS.q=$('ovq').value.trim().toLowerCase();ovList(true)},300)};
[].forEach.call($('ovseg').children,function(b){b.onclick=function(){var v=b.getAttribute('data-v');if(ovS.view===v)return;ovS.view=v;ovS.q='';$('ovq').value='';ovSync();ovList(true)}});
$('adst').onclick=function(){pick('adst',function(){loadAds(true)})};
$('adq').oninput=function(){clearTimeout(adT);adT=setTimeout(function(){loadAds(true)},300)};
$('fstatus').onclick=function(){pick('fstatus',renderAll)};
$('fsort').onclick=function(){pick('fsort',repFilter)};
$('fgroup').onchange=renderAll;
$('fq').oninput=function(){renderAll();if(rIdx){clearTimeout(qT);qT=setTimeout(function(){loadReports(true)},300)}};
$('fdis').onchange=function(){loadReports(true)};
$('lkgo').onclick=function(){doLookup($('lkslug').value)};
$('lkslug').onkeydown=function(e){if(e.key==='Enter')doLookup($('lkslug').value)};
$('relgo').onclick=function(){return release(slugFrom($('relslug').value),function(){$('relslug').value=''})};
$('imgs').onchange=function(){
  var b=this;
  if(!b.checked){refreshFrames();return}
  ask({title:'Show embedded images?',text:'Embedded images in snapshots (including ones from CSAM reports) will be displayed.',ok:'Show images',danger:true}).then(function(ok){if(!ok)b.checked=false;else refreshFrames()})
};
$('ext').onchange=function(){
  var b=this;
  if(!b.checked){refreshFrames();return}
  ask({title:'Load external images?',text:'External images will be fetched by the worker from whatever hosts the page points at. Those hosts see the worker (not your IP) and that a preview was opened, and content from CSAM reports may display.',ok:'Load images',danger:true}).then(function(ok){if(!ok)b.checked=false;else refreshFrames()})
};
$('purgego').onclick=function(){
  ask({title:'Run the purge now?',text:'Permanently deletes pages unpublished more than 30 days ago (except held or locked ones), accounts past their 30-day deletion window, stale like/follow timestamps, backup images older than 14 days that no note references, presence records older than 90 days, alerts older than a year, activity log entries older than 800 days, and dismissed CSAM report index rows older than 18 months.',ok:'Run purge',danger:true}).then(function(ok){
    if(!ok)return;
    msg('Running purge\u2026','ok');
    api('/admin/purge',{method:'POST'}).then(function(o){msg(o.ok?'Purge done, '+o.j.purged+(o.j.purged===1?' item':' items')+' removed':(o.j.error||'Purge failed'))}).catch(function(){msg('Network error, check your connection')})
  })
};
$('msg').onclick=function(){msg('')};
lookupHint();
if(tok){loggedIn(true);loadReports(true)}
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
        return handleCheckSlug(env, decodeURIComponent(pathname.slice('/check-slug/'.length)), request);
      }
      if (method === 'GET' && pathname.startsWith('/meta/')) {
        return handleMeta(env, decodeURIComponent(pathname.slice('/meta/'.length)));
      }
      if (method === 'POST' && pathname === '/publish') {
        return handlePublish(env, request);
      }
      if (method === 'POST' && pathname.startsWith('/publish/') && pathname.endsWith('/relink')
          && pathname.length > '/publish/'.length + '/relink'.length) {
        return handleRelink(env, request, decodeURIComponent(pathname.slice('/publish/'.length, -'/relink'.length)));
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
      if (method === 'GET' && pathname === '/alerts') {
        return handleAlertsList(env, request, url);
      }
      if (method === 'GET' && pathname === '/alerts/unread') {
        return handleAlertsUnread(env, request);
      }
      if (method === 'POST' && pathname === '/alerts/seen') {
        return handleAlertsSeen(env, request);
      }
      if (method === 'DELETE' && pathname.startsWith('/alerts/')) {
        return handleAlertDelete(env, request, decodeURIComponent(pathname.slice('/alerts/'.length)));
      }
      if (method === 'POST' && pathname === '/presence') {
        return handlePresence(env, request);
      }
      if (method === 'POST' && pathname === '/webhooks/revenuecat') {
        return handleRevenueCatWebhook(env, request);
      }
      // Manual trigger for everything scheduled() runs nightly (see below):
      // handlePurge plus pruneAll; the count covers both.
      // POST with the admin token in the X-Admin-Token header, like
      // the other admin endpoints, so the token never lands in a URL, browser
      // history or logs.
      //   curl -X POST -H "X-Admin-Token: $TOKEN" https://<worker>/admin/purge
      if (method === 'POST' && pathname === '/admin/purge') {
        const auth = await adminAuthOk(env, request);
        if (auth === 'limited') return textError(429, 'too many failed attempts, try again in 5 minutes');
        if (auth !== 'ok') return textError(403, 'invalid admin token');
        const purged = (await handlePurge(env)) + (await pruneAll(env));
        await audit(env, 'purge', null, purged + ' removed');
        return json({ ok: true, purged });
      }
      if (method === 'GET' && pathname === '/admin') return handleAdminPage();
      if (method === 'GET' && pathname === '/admin/reports') return handleAdminReports(env, request, url);
      if (method === 'POST' && pathname === '/admin/reports/reindex') return handleAdminReportsReindex(env, request);
      if (method === 'GET' && pathname === '/admin/img') return handleAdminImage(env, request, url);
      if (method === 'GET' && pathname === '/admin/lookup') return handleAdminLookup(env, request, url);
      if (method === 'GET' && pathname === '/admin/owner') return handleAdminOwner(env, request, url);
      if (method === 'GET' && pathname === '/admin/media') return handleAdminMedia(env, request, url);
      if (method === 'GET' && pathname === '/admin/ads') return handleAdminAds(env, request, url);
      if (method === 'GET' && pathname === '/admin/audit') return handleAdminAudit(env, request, url);
      if (method === 'GET' && pathname === '/admin/stats') return handleAdminStats(env, request);
      if (method === 'GET' && pathname === '/admin/trends') return handleAdminTrends(env, request, url);
      if (method === 'GET' && pathname === '/admin/users') return handleAdminUsers(env, request, url);
      if (method === 'GET' && pathname === '/admin/notes') return handleAdminNotes(env, request, url);
      if (method === 'POST' && pathname === '/admin/owner/action') return handleAdminOwnerAction(env, request);
      if (method === 'POST' && pathname === '/admin/story') return handleAdminStory(env, request);
      if (method === 'POST' && pathname === '/admin/ad') return handleAdminAd(env, request);
      if (method === 'POST' && pathname === '/admin/ncmec') return handleAdminNcmec(env, request);
      if (method === 'POST' && pathname === '/admin/undismiss') return handleAdminUndismiss(env, request);
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
    ctx.waitUntil(pruneAll(env));
  }
};
