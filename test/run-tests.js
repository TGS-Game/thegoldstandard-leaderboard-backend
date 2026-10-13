// Deterministic local test suite, run over real HTTPS with a self-signed cert.
// Covers: game-endpoint regression, /health, password login, SSO
// (valid/expired/replay/tampered/alg:none/wrong-aud), token auth in parallel,
// cookie attributes (HttpOnly; Secure; SameSite=None; Partitioned), and the
// rule that CSP frame-ancestors is set on admin pages only. Stage 1 security:
// GUID masking in /get, admin-only /entry/delete + /entry/update-username, the
// entry history trail, and the Unity multipart upload shape.
//
// Run: node test/run-tests.js

const fs = require("fs");
const path = require("path");
const https = require("https");
const crypto = require("crypto");

const { createApp } = require("../src/app");
const { LeaderboardService } = require("../src/service");
const { FakeStorage } = require("./fake-storage");

const HUB_ORIGIN = "https://admin-panel-production-39e5.up.railway.app";
const ADMIN_PASSWORD = "test-password-do-not-ship";
const ADMIN_TOKEN = "test-admin-token";
const SESSION_SECRET = "test-session-secret";
const SSO_SECRET = "test-sso-secret";
const PUBLIC_KEY = "testpublickey123";

const testConfig = {
  port: 0,
  corsOrigin: "*",
  databaseUrl: "",
  allowedPublicKeys: [],
  adminToken: ADMIN_TOKEN,
  adminPassword: ADMIN_PASSWORD,
  sessionSecret: SESSION_SECRET,
  sessionTtlSeconds: 43200,
  ssoSecret: SSO_SECRET,
  ssoAudience: "leaderboard",
  hubOrigin: HUB_ORIGIN,
  maxUsernameLength: 127,
  maxExtraLength: 100
};

// --- tiny assert framework --------------------------------------------------
let pass = 0;
let fail = 0;
const failures = [];
function check(name, cond, detail) {
  if (cond) {
    pass++;
    console.log(`  PASS  ${name}`);
  } else {
    fail++;
    failures.push(name + (detail ? ` -> ${detail}` : ""));
    console.log(`  FAIL  ${name}${detail ? ` -> ${detail}` : ""}`);
  }
}

// --- minimal HTTPS client ---------------------------------------------------
function request(base, { method = "GET", path: p = "/", headers = {}, body, cookie } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(p, base);
    const allHeaders = { ...headers };
    if (cookie) {
      allHeaders["Cookie"] = cookie;
    }
    let payload;
    if (body !== undefined) {
      if (typeof body === "string") {
        payload = body;
      } else {
        payload = JSON.stringify(body);
        allHeaders["Content-Type"] = allHeaders["Content-Type"] || "application/json";
      }
      allHeaders["Content-Length"] = Buffer.byteLength(payload);
    }
    const req = https.request(
      url,
      { method, headers: allHeaders, rejectUnauthorized: false },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            setCookie: res.headers["set-cookie"] || [],
            body: data
          })
        );
      }
    );
    req.on("error", reject);
    if (payload !== undefined) {
      req.write(payload);
    }
    req.end();
  });
}

// extract the session cookie "name=value" pair from a Set-Cookie array
function sessionCookiePair(setCookie) {
  const line = setCookie.find((c) => c.startsWith("tgs_admin_session="));
  if (!line) return null;
  return line.split(";")[0];
}

// --- JWT minting for SSO tests ----------------------------------------------
function b64url(input) {
  return Buffer.from(input).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function mintJwt({ secret = SSO_SECRET, alg = "HS256", aud = "leaderboard", expDelta = 60, jti, sign = true }) {
  const header = b64url(JSON.stringify({ alg, typ: "JWT" }));
  const now = Math.floor(Date.now() / 1000);
  const payload = b64url(
    JSON.stringify({
      aud,
      jti: jti || crypto.randomUUID(),
      iat: now,
      exp: now + expDelta
    })
  );
  let sig = "";
  if (alg === "none") {
    sig = "";
  } else if (sign) {
    sig = b64url(crypto.createHmac("sha256", secret).update(`${header}.${payload}`).digest());
  } else {
    sig = b64url("invalid-signature");
  }
  return `${header}.${payload}.${sig}`;
}

// --- server bootstrap -------------------------------------------------------
function startServer(config, storage) {
  const service = new LeaderboardService(storage, config);
  const app = createApp(service, config);
  const tlsOptions = {
    key: fs.readFileSync(path.join(__dirname, "tmp", "key.pem")),
    cert: fs.readFileSync(path.join(__dirname, "tmp", "cert.pem"))
  };
  return new Promise((resolve) => {
    const server = https.createServer(tlsOptions, app);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ server, base: `https://127.0.0.1:${port}` });
    });
  });
}

// Builds a multipart/form-data body the way the shipped Unity client does
// (UnityWebRequest.Post with text form sections, each with its own text/plain
// part header). Spread the result into request().
function multipartForm(fields) {
  const boundary = `----tgsTestBoundary${crypto.randomBytes(8).toString("hex")}`;
  let body = "";
  for (const [name, value] of Object.entries(fields)) {
    body += `--${boundary}\r\n`;
    body += `Content-Disposition: form-data; name="${name}"\r\n`;
    body += `Content-Type: text/plain; charset="utf-8"\r\n\r\n`;
    body += `${value}\r\n`;
  }
  body += `--${boundary}--\r\n`;
  return { headers: { "Content-Type": `multipart/form-data; boundary=${boundary}` }, body };
}

const CLIENT_KEYS = "Username,Score,Date,Extra,Rank,UserGuid";
const MASK_PATTERN = /^[0-9a-f]{32}$/;
const adminAuth = { Authorization: `Bearer ${ADMIN_TOKEN}` };

// Log capture: denied-route lines (console.warn) and history-failure lines
// (console.error) are asserted on instead of cluttering the output.
const warnLines = [];
const errorLines = [];
console.warn = (...args) => warnLines.push(args.join(" "));
console.error = (...args) => errorLines.push(args.map(String).join(" "));

async function getJson(base, urlPath, headers) {
  const res = await request(base, { path: urlPath, headers });
  let json = null;
  try { json = JSON.parse(res.body); } catch (e) { json = null; }
  return { ...res, json };
}

async function main() {
  const storage = new FakeStorage();
  const { server, base } = await startServer(testConfig, storage);

  console.log("\n=== GAME ENDPOINT REGRESSION (must not break) ===");
  {
    const root = await request(base, { path: "/" });
    check("GET / -> 200 OK", root.status === 200 && root.body === "OK", `status=${root.status} body=${root.body}`);
    check("GET / has NO CSP frame-ancestors", !root.headers["content-security-policy"]);

    const authz = await request(base, { path: "/authorize" });
    const isGuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(authz.body.trim());
    check("GET /authorize -> 200 GUID", authz.status === 200 && isGuid, `body=${authz.body}`);

    const upload = await request(base, {
      method: "POST",
      path: "/entry/upload",
      body: { publicKey: PUBLIC_KEY, userGuid: "guid-1", username: "Alice", score: 100, extra: "x" }
    });
    check("POST /entry/upload -> 200", upload.status === 200, `status=${upload.status} body=${upload.body}`);
    check("POST /entry/upload has NO Set-Cookie", upload.setCookie.length === 0);
    check("POST /entry/upload has NO CSP", !upload.headers["content-security-policy"]);

    await request(base, {
      method: "POST",
      path: "/entry/upload",
      body: { publicKey: PUBLIC_KEY, userGuid: "guid-2", username: "Bob", score: 250, extra: "" }
    });

    const get = await request(base, { path: `/get?publicKey=${PUBLIC_KEY}` });
    let parsed;
    try { parsed = JSON.parse(get.body); } catch (e) { parsed = null; }
    check("GET /get -> 200 array of 2, ranked", get.status === 200 && Array.isArray(parsed) && parsed.length === 2 && parsed[0].Username === "Bob" && parsed[0].Rank === 1, `body=${get.body}`);
    check("GET /get has NO CSP", !get.headers["content-security-policy"]);

    const count = await request(base, { path: `/entry/count?publicKey=${PUBLIC_KEY}` });
    check("GET /entry/count -> 200 '2'", count.status === 200 && count.body.trim() === "2", `body=${count.body}`);

    const personal = await request(base, { path: `/entry/get?publicKey=${PUBLIC_KEY}&userGuid=guid-1` });
    let pe; try { pe = JSON.parse(personal.body); } catch (e) { pe = null; }
    check("GET /entry/get -> 200 entry", personal.status === 200 && pe && pe.Username === "Alice", `body=${personal.body}`);

    // Admin-only since stage 1: without admin auth -> 403 and the row is untouched.
    const rename = await request(base, {
      method: "POST",
      path: "/entry/update-username",
      body: { publicKey: PUBLIC_KEY, userGuid: "guid-1", username: "Alice2" }
    });
    check("POST /entry/update-username (no auth) -> 403 text/plain", rename.status === 403 && /text\/plain/.test(rename.headers["content-type"] || "") && rename.body === "Forbidden.", `status=${rename.status} body=${rename.body}`);
    const afterRename = await storage.getEntry(PUBLIC_KEY, "guid-1");
    check("denied rename left the row unchanged", afterRename && afterRename.username === "Alice" && afterRename.score === 100 && afterRename.extra === "x", JSON.stringify(afterRename));

    const profile = await request(base, {
      method: "POST",
      path: "/player-profile",
      body: { name: "Carol", email: "carol@example.com", country: "US", consentAccepted: true }
    });
    check("POST /player-profile -> 200 {ok:true}", profile.status === 200 && JSON.parse(profile.body).ok === true, `body=${profile.body}`);
    check("POST /player-profile has NO CSP", !profile.headers["content-security-policy"]);

    const del = await request(base, {
      method: "POST",
      path: "/entry/delete",
      body: { publicKey: PUBLIC_KEY, userGuid: "guid-2" }
    });
    check("POST /entry/delete (no auth) -> 403 text/plain", del.status === 403 && /text\/plain/.test(del.headers["content-type"] || "") && del.body === "Forbidden.", `status=${del.status} body=${del.body}`);
    const afterDelete = await storage.getEntry(PUBLIC_KEY, "guid-2");
    check("denied delete left the row in place", afterDelete && afterDelete.username === "Bob" && afterDelete.score === 250, JSON.stringify(afterDelete));

    const delWrongToken = await request(base, {
      method: "POST",
      path: "/entry/delete",
      headers: { Authorization: "Bearer nope", "X-Admin-Token": "nope" },
      body: { publicKey: PUBLIC_KEY, userGuid: "guid-2" }
    });
    check("POST /entry/delete (wrong token) -> 403, row kept", delWrongToken.status === 403 && Boolean(await storage.getEntry(PUBLIC_KEY, "guid-2")), `status=${delWrongToken.status}`);

    const delMultipart = await request(base, {
      method: "POST",
      path: "/entry/delete",
      ...multipartForm({ publicKey: PUBLIC_KEY, userGuid: "guid-2" })
    });
    check("POST /entry/delete (multipart, no auth) -> 403, row kept", delMultipart.status === 403 && Boolean(await storage.getEntry(PUBLIC_KEY, "guid-2")), `status=${delMultipart.status}`);

    check("denied attempts wrote NO rename/delete history", storage.history.every((h) => h.action === "upload_insert"), JSON.stringify(storage.history.map((h) => h.action)));
    const denials = warnLines.filter((l) => l.startsWith("Denied "));
    check("each denial logged one line", denials.length === 4, `lines=${denials.length}`);
    check("denial log has route + 8-char key prefix only", denials.every((l) => /\/entry\/(delete|update-username)/.test(l) && l.includes("testpubl") && !l.includes(PUBLIC_KEY)), denials[0]);
    check("denial log never contains the GUID", denials.every((l) => !l.includes("guid-1") && !l.includes("guid-2")), denials[0]);
  }

  console.log("\n=== /health ===");
  {
    const h = await request(base, { path: "/health" });
    check("GET /health -> 200 {status:ok}", h.status === 200 && JSON.parse(h.body).status === "ok", `status=${h.status} body=${h.body}`);
    check("GET /health needs NO auth", h.status === 200);
    check("GET /health has NO CSP", !h.headers["content-security-policy"]);
    check("GET /health has NO Set-Cookie", h.setCookie.length === 0);
  }
  {
    // degraded data store -> non-2xx
    const badStorage = new FakeStorage({ failPing: true });
    const bad = await startServer(testConfig, badStorage);
    const h = await request(bad.base, { path: "/health" });
    check("GET /health (store down) -> 503", h.status === 503, `status=${h.status}`);
    bad.server.close();
  }

  console.log("\n=== SESSION LOGIN ===");
  let sessionCookie = null;
  {
    const guarded = await request(base, { path: "/admin/api/public-keys" });
    check("GET /admin/api without auth -> 401", guarded.status === 401, `status=${guarded.status}`);

    const adminNoAuth = await request(base, { path: "/admin" });
    check("GET /admin without session -> 302 to /admin/login", adminNoAuth.status === 302 && adminNoAuth.headers.location === "/admin/login", `status=${adminNoAuth.status} loc=${adminNoAuth.headers.location}`);
    check("GET /admin (unauth) sets CSP frame-ancestors = HUB_ORIGIN", adminNoAuth.headers["content-security-policy"] === `frame-ancestors ${HUB_ORIGIN}`, adminNoAuth.headers["content-security-policy"]);

    const loginPage = await request(base, { path: "/admin/login" });
    check("GET /admin/login -> 200 html (open route)", loginPage.status === 200 && /Sign in|Password/i.test(loginPage.body), `status=${loginPage.status}`);
    check("GET /admin/login sets CSP frame-ancestors", loginPage.headers["content-security-policy"] === `frame-ancestors ${HUB_ORIGIN}`, loginPage.headers["content-security-policy"]);

    const wrong = await request(base, {
      method: "POST",
      path: "/admin/login",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "password=" + encodeURIComponent("wrong-password")
    });
    check("POST /admin/login wrong pw -> 302 ?error=1", wrong.status === 302 && /error=1/.test(wrong.headers.location || ""), `status=${wrong.status} loc=${wrong.headers.location}`);
    check("POST /admin/login wrong pw sets NO session cookie", sessionCookiePair(wrong.setCookie) === null);

    const right = await request(base, {
      method: "POST",
      path: "/admin/login",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "password=" + encodeURIComponent(ADMIN_PASSWORD)
    });
    check("POST /admin/login correct pw -> 302 /admin", right.status === 302 && right.headers.location === "/admin", `status=${right.status} loc=${right.headers.location}`);
    const cookieLine = right.setCookie.find((c) => c.startsWith("tgs_admin_session="));
    check("login Set-Cookie present", Boolean(cookieLine), JSON.stringify(right.setCookie));
    check("cookie is HttpOnly", /;\s*HttpOnly/i.test(cookieLine || ""), cookieLine);
    check("cookie is Secure", /;\s*Secure/i.test(cookieLine || ""), cookieLine);
    check("cookie is SameSite=None", /;\s*SameSite=None/i.test(cookieLine || ""), cookieLine);
    check("cookie is Partitioned", /;\s*Partitioned/i.test(cookieLine || ""), cookieLine);
    sessionCookie = sessionCookiePair(right.setCookie);

    const adminPage = await request(base, { path: "/admin", cookie: sessionCookie });
    check("GET /admin with session -> 200 panel", adminPage.status === 200 && /TGS Leaderboard/.test(adminPage.body), `status=${adminPage.status}`);
    check("GET /admin (authed) still sets CSP", adminPage.headers["content-security-policy"] === `frame-ancestors ${HUB_ORIGIN}`);

    const keys = await request(base, { path: "/admin/api/public-keys", cookie: sessionCookie });
    check("GET /admin/api with session -> 200", keys.status === 200, `status=${keys.status} body=${keys.body}`);

    const logout = await request(base, { method: "POST", path: "/admin/logout", cookie: sessionCookie });
    const clear = logout.setCookie.find((c) => c.startsWith("tgs_admin_session="));
    check("POST /admin/logout -> 302 /admin/login", logout.status === 302 && logout.headers.location === "/admin/login", `status=${logout.status}`);
    check("logout clears cookie (Max-Age=0)", /Max-Age=0/i.test(clear || ""), clear);
  }

  console.log("\n=== TOKEN AUTH (parallel, must keep working) ===");
  {
    const bearer = await request(base, { path: "/admin/api/public-keys", headers: { Authorization: `Bearer ${ADMIN_TOKEN}` } });
    check("Bearer token -> 200", bearer.status === 200, `status=${bearer.status}`);
    const xheader = await request(base, { path: "/admin/api/public-keys", headers: { "X-Admin-Token": ADMIN_TOKEN } });
    check("X-Admin-Token -> 200", xheader.status === 200, `status=${xheader.status}`);
    const badtok = await request(base, { path: "/admin/api/public-keys", headers: { Authorization: "Bearer nope" } });
    check("wrong token -> 401", badtok.status === 401, `status=${badtok.status}`);
  }

  console.log("\n=== SSO (GET /sso) ===");
  {
    const valid = await request(base, { path: `/sso?token=${mintJwt({ jti: "jti-valid-1" })}` });
    check("valid SSO token -> 302 /admin", valid.status === 302 && valid.headers.location === "/admin", `status=${valid.status} loc=${valid.headers.location}`);
    const ssoCookie = sessionCookiePair(valid.setCookie);
    check("valid SSO sets session cookie", Boolean(ssoCookie));
    check("SSO response sets CSP frame-ancestors", valid.headers["content-security-policy"] === `frame-ancestors ${HUB_ORIGIN}`);
    // prove the SSO-issued session actually works
    const useSso = await request(base, { path: "/admin/api/public-keys", cookie: ssoCookie });
    check("SSO session reaches /admin/api -> 200", useSso.status === 200, `status=${useSso.status}`);

    // replay the SAME token (same jti already consumed) -> 401
    const replay = await request(base, { path: `/sso?token=${mintJwt({ jti: "jti-replay" })}` });
    check("first use of jti-replay -> 302", replay.status === 302);
    const replay2 = await request(base, { path: `/sso?token=${mintJwt({ jti: "jti-replay" })}` });
    check("replayed jti -> 401", replay2.status === 401, `status=${replay2.status}`);

    const expired = await request(base, { path: `/sso?token=${mintJwt({ expDelta: -120, jti: "jti-expired" })}` });
    check("expired SSO token -> 401", expired.status === 401, `status=${expired.status}`);

    const tampered = await request(base, { path: `/sso?token=${mintJwt({ sign: false, jti: "jti-tamper" })}` });
    check("tampered signature -> 401", tampered.status === 401, `status=${tampered.status}`);

    const algNone = await request(base, { path: `/sso?token=${mintJwt({ alg: "none", jti: "jti-none" })}` });
    check("alg:none token -> 401", algNone.status === 401, `status=${algNone.status}`);

    const wrongAud = await request(base, { path: `/sso?token=${mintJwt({ aud: "not-leaderboard", jti: "jti-aud" })}` });
    check("wrong audience -> 401", wrongAud.status === 401, `status=${wrongAud.status}`);

    const wrongSecret = await request(base, { path: `/sso?token=${mintJwt({ secret: "attacker-secret", jti: "jti-secret" })}` });
    check("wrong signing secret -> 401", wrongSecret.status === 401, `status=${wrongSecret.status}`);
  }

  console.log("\n=== UNITY MULTIPART UPLOAD (exact client shape) ===");
  const unityGuid = (await request(base, { path: "/authorize" })).body.trim();
  {
    const upload = await request(base, {
      method: "POST",
      path: "/entry/upload",
      ...multipartForm({
        publicKey: PUBLIC_KEY,
        username: "Dana-GB-12345",
        score: "12345",
        extra: " ",
        userGuid: unityGuid
      })
    });
    check("multipart /entry/upload (extra=' ') -> 200", upload.status === 200, `status=${upload.status} body=${upload.body}`);

    const get = await getJson(base, `/get?publicKey=${PUBLIC_KEY}&userGuid=${unityGuid}&isInAscendingOrder=0&skip=0&take=100&timePeriod=0`);
    const mine = (get.json || []).find((row) => row.Username === "Dana-GB-12345");
    check("GET /get returns the uploaded row", get.status === 200 && Boolean(mine), get.body);
    check("Extra comes back as exactly ' ' (not trimmed)", mine && mine.Extra === " ", JSON.stringify(mine));
    check("Score is the integer sent", mine && mine.Score === 12345 && mine.Rank === 1, JSON.stringify(mine));
    check("viewer's own row carries the REAL guid", mine && mine.UserGuid === unityGuid, JSON.stringify(mine));

    const nextGuid = (await request(base, { path: "/authorize" })).body.trim();
    check("GET /authorize after upload -> a brand-new GUID", /^[0-9a-f-]{36}$/.test(nextGuid) && nextGuid !== unityGuid, nextGuid);
  }

  console.log("\n=== GUID MASKING IN GET /get ===");
  {
    const realGuids = ["guid-1", "guid-2", unityGuid];

    const anon = await getJson(base, `/get?publicKey=${PUBLIC_KEY}&take=50`);
    check("GET /get (no userGuid) -> 200 array of 3", anon.status === 200 && Array.isArray(anon.json) && anon.json.length === 3, anon.body);
    check("no real guid appears when userGuid is omitted", anon.json.every((row) => !realGuids.includes(row.UserGuid)) && !anon.body.includes(unityGuid) && !anon.body.includes("guid-1") && !anon.body.includes("guid-2"), anon.body);
    check("every masked UserGuid is a 32-char hex string", anon.json.every((row) => typeof row.UserGuid === "string" && MASK_PATTERN.test(row.UserGuid)), anon.body);
    check("masked tokens differ per player", new Set(anon.json.map((row) => row.UserGuid)).size === 3, anon.body);
    check("response keys and order unchanged", anon.json.every((row) => Object.keys(row).join(",") === CLIENT_KEYS), anon.body);
    check("response value types unchanged", anon.json.every((row) => typeof row.Username === "string" && Number.isInteger(row.Score) && Number.isInteger(row.Date) && typeof row.Extra === "string" && Number.isInteger(row.Rank)), anon.body);

    const anon2 = await getJson(base, `/get?publicKey=${PUBLIC_KEY}&take=50`);
    check("masked tokens are stable across two calls", anon.body === anon2.body, anon2.body);

    const asAlice = await getJson(base, `/get?publicKey=${PUBLIC_KEY}&userGuid=guid-1`);
    const aliceRow = asAlice.json.find((row) => row.Username === "Alice");
    const others = asAlice.json.filter((row) => row.Username !== "Alice");
    check("viewer row has the real guid when userGuid is passed", aliceRow && aliceRow.UserGuid === "guid-1", asAlice.body);
    check("no other row equals another player's real guid", others.length === 2 && others.every((row) => !realGuids.includes(row.UserGuid) && MASK_PATTERN.test(row.UserGuid)), asAlice.body);
    check("other players' guids absent from the raw body", !asAlice.body.includes("guid-2") && !asAlice.body.includes(unityGuid), asAlice.body);
    const bobAnon = anon.json.find((row) => row.Username === "Bob");
    const bobSeenByAlice = asAlice.json.find((row) => row.Username === "Bob");
    check("a player's mask is the same for every viewer", bobAnon.UserGuid === bobSeenByAlice.UserGuid);
    check("keys/order unchanged with userGuid passed", asAlice.json.every((row) => Object.keys(row).join(",") === CLIENT_KEYS), asAlice.body);

    const padded = await getJson(base, `/get?publicKey=${PUBLIC_KEY}&userGuid=%20guid-1%20`);
    check("userGuid is trimmed the same way as on upload", padded.json.find((row) => row.Username === "Alice").UserGuid === "guid-1", padded.body);

    const wrongViewer = await getJson(base, `/get?publicKey=${PUBLIC_KEY}&userGuid=not-a-real-guid`);
    check("unknown userGuid -> every row masked", wrongViewer.json.every((row) => MASK_PATTERN.test(row.UserGuid)), wrongViewer.body);

    const personal = await getJson(base, `/entry/get?publicKey=${PUBLIC_KEY}&userGuid=guid-1`);
    check("GET /entry/get still returns the caller's own guid", personal.status === 200 && personal.json.Username === "Alice" && personal.json.UserGuid === "guid-1" && Object.keys(personal.json).join(",") === CLIENT_KEYS, personal.body);
    const viaMask = await getJson(base, `/entry/get?publicKey=${PUBLIC_KEY}&userGuid=${bobAnon.UserGuid}`);
    check("GET /entry/get with a masked token finds nothing", viaMask.status === 200 && viaMask.json.Username === "" && viaMask.json.Rank === 0 && !viaMask.body.includes("guid-2"), viaMask.body);

    const adminList = await getJson(base, `/admin/api/entries?publicKey=${PUBLIC_KEY}`, adminAuth);
    check("admin listing still returns REAL guids", adminList.status === 200 && realGuids.every((guid) => adminList.json.some((row) => row.userGuid === guid)), adminList.body);
  }

  console.log("\n=== ADMIN 'yes' FLAG (website contract) ===");
  {
    const upsert = await request(base, {
      method: "POST",
      path: "/admin/api/entries",
      headers: adminAuth,
      body: { publicKey: PUBLIC_KEY, userGuid: "guid-2", username: "Bob", score: 250, extra: "yes" }
    });
    check("admin upsert extra='yes' -> 200 {ok:true}", upsert.status === 200 && JSON.parse(upsert.body).ok === true, `status=${upsert.status} body=${upsert.body}`);

    const site = await getJson(base, `/get?publicKey=${PUBLIC_KEY}&take=50`);
    const bob = site.json.find((row) => row.Username === "Bob");
    check("GET /get returns Extra 'yes' for that row", bob && bob.Extra === "yes", site.body);
    check("masking does not affect Username/Extra/Score", bob && bob.Score === 250 && MASK_PATTERN.test(bob.UserGuid), JSON.stringify(bob));
    const dana = site.json.find((row) => row.Username === "Dana-GB-12345");
    check("un-approved row still has Extra ' '", dana && dana.Extra === " ", JSON.stringify(dana));
  }

  console.log("\n=== ADMIN-ONLY /entry/update-username + /entry/delete ===");
  {
    // overwrite first so history has an upload_overwrite row
    const overwrite = await request(base, {
      method: "POST",
      path: "/entry/upload",
      headers: { "X-Forwarded-For": "203.0.113.7", "User-Agent": "UnityPlayer/2022.3 (UnityWebRequest/1.0)" },
      body: { publicKey: PUBLIC_KEY, userGuid: "guid-1", username: "Alice", score: 150, extra: "x" }
    });
    check("re-upload with same guid -> 200", overwrite.status === 200, `status=${overwrite.status}`);

    const rename = await request(base, {
      method: "POST",
      path: "/entry/update-username",
      headers: adminAuth,
      body: { publicKey: PUBLIC_KEY, userGuid: "guid-1", username: "Alice2" }
    });
    check("rename with Bearer admin token -> 200 OK", rename.status === 200 && rename.body === "OK", `status=${rename.status} body=${rename.body}`);
    check("rename applied", (await storage.getEntry(PUBLIC_KEY, "guid-1")).username === "Alice2");

    const renameCookie = await request(base, {
      method: "POST",
      path: "/entry/update-username",
      cookie: sessionCookie,
      ...multipartForm({ publicKey: PUBLIC_KEY, userGuid: "guid-1", username: "Alice3" })
    });
    check("rename with session cookie only (multipart) -> 403, name kept", renameCookie.status === 403 && (await storage.getEntry(PUBLIC_KEY, "guid-1")).username === "Alice2", `status=${renameCookie.status}`);

    const del = await request(base, {
      method: "POST",
      path: "/entry/delete",
      headers: { "X-Admin-Token": ADMIN_TOKEN },
      body: { publicKey: PUBLIC_KEY, userGuid: "guid-2" }
    });
    check("delete with X-Admin-Token -> 200 OK", del.status === 200 && del.body === "OK", `status=${del.status} body=${del.body}`);
    check("delete applied", (await storage.getEntry(PUBLIC_KEY, "guid-2")) === null);

    const delMissing = await request(base, {
      method: "POST",
      path: "/entry/delete",
      headers: adminAuth,
      body: { publicKey: PUBLIC_KEY, userGuid: "guid-2" }
    });
    check("admin delete of a missing entry -> 404 (as before)", delMissing.status === 404, `status=${delMissing.status}`);
  }

  console.log("\n=== ENTRY HISTORY ===");
  {
    const noAuth = await request(base, { path: "/admin/api/entry-history" });
    check("GET /admin/api/entry-history without auth -> 401", noAuth.status === 401, `status=${noAuth.status}`);
    const badAuth = await request(base, { path: "/admin/api/entry-history", headers: { Authorization: "Bearer nope" } });
    check("GET /admin/api/entry-history wrong token -> 401", badAuth.status === 401, `status=${badAuth.status}`);

    const all = await getJson(base, "/admin/api/entry-history", adminAuth);
    check("GET /admin/api/entry-history with auth -> 200 array", all.status === 200 && Array.isArray(all.json), all.body);
    const actions = all.json.map((h) => h.action);
    // 3 inserts, 1 admin overwrite, 1 upload overwrite, 1 rename, 1 delete
    check("one history row per mutation (7)", all.json.length === 7, JSON.stringify(actions));
    check("newest first", all.json.every((h, i) => i === 0 || all.json[i - 1].at > h.at || (all.json[i - 1].at === h.at && all.json[i - 1].id > h.id)), JSON.stringify(all.json.map((h) => [h.at, h.id])));
    check("failed delete (404) wrote no history", actions.filter((a) => a === "delete").length === 1, JSON.stringify(actions));

    const alice = await getJson(base, `/admin/api/entry-history?publicKey=${PUBLIC_KEY}&userGuid=guid-1`, adminAuth);
    const insert = alice.json.find((h) => h.action === "upload_insert");
    check("upload insert recorded (no old row, new values)", insert && insert.source === "public" && insert.oldUsername === null && insert.oldScore === null && insert.newUsername === "Alice" && insert.newScore === 100 && insert.newExtra === "x" && Boolean(insert.entryId), JSON.stringify(insert));
    const overwrite = alice.json.find((h) => h.action === "upload_overwrite");
    check("upload overwrite recorded (old + new row)", overwrite && overwrite.source === "public" && overwrite.oldUsername === "Alice" && overwrite.oldScore === 100 && overwrite.oldExtra === "x" && Number.isInteger(overwrite.oldCreatedAt) && Number.isInteger(overwrite.oldUpdatedAt) && overwrite.newScore === 150 && overwrite.entryId === insert.entryId, JSON.stringify(overwrite));
    check("request metadata captured (x-forwarded-for + socket, user-agent)", overwrite && overwrite.ip.startsWith("203.0.113.7 via ") && overwrite.ip.length <= 200 && overwrite.userAgent === "UnityPlayer/2022.3 (UnityWebRequest/1.0)", JSON.stringify(overwrite));
    const renames = alice.json.filter((h) => h.action === "rename");
    check("admin rename recorded (old + new name)", renames.length === 1 && renames[0].source === "admin" && renames[0].oldUsername === "Alice" && renames[0].newUsername === "Alice2" && renames[0].newScore === 150, JSON.stringify(renames));
    check("userGuid filter returns only that player's rows", alice.json.length === 3 && alice.json.every((h) => h.userGuid === "guid-1"), JSON.stringify(alice.json.map((h) => h.action)));

    const bob = await getJson(base, `/admin/api/entry-history?publicKey=${PUBLIC_KEY}&userGuid=guid-2`, adminAuth);
    const adminEdit = bob.json.find((h) => h.action === "admin_upsert_overwrite");
    check("admin upsert recorded", adminEdit && adminEdit.source === "admin" && adminEdit.oldExtra === "" && adminEdit.newExtra === "yes", JSON.stringify(adminEdit));
    const deleted = bob.json.find((h) => h.action === "delete");
    check("admin delete recorded with the full old row (restorable)", deleted && deleted.source === "admin" && deleted.oldUsername === "Bob" && deleted.oldScore === 250 && deleted.oldExtra === "yes" && deleted.newUsername === null && deleted.newScore === null && deleted.newExtra === null, JSON.stringify(deleted));

    const limited = await getJson(base, "/admin/api/entry-history?limit=2", adminAuth);
    check("limit is honoured", limited.json.length === 2 && limited.json[0].id === all.json[0].id, limited.body);
    const huge = await getJson(base, "/admin/api/entry-history?limit=999999", adminAuth);
    check("oversized limit is accepted (capped at 500)", huge.status === 200 && huge.json.length === 7, `status=${huge.status}`);

    // admin API paths: insert + delete through /admin/api/entries
    await request(base, { method: "POST", path: "/admin/api/entries", headers: adminAuth, body: { publicKey: PUBLIC_KEY, userGuid: "guid-admin", username: "Made", score: 5, extra: "" } });
    const adminDel = await request(base, { method: "DELETE", path: `/admin/api/entries/${PUBLIC_KEY}/guid-admin`, headers: adminAuth });
    const made = await getJson(base, "/admin/api/entry-history?userGuid=guid-admin", adminAuth);
    check("admin API insert + delete recorded", adminDel.status === 200 && made.json.length === 2 && made.json[0].action === "admin_delete" && made.json[0].oldUsername === "Made" && made.json[1].action === "admin_upsert_insert", made.body);
  }

  console.log("\n=== HISTORY WRITE FAILURE MUST NOT BREAK THE GAME ===");
  {
    const brokenStorage = new FakeStorage({ failHistory: true });
    const broken = await startServer(testConfig, brokenStorage);
    const errorsBefore = errorLines.length;
    const upload = await request(broken.base, {
      method: "POST",
      path: "/entry/upload",
      ...multipartForm({ publicKey: PUBLIC_KEY, username: "Eve-US-900", score: "900", extra: " ", userGuid: "guid-broken-history" })
    });
    check("upload with failing history store -> 200", upload.status === 200 && upload.body === "OK", `status=${upload.status} body=${upload.body}`);
    const get = await getJson(broken.base, `/get?publicKey=${PUBLIC_KEY}&userGuid=guid-broken-history`);
    check("entry was still stored and is returned", get.json.length === 1 && get.json[0].Username === "Eve-US-900" && get.json[0].Extra === " " && get.json[0].UserGuid === "guid-broken-history", get.body);
    const overwrite = await request(broken.base, {
      method: "POST",
      path: "/entry/upload",
      body: { publicKey: PUBLIC_KEY, userGuid: "guid-broken-history", username: "Eve-US-950", score: 950, extra: " " }
    });
    check("overwrite with failing history store -> 200", overwrite.status === 200, `status=${overwrite.status}`);
    const logged = errorLines.slice(errorsBefore);
    check("history failure logged one line per write", logged.length === 2 && logged.every((l) => /Entry history write failed/.test(l)), JSON.stringify(logged));
    check("failure log has no full key or GUID", logged.every((l) => !l.includes(PUBLIC_KEY) && !l.includes("guid-broken-history")), JSON.stringify(logged));
    broken.server.close();
  }

  console.log("\n=== NO ADMIN AUTH CONFIGURED -> the two routes deny everyone ===");
  {
    const openConfig = { ...testConfig, adminToken: "", adminPassword: "", sessionSecret: "", ssoSecret: "" };
    const openStorage = new FakeStorage();
    const open = await startServer(openConfig, openStorage);
    await request(open.base, { method: "POST", path: "/entry/upload", body: { publicKey: PUBLIC_KEY, userGuid: "guid-x", username: "Xan", score: 1, extra: " " } });

    const del = await request(open.base, { method: "POST", path: "/entry/delete", headers: { Authorization: "Bearer ", "X-Admin-Token": "" }, body: { publicKey: PUBLIC_KEY, userGuid: "guid-x" } });
    check("POST /entry/delete -> 403 when admin is not configured", del.status === 403, `status=${del.status}`);
    const rename = await request(open.base, { method: "POST", path: "/entry/update-username", headers: { Authorization: "Bearer undefined" }, cookie: sessionCookie, body: { publicKey: PUBLIC_KEY, userGuid: "guid-x", username: "Hacked" } });
    check("POST /entry/update-username -> 403 when admin is not configured", rename.status === 403, `status=${rename.status}`);
    const row = await openStorage.getEntry(PUBLIC_KEY, "guid-x");
    check("row untouched", row && row.username === "Xan", JSON.stringify(row));
    const hist = await request(open.base, { path: "/admin/api/entry-history" });
    check("entry-history is not exposed without admin config", hist.status === 404, `status=${hist.status}`);
    const masked = await getJson(open.base, `/get?publicKey=${PUBLIC_KEY}`);
    const masked2 = await getJson(open.base, `/get?publicKey=${PUBLIC_KEY}`);
    check("masking works with the random per-process key", MASK_PATTERN.test(masked.json[0].UserGuid) && masked.body === masked2.body, masked.body);
    open.server.close();
  }

  check("no unexpected server errors were logged", errorLines.every((l) => /Entry history write failed/.test(l)), JSON.stringify(errorLines));

  server.close();

  console.log(`\n================ RESULTS ================`);
  console.log(`  PASS: ${pass}   FAIL: ${fail}`);
  if (fail > 0) {
    console.log("  Failed checks:");
    for (const f of failures) console.log(`   - ${f}`);
    process.exit(1);
  }
  console.log("  ALL GREEN");
  process.exit(0);
}

main().catch((e) => {
  // console.error is captured above, so write straight to stderr.
  process.stderr.write(`${e && e.stack ? e.stack : e}\n`);
  process.exit(1);
});
