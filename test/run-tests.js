// Deterministic local test suite, run over real HTTPS with a self-signed cert.
// Covers: game-endpoint regression, /health, password login, SSO
// (valid/expired/replay/tampered/alg:none/wrong-aud), token auth in parallel,
// the DIRECT_ADMIN_LOGIN switch (on and off, and what off must never touch),
// cookie attributes (HttpOnly; Secure; SameSite=None; Partitioned), and the
// rule that CSP frame-ancestors is set on admin pages only. Stage 1 security:
// GUID masking in /get, admin-only /entry/delete + /entry/update-username, the
// entry history trail, and the Unity multipart upload shape. Observe mode
// (log-only): every observation type, identical responses with it on and off,
// caps, bounded memory, a failing/hung observation store, redaction, admin reads.
//
// Run: node test/run-tests.js

const fs = require("fs");
const path = require("path");
const https = require("https");
const crypto = require("crypto");

const { createApp } = require("../src/app");
const auth = require("../src/auth");
const { LeaderboardService } = require("../src/service");
const { FakeStorage } = require("./fake-storage");

const HUB_ORIGIN = "https://admin-panel-production-39e5.up.railway.app";
const ADMIN_PASSWORD = "test-password-do-not-ship";
const ADMIN_TOKEN = "test-admin-token";
const SESSION_SECRET = "test-session-secret";
const SSO_SECRET = "test-sso-secret";
const PUBLIC_KEY = "testpublickey123";
// The shipped game's key (public) and an older build's key that must only be
// recorded, never blocked.
const LIVE_KEY = "536aec42d31fa4ec5c486c219f9821f6a145562fcb069c6f19f40786fdc38678";
const OLD_KEY = `ff61800f${"0".repeat(56)}`;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const unityHeaders = {
  "User-Agent": "UnityPlayer/2022.3.10f1 (UnityWebRequest/1.0, libcurl/8.4.0-DEV)",
  "X-Unity-Version": "2022.3.10f1"
};

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
      resolve({ server, service, base: `https://127.0.0.1:${port}` });
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
// Observe-mode lines (console.log, prefixed "[observe]") are captured too.
const observeLines = [];
const printLine = console.log;
console.log = (...args) => {
  const line = args.map(String).join(" ");
  if (line.startsWith("[observe]")) {
    observeLines.push(line);
  } else {
    printLine(...args);
  }
};

// Observation work runs after the response; wait until its queue is empty.
async function settle(target, maxMs = 2000) {
  const observer = target.service.observer;
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  await sleep(30);
  const deadline = Date.now() + maxMs;
  while ((observer.queue.length > 0 || observer.inFlight > 0) && Date.now() < deadline) {
    await sleep(5);
  }
}

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

  console.log("\n=== DIRECT_ADMIN_LOGIN switch ===");
  {
    const HUB_URL = "https://admin.thegoldstandard.com";
    const isHubPage = (r) => r.body.includes("Sign in through the admin hub") && r.body.includes(`href="${HUB_URL}"`);
    const nowSec = Math.floor(Date.now() / 1000);
    // A session signed before the `via` marker existed (no marker at all).
    const legacyCookie = `tgs_admin_session=${auth.signSession({ sub: "admin", iat: nowSec, exp: nowSec + 600 }, SESSION_SECRET)}`;
    const loginBody = `password=${encodeURIComponent(ADMIN_PASSWORD)}`;
    const formHeaders = { "Content-Type": "application/x-www-form-urlencoded" };

    // --- switch parsing: only a clear "off" value turns it off ---
    const savedEnv = process.env.DIRECT_ADMIN_LOGIN;
    const configPath = require.resolve("../src/config");
    const readSwitch = (value) => {
      if (value === undefined) {
        delete process.env.DIRECT_ADMIN_LOGIN;
      } else {
        process.env.DIRECT_ADMIN_LOGIN = value;
      }
      delete require.cache[configPath];
      return require("../src/config").directAdminLogin;
    };
    check("DIRECT_ADMIN_LOGIN unset -> on", readSwitch(undefined) === true);
    for (const value of ["", "on", "true", "1", "yes", "banana"]) {
      check(`DIRECT_ADMIN_LOGIN=${JSON.stringify(value)} -> on`, readSwitch(value) === true);
    }
    for (const value of ["off", "OFF", "false", "False", "0", "no", " No "]) {
      check(`DIRECT_ADMIN_LOGIN=${JSON.stringify(value)} -> off`, readSwitch(value) === false);
    }
    readSwitch(savedEnv);
    delete require.cache[configPath];

    // --- ON (the default server above has no directAdminLogin field) ---
    const login = await request(base, { method: "POST", path: "/admin/login", headers: formHeaders, body: loginBody });
    const directCookie = sessionCookiePair(login.setCookie);
    check("ON: password login still issues a session", login.status === 302 && login.headers.location === "/admin" && Boolean(directCookie), `status=${login.status}`);
    const directPayload = auth.verifySession(directCookie.split("=")[1], SESSION_SECRET, nowSec - 5);
    check("ON: password session is marked via=password", directPayload && directPayload.via === "password", JSON.stringify(directPayload));
    const onDirect = await request(base, { path: "/admin/api/public-keys", cookie: directCookie });
    check("ON: password session reaches /admin/api -> 200", onDirect.status === 200, `status=${onDirect.status}`);
    const onLegacy = await request(base, { path: "/admin/api/public-keys", cookie: legacyCookie });
    check("ON: unmarked (pre-deploy) session still works -> 200", onLegacy.status === 200, `status=${onLegacy.status}`);

    const explicitOn = await startServer({ ...testConfig, directAdminLogin: true }, new FakeStorage());
    const onForm = await request(explicitOn.base, { path: "/admin/login" });
    check("ON (explicit): GET /admin/login -> 200 password form", onForm.status === 200 && /name="password"/.test(onForm.body) && !isHubPage(onForm), `status=${onForm.status}`);
    const onPost = await request(explicitOn.base, { method: "POST", path: "/admin/login", headers: formHeaders, body: loginBody });
    check("ON (explicit): POST /admin/login correct pw -> 302 /admin + cookie", onPost.status === 302 && onPost.headers.location === "/admin" && Boolean(sessionCookiePair(onPost.setCookie)), `status=${onPost.status}`);
    explicitOn.server.close();

    // --- OFF ---
    const off = await startServer({ ...testConfig, directAdminLogin: false }, new FakeStorage());

    const offForm = await request(off.base, { path: "/admin/login" });
    check("OFF: GET /admin/login -> 403 hub page, no form", offForm.status === 403 && isHubPage(offForm) && !/<form|password/i.test(offForm.body), `status=${offForm.status}`);
    check("OFF: hub page keeps CSP frame-ancestors", offForm.headers["content-security-policy"] === `frame-ancestors ${HUB_ORIGIN}`, offForm.headers["content-security-policy"]);

    const offPost = await request(off.base, { method: "POST", path: "/admin/login", headers: formHeaders, body: loginBody });
    check("OFF: POST /admin/login correct pw -> 403 hub page", offPost.status === 403 && isHubPage(offPost), `status=${offPost.status} loc=${offPost.headers.location}`);
    check("OFF: POST /admin/login sets NO cookie", offPost.setCookie.length === 0, JSON.stringify(offPost.setCookie));
    const offWrong = await request(off.base, { method: "POST", path: "/admin/login", headers: formHeaders, body: "password=wrong" });
    check("OFF: wrong pw answers exactly like correct pw (credentials not read)", offWrong.status === offPost.status && offWrong.body === offPost.body && offWrong.headers.location === undefined, `status=${offWrong.status}`);

    const offAdmin = await request(off.base, { path: "/admin" });
    check("OFF: GET /admin without session -> 302 /admin/login", offAdmin.status === 302 && offAdmin.headers.location === "/admin/login", `status=${offAdmin.status}`);

    for (const [label, cookie] of [["password", directCookie], ["unmarked", legacyCookie]]) {
      const api = await request(off.base, { path: "/admin/api/public-keys", cookie });
      check(`OFF: ${label} session on /admin/api -> 401`, api.status === 401, `status=${api.status}`);
      const write = await request(off.base, { method: "POST", path: "/admin/api/entries", cookie, body: { publicKey: PUBLIC_KEY, userGuid: "off-guid", username: "nope", score: 1 } });
      check(`OFF: ${label} session cannot write -> 401`, write.status === 401, `status=${write.status}`);
      const page = await request(off.base, { path: "/admin", cookie });
      check(`OFF: ${label} session on /admin -> 302 /admin/login`, page.status === 302 && page.headers.location === "/admin/login", `status=${page.status}`);
      const form = await request(off.base, { path: "/admin/login", cookie });
      check(`OFF: ${label} session on /admin/login -> 403 hub page`, form.status === 403 && isHubPage(form), `status=${form.status}`);
    }

    // SSO keeps working and its session is accepted.
    const sso = await request(off.base, { path: `/sso?token=${mintJwt({ jti: "jti-off-1" })}` });
    const offSsoCookie = sessionCookiePair(sso.setCookie);
    check("OFF: valid /sso -> 302 /admin + cookie", sso.status === 302 && sso.headers.location === "/admin" && Boolean(offSsoCookie), `status=${sso.status}`);
    const ssoPayload = auth.verifySession(offSsoCookie.split("=")[1], SESSION_SECRET, nowSec - 5);
    check("OFF: SSO session is marked via=sso", ssoPayload && ssoPayload.via === "sso", JSON.stringify(ssoPayload));
    const ssoPage = await request(off.base, { path: "/admin", cookie: offSsoCookie });
    check("OFF: SSO session on /admin -> 200 panel", ssoPage.status === 200 && /TGS Leaderboard/.test(ssoPage.body), `status=${ssoPage.status}`);
    const ssoApi = await request(off.base, { path: "/admin/api/public-keys", cookie: offSsoCookie });
    check("OFF: SSO session on /admin/api -> 200", ssoApi.status === 200, `status=${ssoApi.status}`);
    const ssoWrite = await request(off.base, { method: "POST", path: "/admin/api/entries", cookie: offSsoCookie, body: { publicKey: PUBLIC_KEY, userGuid: "sso-guid", username: "SsoMade", score: 7 } });
    check("OFF: SSO session can write via /admin/api -> 200", ssoWrite.status === 200, `status=${ssoWrite.status} body=${ssoWrite.body}`);
    const ssoLogin = await request(off.base, { path: "/admin/login", cookie: offSsoCookie });
    check("OFF: SSO session on /admin/login -> 302 /admin", ssoLogin.status === 302 && ssoLogin.headers.location === "/admin", `status=${ssoLogin.status}`);
    const ssoBad = await request(off.base, { path: `/sso?token=${mintJwt({ sign: false, jti: "jti-off-bad" })}` });
    check("OFF: tampered /sso still -> 401", ssoBad.status === 401, `status=${ssoBad.status}`);
    const onSso = await request(base, { path: `/sso?token=${mintJwt({ jti: "jti-on-then-off" })}` });
    const onSsoOnOff = await request(off.base, { path: "/admin/api/public-keys", cookie: sessionCookiePair(onSso.setCookie) });
    check("OFF: SSO session issued while ON is accepted after switching OFF", onSsoOnOff.status === 200, `status=${onSsoOnOff.status}`);

    // ADMIN_TOKEN header (machine API) is untouched.
    const tokenHeaders = { Authorization: `Bearer ${ADMIN_TOKEN}` };
    const offBearer = await request(off.base, { path: "/admin/api/public-keys", headers: tokenHeaders });
    check("OFF: Bearer token on /admin/api -> 200", offBearer.status === 200, `status=${offBearer.status}`);
    const offX = await request(off.base, { path: `/admin/api/entries?publicKey=${PUBLIC_KEY}`, headers: { "X-Admin-Token": ADMIN_TOKEN } });
    check("OFF: X-Admin-Token on /admin/api -> 200", offX.status === 200, `status=${offX.status}`);
    const offTokenWrite = await request(off.base, { method: "POST", path: "/admin/api/entries", headers: tokenHeaders, body: { publicKey: PUBLIC_KEY, userGuid: "tok-guid", username: "TokMade", score: 9 } });
    check("OFF: token write via /admin/api -> 200", offTokenWrite.status === 200, `status=${offTokenWrite.status} body=${offTokenWrite.body}`);
    const offTokenPage = await request(off.base, { path: "/admin", headers: tokenHeaders });
    check("OFF: token on GET /admin -> 200 panel", offTokenPage.status === 200, `status=${offTokenPage.status}`);
    const offTokenWithDirect = await request(off.base, { path: "/admin/api/public-keys", headers: tokenHeaders, cookie: directCookie });
    check("OFF: token + refused password cookie -> still 200", offTokenWithDirect.status === 200, `status=${offTokenWithDirect.status}`);
    const offBadTok = await request(off.base, { path: "/admin/api/public-keys", headers: { Authorization: "Bearer nope" } });
    check("OFF: wrong token -> 401", offBadTok.status === 401, `status=${offBadTok.status}`);
    const offRenameForm = multipartForm({ publicKey: PUBLIC_KEY, username: "TokRenamed", userGuid: "tok-guid" });
    const offRename = await request(off.base, { method: "POST", path: "/entry/update-username", headers: { ...offRenameForm.headers, ...tokenHeaders }, body: offRenameForm.body });
    check("OFF: token rename via /entry/update-username -> 200", offRename.status === 200, `status=${offRename.status} body=${offRename.body}`);
    const offCookieRename = await request(off.base, { method: "POST", path: "/entry/update-username", cookie: offSsoCookie, ...multipartForm({ publicKey: PUBLIC_KEY, username: "CookieRenamed", userGuid: "tok-guid" }) });
    check("OFF: /entry/update-username with session cookie only -> 403 (as with ON)", offCookieRename.status === 403, `status=${offCookieRename.status}`);
    const offDeleteForm = multipartForm({ publicKey: PUBLIC_KEY, userGuid: "tok-guid" });
    const offDelete = await request(off.base, { method: "POST", path: "/entry/delete", headers: { ...offDeleteForm.headers, ...tokenHeaders }, body: offDeleteForm.body });
    check("OFF: token delete via /entry/delete -> 200", offDelete.status === 200, `status=${offDelete.status} body=${offDelete.body}`);

    // Game routes and health are untouched.
    const offHealth = await request(off.base, { path: "/health" });
    check("OFF: GET /health -> 200 ok", offHealth.status === 200 && JSON.parse(offHealth.body).status === "ok", `status=${offHealth.status}`);
    const offRoot = await request(off.base, { path: "/" });
    check("OFF: GET / -> 200 OK", offRoot.status === 200 && offRoot.body === "OK", `status=${offRoot.status}`);
    const offAuthorize = await request(off.base, { path: "/authorize" });
    const offGuid = offAuthorize.body.trim();
    check("OFF: GET /authorize -> 200 guid", offAuthorize.status === 200 && UUID_RE.test(offGuid), offAuthorize.body);
    const offUpload = await request(off.base, { method: "POST", path: "/entry/upload", ...multipartForm({ publicKey: PUBLIC_KEY, username: "OffPlayer", score: "321", extra: " ", userGuid: offGuid }) });
    check("OFF: POST /entry/upload -> 200", offUpload.status === 200 && offUpload.body === "OK", `status=${offUpload.status} body=${offUpload.body}`);
    const offGet = await getJson(off.base, `/get?publicKey=${PUBLIC_KEY}&userGuid=${offGuid}&isInAscendingOrder=0&skip=0&take=100&timePeriod=0`);
    check("OFF: GET /get returns the uploaded row", offGet.status === 200 && (offGet.json || []).some((row) => row.Username === "OffPlayer" && row.Score === 321), offGet.body);
    const offPersonal = await getJson(off.base, `/entry/get?publicKey=${PUBLIC_KEY}&userGuid=${offGuid}`);
    check("OFF: GET /entry/get -> 200 own entry", offPersonal.status === 200 && offPersonal.json && offPersonal.json.Username === "OffPlayer", offPersonal.body);
    const offCount = await request(off.base, { path: `/entry/count?publicKey=${PUBLIC_KEY}` });
    check("OFF: GET /entry/count -> 200", offCount.status === 200 && Number(offCount.body) >= 1, `status=${offCount.status} body=${offCount.body}`);
    const profileFields = { name: "Off Player", email: "off-player@example.com", country: "GB", consentAccepted: "true" };
    const offProfile = await request(off.base, { method: "POST", path: "/player-profile", ...multipartForm(profileFields) });
    const onProfile = await request(base, { method: "POST", path: "/player-profile", ...multipartForm(profileFields) });
    check("OFF: POST /player-profile answers exactly as with ON", offProfile.status === onProfile.status && offProfile.body === onProfile.body, `off=${offProfile.status} ${offProfile.body} on=${onProfile.status} ${onProfile.body}`);
    check("OFF: game routes carry no CSP header", offGet.headers["content-security-policy"] === undefined && offHealth.headers["content-security-policy"] === undefined);

    // Logout still just clears the cookie.
    const offLogout = await request(off.base, { method: "POST", path: "/admin/logout", cookie: offSsoCookie });
    check("OFF: POST /admin/logout -> 302 /admin/login, cookie cleared", offLogout.status === 302 && offLogout.headers.location === "/admin/login" && /Max-Age=0/i.test(offLogout.setCookie.join(";")), `status=${offLogout.status}`);
    off.server.close();

    // OFF with no ADMIN_PASSWORD at all (SSO + token only).
    const offNoPw = await startServer({ ...testConfig, adminPassword: "", directAdminLogin: false }, new FakeStorage());
    const noPwForm = await request(offNoPw.base, { path: "/admin/login" });
    check("OFF, no password set: GET /admin/login -> 403 hub page", noPwForm.status === 403 && isHubPage(noPwForm), `status=${noPwForm.status}`);
    const noPwSso = await request(offNoPw.base, { path: `/sso?token=${mintJwt({ jti: "jti-off-nopw" })}` });
    const noPwApi = await request(offNoPw.base, { path: "/admin/api/public-keys", cookie: sessionCookiePair(noPwSso.setCookie) });
    check("OFF, no password set: SSO session works -> 200", noPwSso.status === 302 && noPwApi.status === 200, `sso=${noPwSso.status} api=${noPwApi.status}`);
    offNoPw.server.close();
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

  // ===========================================================================
  // OBSERVE MODE (log-only). Every check below also asserts that responses are
  // the same as with SECURITY_OBSERVE=off.
  // ===========================================================================
  const observeOffConfig = { ...testConfig, observe: { enabled: false } };
  const obsStorage = new FakeStorage();
  const offStorage = new FakeStorage();
  const obs = await startServer({ ...testConfig, observe: {} }, obsStorage);
  const off = await startServer(observeOffConfig, offStorage);
  const usedGuids = [];
  const authorizeOn = async (target) => {
    const guid = (await request(target.base, { path: "/authorize", headers: unityHeaders })).body.trim();
    usedGuids.push(guid);
    return guid;
  };
  const upload = (target, fields, headers = {}) => {
    const form = multipartForm(fields);
    return request(target.base, { method: "POST", path: "/entry/upload", headers: { ...unityHeaders, ...headers, ...form.headers }, body: form.body });
  };

  console.log("\n=== OBSERVE: normal game flow records nothing ===");
  {
    // An old registry row, to prove the opportunistic prune (first request).
    obsStorage.issuedGuids.set("old-guid", { guid: "old-guid", issuedAt: Math.floor(Date.now() / 1000) - 91 * 86400, ip: "", ipSource: "socket", userAgent: "" });
    const linesBefore = observeLines.length;

    const guid = await authorizeOn(obs);
    check("observe: /authorize still returns a plain GUID", UUID_RE.test(guid), guid);
    const up = await upload(obs, { publicKey: LIVE_KEY, username: "Dana-GB-123.45", score: "12345", extra: " ", userGuid: guid });
    check("observe: game-shaped upload -> 200 OK", up.status === 200 && up.body === "OK", `status=${up.status} body=${up.body}`);
    const get = await getJson(obs.base, `/get?publicKey=${LIVE_KEY}&userGuid=${guid}&isInAscendingOrder=0&skip=0&take=100&timePeriod=0`, unityHeaders);
    check("observe: /get returns the row with the real guid", get.status === 200 && get.json.length === 1 && get.json[0].UserGuid === guid && get.json[0].Extra === " ", get.body);
    const guid2 = await authorizeOn(obs);
    const up2 = await upload(obs, { publicKey: LIVE_KEY, username: "Dana-GB-200", score: "200", extra: " ", userGuid: guid2 });
    check("observe: second upload (raw score in the name) -> 200", up2.status === 200, `status=${up2.status}`);
    const profile = await request(obs.base, { method: "POST", path: "/player-profile", ...multipartForm({ name: "Carol", email: "carol@example.com", country: "US", consentAccepted: "true" }) });
    check("observe: normal /player-profile -> 200", profile.status === 200 && profile.body === '{"ok":true}', profile.body);

    await settle(obs);
    check("observe: normal flow wrote NO observation rows", obsStorage.observations.length === 0, JSON.stringify(obsStorage.observations));
    check("observe: normal flow printed NO [observe] lines", observeLines.length === linesBefore, JSON.stringify(observeLines.slice(linesBefore)));
    const issuedRow = obsStorage.issuedGuids.get(guid);
    check("observe: issued GUID was registered", Boolean(issuedRow) && obsStorage.issuedGuids.has(guid2) && issuedRow.ipSource === "socket" && issuedRow.ip === "127.0.0.1" && issuedRow.userAgent.startsWith("UnityPlayer/"), JSON.stringify(issuedRow));
    check("observe: registry rows older than 90 days were pruned", !obsStorage.issuedGuids.has("old-guid"));
  }

  console.log("\n=== OBSERVE: each observation type, response identical to observe-off ===");
  {
    // Sends the same request to the observing server and to the one with
    // observation off, and compares status, body and headers.
    const pair = async (name, build, reasons, { ignoreEntryDate = false } = {}) => {
      const before = obsStorage.observations.length;
      const [on, plain] = [await build(obs), await build(off)];
      // "date" is the clock. With ignoreEntryDate the stored upload second (and
      // the etag/length derived from it) is left out too: the two servers'
      // rows were written by two separate uploads.
      const skipped = ignoreEntryDate ? ["date", "etag"] : ["date"];
      const strip = (headers) => JSON.stringify(Object.entries(headers).filter(([key]) => !skipped.includes(key)));
      const text = (body) => (ignoreEntryDate ? body.replace(/"Date":\d+/g, '"Date":0') : body);
      check(`${name}: same status/body/headers as observe-off`, on.status === plain.status && text(on.body) === text(plain.body) && strip(on.headers) === strip(plain.headers), `on=${on.status} ${on.body} off=${plain.status} ${plain.body}`);
      await settle(obs);
      const added = obsStorage.observations.slice(before);
      for (const reason of reasons) {
        check(`${name}: recorded ${reason}`, added.some((o) => o.reason === reason), JSON.stringify(added.map((o) => o.reason)));
      }
      return { on, plain, added };
    };
    // Each server gets a GUID it issued itself, so only the tested field is odd.
    const issued = async (target) => (target === obs ? authorizeOn(obs) : (await request(off.base, { path: "/authorize" })).body.trim());
    const good = { publicKey: LIVE_KEY, username: "Eve-US-9.00", score: "900", extra: " " };

    const oldKey = await pair("upload with the ff61800f key", async (t) => upload(t, { ...good, publicKey: OLD_KEY, userGuid: await issued(t) }), ["unexpected_public_key"]);
    check("old key upload -> 200 OK as before", oldKey.on.status === 200 && oldKey.on.body === "OK");
    check("unexpected_public_key row has prefix + length only", oldKey.added.length === 1 && oldKey.added[0].keyPrefix === "ff61800f" && JSON.parse(oldKey.added[0].detail).length === 64 && oldKey.added[0].route === "/entry/upload", JSON.stringify(oldKey.added));
    check("old key entry was stored exactly as with observe off", (await obsStorage.listEntries(OLD_KEY)).length === 1 && (await offStorage.listEntries(OLD_KEY)).length === 1);

    const madeUp = crypto.randomUUID();
    usedGuids.push(madeUp);
    const notIssued = await pair("upload with a made-up GUID", (t) => upload(t, { ...good, userGuid: madeUp }), ["guid_not_issued"]);
    const notIssuedRow = notIssued.added.find((o) => o.reason === "guid_not_issued");
    check("made-up GUID upload -> 200 OK as before", notIssued.on.status === 200 && notIssued.on.body === "OK");
    check("guid_not_issued says uuid-shaped, no earlier entry", notIssued.added.length === 1 && JSON.parse(notIssuedRow.detail).uuidShaped === true && JSON.parse(notIssuedRow.detail).entryExisted === false, JSON.stringify(notIssued.added));
    check("guid_ref is the /get mask, not the GUID", notIssuedRow.guidRef === obs.service.maskUserGuid(LIVE_KEY, madeUp) && MASK_PATTERN.test(notIssuedRow.guidRef), notIssuedRow.guidRef);
    const again = await pair("re-upload with the same made-up GUID", (t) => upload(t, { ...good, userGuid: madeUp }), ["guid_not_issued"]);
    check("guid_not_issued notes the entry already existed", JSON.parse(again.added[0].detail).entryExisted === true, JSON.stringify(again.added));

    const shape = await pair("upload with a non-UUID GUID", (t) => upload(t, { ...good, userGuid: "typed-by-hand" }), ["guid_shape", "guid_not_issued"]);
    check("guid_shape records the length only", JSON.parse(shape.added.find((o) => o.reason === "guid_shape").detail).length === 13);

    const yes = await pair("upload with extra 'yes'", async (t) => upload(t, { ...good, username: "Yes-GB-9.00", extra: "yes", userGuid: await issued(t) }), ["extra_unexpected"]);
    const yesRowOn = (await obsStorage.listEntries(LIVE_KEY)).find((e) => e.username === "Yes-GB-9.00");
    const yesRowOff = (await offStorage.listEntries(LIVE_KEY)).find((e) => e.username === "Yes-GB-9.00");
    check("extra 'yes' upload -> 200 and stored exactly as before", yes.on.status === 200 && yesRowOn.extra === "yes" && yesRowOff.extra === "yes" && yesRowOn.score === 900, JSON.stringify(yesRowOn));
    check("extra_unexpected records the value", yes.added.length === 1 && JSON.parse(yes.added[0].detail).value === "yes", JSON.stringify(yes.added));
    const yesPadded = await pair("upload with extra ' YES\\n'", async (t) => upload(t, { ...good, extra: " YES\n", userGuid: await issued(t) }), ["extra_unexpected"]);
    check("extra value is trimmed + lowercased", JSON.parse(yesPadded.added[0].detail).value === "yes");

    const negative = await pair("upload with a negative score", async (t) => upload(t, { ...good, username: "Neg-GB--5", score: "-5", userGuid: await issued(t) }), ["score_out_of_bounds"]);
    check("negative score recorded with its value, still 200", negative.on.status === 200 && JSON.parse(negative.added[0].detail).problem === "negative" && JSON.parse(negative.added[0].detail).value === -5 && negative.added.length === 1, JSON.stringify(negative.added));
    const huge = await pair("upload with a huge score", async (t) => upload(t, { ...good, username: "Big-GB-999999999", score: "999999999", userGuid: await issued(t) }), ["score_out_of_bounds"]);
    check("score above max recorded, still 200", huge.on.status === 200 && JSON.parse(huge.added[0].detail).problem === "above_max" && JSON.parse(huge.added[0].detail).value === 999999999, JSON.stringify(huge.added));
    const lax = await pair("upload with score '12abc'", async (t) => upload(t, { ...good, score: "12abc", userGuid: await issued(t) }), ["score_out_of_bounds"]);
    check("non-integer score still accepted exactly as before (200)", lax.on.status === 200 && lax.plain.status === 200);
    const nan = await pair("upload with score 'abc'", async (t) => upload(t, { ...good, score: "abc", userGuid: await issued(t) }), ["score_out_of_bounds"]);
    check("unparseable score -> the same 400 as before", nan.on.status === 400 && nan.on.body === "score must be an integer.", nan.on.body);

    const noShape = await pair("upload with an unpacked username", async (t) => upload(t, { ...good, username: "PrivatePersonName", userGuid: await issued(t) }), ["username_shape"]);
    check("username_shape (shape) has lengths, not the name", noShape.added.length === 1 && JSON.parse(noShape.added[0].detail).relation === "shape_mismatch" && JSON.parse(noShape.added[0].detail).usernameLength === 17 && !JSON.stringify(noShape.added).includes("PrivatePerson"), JSON.stringify(noShape.added));
    const mismatch = await pair("upload whose name score differs", async (t) => upload(t, { ...good, username: "Dana-GB-777", score: "12345", userGuid: await issued(t) }), ["username_shape"]);
    check("username_shape records the relation", JSON.parse(mismatch.added[0].detail).relation === "mismatch" && JSON.parse(mismatch.added[0].detail).tail === "777" && JSON.parse(mismatch.added[0].detail).score === 12345, JSON.stringify(mismatch.added));

    const longName = `${"N".repeat(70)}-GB-9.00`;
    const tooLong = await pair("upload with a long username", async (t) => upload(t, { ...good, username: longName, userGuid: await issued(t) }), ["username_too_long"]);
    check("username_too_long records the length; name stored as before", tooLong.added.length === 1 && JSON.parse(tooLong.added[0].detail).length === 78 && (await obsStorage.listEntries(LIVE_KEY)).some((e) => e.username === longName), JSON.stringify(tooLong.added));

    const badEmail = await pair("profile with a malformed email", (t) => request(t.base, { method: "POST", path: "/player-profile", ...multipartForm({ name: "Mallory", email: "secret-address-at-nowhere", country: "US", consentAccepted: "true" }) }), ["profile_fields"]);
    check("malformed email -> the same 400 as before", badEmail.on.status === 400 && badEmail.on.body === "email is invalid.", badEmail.on.body);
    const longProfile = await pair("profile with an over-long name", (t) => request(t.base, { method: "POST", path: "/player-profile", body: { name: "P".repeat(80), email: "long.name@example.com", country: "US", consentAccepted: true } }), ["profile_fields"]);
    check("over-long name is still accepted (200)", longProfile.on.status === 200 && longProfile.on.body === '{"ok":true}');
    const profileText = JSON.stringify([...badEmail.added, ...longProfile.added]);
    check("profile_fields holds lengths/booleans only", JSON.parse(longProfile.added[0].detail).nameLength === 80 && JSON.parse(longProfile.added[0].detail).nameTooLong === true && JSON.parse(badEmail.added[0].detail).emailValid === false && !profileText.includes("secret-address") && !profileText.includes("long.name@") && !profileText.includes("Mallory"), profileText);

    // Same GUID on both servers, so the masked UserGuid must match as well.
    const otherKey = `ff61800f${"1".repeat(56)}`;
    await upload(obs, { ...good, publicKey: otherKey, userGuid: madeUp });
    await upload(off, { ...good, publicKey: otherKey, userGuid: madeUp });
    const getOld = await pair("GET /get with an ff61800f-style key", (t) => request(t.base, { path: `/get?publicKey=${otherKey}&take=10` }), ["unexpected_public_key"], { ignoreEntryDate: true });
    check("/get body is identical with observation on", getOld.on.status === 200 && JSON.parse(getOld.on.body).length === 1 && MASK_PATTERN.test(JSON.parse(getOld.on.body)[0].UserGuid), getOld.on.body);
    const normalise = (body) => body.replace(/"Date":\d+/g, '"Date":0');
    const getLiveOn = await request(obs.base, { path: `/get?publicKey=${LIVE_KEY}&take=100` });
    const getLiveOff = await request(off.base, { path: `/get?publicKey=${LIVE_KEY}&take=100` });
    // The first section uploaded two extra rows to the observing server only.
    const onRows = JSON.parse(normalise(getLiveOn.body)).filter((row) => !row.Username.startsWith("Dana-GB-123") && row.Username !== "Dana-GB-200");
    const offRows = JSON.parse(normalise(getLiveOff.body));
    const shapeOf = (rows) => JSON.stringify(rows.map((row) => [row.Username, row.Score, row.Extra, Object.keys(row).join(",")]).sort());
    check("/get lists the same stored rows on both servers", getLiveOn.status === 200 && shapeOf(onRows) === shapeOf(offRows) && offRows.length > 8, `${onRows.length} vs ${offRows.length}`);

    check("observe-off server never touched the observation store", offStorage.observeCalls === 0 && offStorage.observations.length === 0 && offStorage.issuedGuids.size === 0 && offStorage.traffic.size === 0, `calls=${offStorage.observeCalls}`);
    check("observe-off server holds no observation state", off.service.observer.rateCounters.size === 0 && off.service.observer.pendingTraffic.size === 0 && off.service.observer.recentGuids.size === 0);
  }

  console.log("\n=== OBSERVE: client-contract telemetry ===");
  {
    const guid = await authorizeOn(obs);
    await upload(obs, { publicKey: LIVE_KEY, username: "Web-GB-1.00", score: "100", extra: " ", userGuid: guid }, { Origin: "https://play.example.com" });
    await request(obs.base, { path: `/get?publicKey=${LIVE_KEY}`, headers: { Origin: "https://www.example.org", "User-Agent": "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/126.0 Mobile Safari/537.36", "X-Real-IP": "198.51.100.9", "X-Forwarded-For": "198.51.100.9, 10.0.0.1" } });
    await settle(obs);
    await obs.service.observer.flushTraffic();
    const rows = [...obsStorage.traffic.values()];
    const hourOk = rows.every((row) => row.hour % 3600 === 0 && Number.isInteger(row.count) && row.count > 0);
    check("traffic_hourly rows are hour-bucketed counts", rows.length > 0 && hourOk, JSON.stringify(rows.slice(0, 3)));
    const unityUpload = rows.find((row) => row.route === "/entry/upload" && row.dimKey === "c|ct=multipart;o=play.example.com;uv=2022.3.10f1;ua=UnityPlayer/2022.3.10f1;g=1;s=200");
    check("upload tuple: multipart + origin host + unity version + UA family + guid + status", Boolean(unityUpload), JSON.stringify(rows.filter((row) => row.route === "/entry/upload").map((row) => row.dimKey)));
    const webGet = rows.find((row) => row.route === "/get" && row.dimKey === "c|ct=none;o=www.example.org;uv=-;ua=browser:Chrome:Android;g=0;s=200");
    check("website /get tuple: no content-type, origin, browser family, no userGuid", Boolean(webGet), JSON.stringify(rows.filter((row) => row.route === "/get").map((row) => row.dimKey)));
    check("client address shape is aggregated (x-real-ip vs x-forwarded-for)", rows.some((row) => row.route === "/get" && row.dimKey === "addr|src=x-real-ip;xri=1;xff=2;xri_eq_xff=first;sock=loopback") && rows.some((row) => row.dimKey === "addr|src=socket;xri=0;xff=0;xri_eq_xff=-;sock=loopback"), JSON.stringify(rows.filter((row) => row.dimKey.startsWith("addr|")).map((row) => row.dimKey)));
    check("public keys are aggregated by prefix only", rows.some((row) => row.dimKey === "key|536aec42:64:expected") && rows.some((row) => row.dimKey === "key|ff61800f:64:unexpected"));
    const before = rows.find((row) => row.route === "/authorize" && row.dimKey.startsWith("c|")).count;
    await request(obs.base, { path: "/authorize", headers: unityHeaders });
    await settle(obs);
    await obs.service.observer.flushTraffic();
    const after = [...obsStorage.traffic.values()].find((row) => row.route === "/authorize" && row.dimKey.startsWith("c|")).count;
    check("a second flush increments the same row (upsert)", after === before + 1, `${before} -> ${after}`);
  }

  console.log("\n=== OBSERVE: rate thresholds never block, one row per window ===");
  {
    let clock = 0;
    const rateStorage = new FakeStorage();
    const rate = await startServer({
      ...testConfig,
      observe: {
        now: () => Math.floor(Date.now() / 1000) + clock,
        rateAuthorize: { max: 3, windowSeconds: 600 },
        rateUpload: "4/600",
        rateUploadGuid: { max: 2, windowSeconds: 600 },
        rateProfile: { max: 2, windowSeconds: 3600 }
      }
    }, rateStorage);
    const rateRows = (route) => rateStorage.observations.filter((o) => o.reason === "would_rate_limit" && o.route === route);

    const statuses = [];
    for (let i = 0; i < 7; i++) statuses.push((await request(rate.base, { path: "/authorize" })).status);
    await settle(rate);
    check("7 x /authorize over a limit of 3 -> all 200", statuses.every((s) => s === 200), JSON.stringify(statuses));
    check("exactly ONE would_rate_limit row for that window", rateRows("/authorize").length === 1, JSON.stringify(rateRows("/authorize")));
    const firstRow = rateRows("/authorize")[0];
    check("row has the count reached, limit, window and client address", firstRow && JSON.parse(firstRow.detail).count === 4 && JSON.parse(firstRow.detail).limit === 3 && JSON.parse(firstRow.detail).windowSeconds === 600 && JSON.parse(firstRow.detail).scope === "ip" && firstRow.ip === "127.0.0.1" && firstRow.ipSource === "socket", JSON.stringify(firstRow));

    for (const ip of ["203.0.113.1", "203.0.113.2"]) {
      for (let i = 0; i < 3; i++) await request(rate.base, { path: "/authorize", headers: { "X-Real-IP": ip } });
    }
    for (let i = 0; i < 5; i++) await request(rate.base, { path: "/authorize", headers: { "X-Forwarded-For": "198.51.100.1, 203.0.113.50" } });
    await settle(rate);
    check("clients are counted separately by x-real-ip", rateRows("/authorize").every((o) => !o.ip.startsWith("203.0.113.1") && o.ip !== "203.0.113.2"));
    const xffRow = rateRows("/authorize").find((o) => o.ipSource === "x-forwarded-for-last");
    check("without x-real-ip the LAST x-forwarded-for entry is the key", rateRows("/authorize").length === 2 && xffRow && xffRow.ip === "203.0.113.50", JSON.stringify(rateRows("/authorize")));

    clock += 601;
    for (let i = 0; i < 5; i++) await request(rate.base, { path: "/authorize" });
    await settle(rate);
    check("a new window records one more row (and no more)", rateRows("/authorize").filter((o) => o.ipSource === "socket").length === 2, JSON.stringify(rateRows("/authorize")));
    check("an overdue flush ran from the request path side-effect free", rateStorage.traffic.size > 0);

    const guid = (await request(rate.base, { path: "/authorize", headers: { "X-Real-IP": "203.0.113.9" } })).body.trim();
    usedGuids.push(guid);
    const uploadStatuses = [];
    for (let i = 0; i < 6; i++) uploadStatuses.push((await upload(rate, { publicKey: LIVE_KEY, username: "Rate-GB-1.00", score: "100", extra: " ", userGuid: guid })).status);
    await settle(rate);
    check("6 x upload over both upload limits -> all 200", uploadStatuses.every((s) => s === 200), JSON.stringify(uploadStatuses));
    const uploadRows = rateRows("/entry/upload").map((o) => ({ ...JSON.parse(o.detail), guidRef: o.guidRef }));
    check("one per-IP row and one per-GUID row", uploadRows.length === 2 && uploadRows.filter((o) => o.scope === "ip" && o.count === 5 && o.guidRef === "").length === 1 && uploadRows.filter((o) => o.scope === "guid" && o.count === 3 && MASK_PATTERN.test(o.guidRef)).length === 1, JSON.stringify(uploadRows));
    check("the entry was stored normally", (await rateStorage.getEntry(LIVE_KEY, guid)).score === 100);

    const profileStatuses = [];
    for (let i = 0; i < 5; i++) profileStatuses.push((await request(rate.base, { method: "POST", path: "/player-profile", body: { name: "Rae", email: `rae${i}@example.com`, country: "US", consentAccepted: true } })).status);
    await settle(rate);
    check("5 x /player-profile over a limit of 2 -> all 200, one row", profileStatuses.every((s) => s === 200) && rateRows("/player-profile").length === 1 && rateStorage.profiles.size === 5, JSON.stringify(profileStatuses));

    const summary = await getJson(rate.base, "/admin/api/observation-summary", adminAuth);
    const authorizeRate = summary.json.rate.find((r) => r.route === "/authorize");
    check("summary: windows triggered, requests over the limit, distinct clients", authorizeRate.limit === 3 && authorizeRate.windowsTriggered === 3 && authorizeRate.requestsOverLimit === 8 && authorizeRate.distinctClients === 2, JSON.stringify(authorizeRate));
    const guidRate = summary.json.rate.find((r) => r.route === "/entry/upload" && r.scope === "guid");
    check("summary: per-GUID upload rate is reported apart", guidRate.limit === 2 && guidRate.windowsTriggered === 1 && guidRate.requestsOverLimit === 4 && guidRate.distinctClients === 1, JSON.stringify(guidRate));
    rate.server.close();
  }

  console.log("\n=== OBSERVE: caps and bounded memory ===");
  {
    const capStorage = new FakeStorage();
    const capped = await startServer({ ...testConfig, observe: { maxRowsPerHour: 3, maxDimensions: 5, maxRateKeys: 10, maxRecentGuids: 6, maxDistinctIps: 4, maxIssuedPerHour: 12 } }, capStorage);
    const linesBefore = observeLines.length;
    const statuses = [];
    for (let i = 0; i < 9; i++) statuses.push((await request(capped.base, { path: `/get?publicKey=${OLD_KEY}` })).status);
    await settle(capped);
    const keyRows = capStorage.observations.filter((o) => o.reason === "unexpected_public_key");
    const suppressed = capStorage.observations.filter((o) => o.reason === "observations_suppressed");
    check("per-hour cap: only 3 rows of one reason are written", statuses.every((s) => s === 200) && keyRows.length === 3, `rows=${keyRows.length}`);
    check("per-hour cap: a single observations_suppressed row follows", suppressed.length === 1 && JSON.parse(suppressed[0].detail).suppressedReason === "unexpected_public_key" && capStorage.observations.length === 4, JSON.stringify(suppressed));
    check("per-hour cap: [observe] lines are capped the same way", observeLines.length - linesBefore === 4, `lines=${observeLines.length - linesBefore}`);

    for (let i = 0; i < 14; i++) await request(capped.base, { path: `/get?publicKey=${LIVE_KEY}`, headers: { "User-Agent": `HostileBot${i}/1.0` } });
    for (let i = 0; i < 30; i++) await request(capped.base, { path: "/authorize", headers: { "X-Real-IP": `192.0.2.${i}` } });
    await settle(capped);
    await capped.service.observer.flushTraffic();
    const getTuples = [...capStorage.traffic.values()].filter((row) => row.route === "/get" && row.dimKey.startsWith("c|"));
    check("traffic dimension cap: 5 distinct keys + 'other'", getTuples.length === 6 && getTuples.some((row) => row.dimKey === "c|other"), JSON.stringify(getTuples.map((row) => row.dimKey)));
    check("traffic dimension cap: no request is lost from the count", getTuples.reduce((total, row) => total + row.count, 0) === 23);
    const totals = [...capStorage.traffic.values()].find((row) => row.route === "/get" && row.dimKey === "obs|unexpected_public_key");
    const hidden = [...capStorage.traffic.values()].find((row) => row.route === "/get" && row.dimKey === "obs_suppressed|unexpected_public_key");
    check("suppressed observations are still counted in the aggregate", totals.count === 9 && hidden.count === 6, JSON.stringify([totals, hidden]));
    const observer = capped.service.observer;
    check("rate counter map stays bounded", observer.rateCounters.size <= 10, `size=${observer.rateCounters.size}`);
    check("recent GUID map stays bounded", observer.recentGuids.size <= 6, `size=${observer.recentGuids.size}`);
    check("distinct-IP sets stay bounded", observer.seenIps.get("/authorize").size <= 4 && [...capStorage.traffic.values()].find((row) => row.route === "/authorize" && row.dimKey === "ips|distinct").count === 4);
    check("issued_guids writes are capped per hour", capStorage.issuedGuids.size === 12 && [...capStorage.traffic.values()].find((row) => row.dimKey === "registry|skipped_hourly_cap").count === 18, `size=${capStorage.issuedGuids.size}`);
    check("pending traffic is empty after a flush", observer.pendingTraffic.size === 0);
    capped.server.close();
  }

  console.log("\n=== OBSERVE: a failing or hung observation store never reaches the game ===");
  for (const mode of ["failObserve", "hangObserve"]) {
    const brokenStorage = new FakeStorage({ [mode]: true });
    const broken = await startServer({ ...testConfig, observe: { maxQueue: 5 } }, brokenStorage);
    const errorsBefore = errorLines.length;
    const started = Date.now();

    const authz = await request(broken.base, { path: "/authorize" });
    const guid = authz.body.trim();
    usedGuids.push(guid);
    const fields = { publicKey: OLD_KEY, username: "Broken-GB-1.00", score: "100", extra: "yes", userGuid: "made-up-guid" };
    const up = await upload(broken, fields);
    const plainUp = await upload(off, fields);
    const upIssued = await upload(broken, { ...fields, userGuid: guid });
    const profileBody = { name: "Pat", email: "not-an-email", country: "US", consentAccepted: true };
    const profile = await request(broken.base, { method: "POST", path: "/player-profile", body: profileBody });
    const plainProfile = await request(off.base, { method: "POST", path: "/player-profile", body: profileBody });
    const okProfile = await request(broken.base, { method: "POST", path: "/player-profile", body: { ...profileBody, email: `pat-${mode}@example.com` } });
    const get = await getJson(broken.base, `/get?publicKey=${OLD_KEY}&userGuid=made-up-guid`);
    for (let i = 0; i < 25; i++) await request(broken.base, { path: `/get?publicKey=${OLD_KEY}` });
    const elapsed = Date.now() - started;

    check(`${mode}: /authorize -> 200 GUID`, authz.status === 200 && UUID_RE.test(guid), authz.body);
    check(`${mode}: upload -> identical to observe-off`, up.status === 200 && up.body === plainUp.body && up.status === plainUp.status && upIssued.status === 200, `status=${up.status}`);
    check(`${mode}: /player-profile -> identical to observe-off`, profile.status === plainProfile.status && profile.body === plainProfile.body && okProfile.status === 200 && okProfile.body === '{"ok":true}', `${profile.status} ${profile.body}`);
    check(`${mode}: /get -> 200 with the stored row`, get.status === 200 && get.json.some((row) => row.UserGuid === "made-up-guid" && row.Extra === "yes"), get.body);
    check(`${mode}: all 31 requests answered promptly`, elapsed < 5000, `ms=${elapsed}`);
    await settle(broken, 300);
    const observer = broken.service.observer;
    check(`${mode}: background queue stays bounded`, observer.queue.length <= 5 && observer.inFlight <= 2, `queue=${observer.queue.length} inFlight=${observer.inFlight}`);
    check(`${mode}: nothing was stored, jobs were dropped or failed`, brokenStorage.observations.length === 0 && brokenStorage.issuedGuids.size === 0 && (mode === "hangObserve" ? observer.stats.dropped > 0 : observer.stats.writeErrors > 0), JSON.stringify(observer.stats));
    const logged = errorLines.slice(errorsBefore);
    check(`${mode}: failures are logged at most once per job type`, logged.every((l) => l.startsWith("[observe] ")) && logged.length <= 5 && (mode === "hangObserve" ? logged.length === 0 : logged.length >= 1), JSON.stringify(logged));
    const flushed = await Promise.race([observer.flushTraffic().then(() => "resolved"), new Promise((resolve) => setTimeout(() => resolve("pending"), 300))]);
    check(`${mode}: flush never throws`, mode === "failObserve" ? flushed === "resolved" : true, flushed);
    const stopped = await Promise.race([observer.stop().then(() => "resolved"), new Promise((resolve) => setTimeout(() => resolve("pending"), 300))]);
    check(`${mode}: counts survive a failed flush in bounded memory`, observer.pendingTraffic.size <= 5000 && (mode === "hangObserve" || (stopped === "resolved" && observer.pendingTraffic.size > 0)), `pending=${observer.pendingTraffic.size} ${stopped}`);
    broken.server.close();
  }

  console.log("\n=== OBSERVE: admin read endpoints ===");
  {
    for (const urlPath of ["/admin/api/observations", "/admin/api/observation-summary"]) {
      const noAuth = await request(obs.base, { path: urlPath });
      const badAuth = await request(obs.base, { path: urlPath, headers: { Authorization: "Bearer nope" } });
      check(`GET ${urlPath} requires admin auth`, noAuth.status === 401 && badAuth.status === 401, `${noAuth.status} ${badAuth.status}`);
    }

    const all = await getJson(obs.base, "/admin/api/observations", adminAuth);
    check("GET /admin/api/observations -> 200 array, newest first", all.status === 200 && Array.isArray(all.json) && all.json.length > 10 && all.json.every((o, i) => i === 0 || all.json[i - 1].at > o.at || (all.json[i - 1].at === o.at && all.json[i - 1].id > o.id)), `len=${all.json && all.json.length}`);
    check("observation rows have the documented fields", all.json.every((o) => Object.keys(o).join(",") === "id,at,route,reason,ip,ipSource,userAgent,keyPrefix,guidRef,detail" && typeof o.detail === "object" && o.keyPrefix.length <= 8 && o.userAgent.length <= 300), JSON.stringify(all.json[0]));
    const byReason = await getJson(obs.base, "/admin/api/observations?reason=extra_unexpected", adminAuth);
    check("reason filter", byReason.json.length === 2 && byReason.json.every((o) => o.reason === "extra_unexpected"), byReason.body);
    const byRoute = await getJson(obs.base, "/admin/api/observations?route=/player-profile", adminAuth);
    check("route filter", byRoute.json.length === 2 && byRoute.json.every((o) => o.route === "/player-profile"), byRoute.body);
    const limited = await getJson(obs.base, "/admin/api/observations?limit=3", adminAuth);
    const overLimit = await getJson(obs.base, "/admin/api/observations?limit=999999", adminAuth);
    check("limit is honoured and capped", limited.json.length === 3 && limited.json[0].id === all.json[0].id && overLimit.status === 200 && overLimit.json.length === obsStorage.observations.length);
    const future = await getJson(obs.base, `/admin/api/observations?since=${Math.floor(Date.now() / 1000) + 3600}`, adminAuth);
    check("since filter", future.status === 200 && future.json.length === 0, future.body);

    const summary = await getJson(obs.base, "/admin/api/observation-summary", adminAuth);
    const s = summary.json;
    check("GET /admin/api/observation-summary -> 200 with every section", summary.status === 200 && ["enabled", "since", "until", "expectedPublicKeys", "limits", "observations", "contract", "publicKeys", "uploads", "issuedGuids", "rate", "clientAddress", "observationTotals", "process"].every((key) => key in s), Object.keys(s || {}).join(","));
    check("summary: counts grouped by reason and route", s.observations.some((o) => o.reason === "guid_not_issued" && o.route === "/entry/upload" && o.count === 4 && o.distinctIps === 1) && s.observations.some((o) => o.reason === "profile_fields" && o.route === "/player-profile" && o.count === 2), JSON.stringify(s.observations));
    check("summary: public keys in use, by prefix", s.publicKeys.some((k) => k.keyPrefix === "536aec42" && k.expected === true && k.route === "/entry/upload" && k.count > 5) && s.publicKeys.some((k) => k.keyPrefix === "ff61800f" && k.expected === false && k.length === 64) && s.expectedPublicKeys[0].keyPrefix === "536aec42", JSON.stringify(s.publicKeys));
    check("summary: share of uploads using a server-issued GUID", s.uploads.guidIssued === 13 && s.uploads.guidNotIssued === 4 && s.uploads.guidNotIssuedNewEntry === 3 && s.uploads.guidNotIssuedExistingEntry === 1 && s.uploads.issuedShare === 0.7647 && s.uploads.requests === 17, JSON.stringify(s.uploads));
    check("summary: issued GUID counts by address source", s.issuedGuids.total === obsStorage.issuedGuids.size && s.issuedGuids.bySource[0].ipSource === "socket" && s.issuedGuids.bySource[0].distinctIps === 1, JSON.stringify(s.issuedGuids));
    const uploadContract = s.contract["/entry/upload"];
    check("summary: content types, unity versions, origins, statuses", uploadContract.requests === 17 && uploadContract.contentType.multipart === 17 && uploadContract.unityVersion["2022.3.10f1"] === 17 && uploadContract.origin["play.example.com"] === 1 && uploadContract.status["200"] === 16 && uploadContract.status["400"] === 1 && uploadContract.userAgent["UnityPlayer/2022.3.10f1"] === 17, JSON.stringify(uploadContract));
    check("summary: whether /get carries userGuid", s.contract["/get"].userGuid["1"] === 1 && s.contract["/get"].userGuid["0"] === 3, JSON.stringify(s.contract["/get"].userGuid));
    check("summary: username score relation and extra values", s.uploads.usernameScoreRelation.score_div_100 === 10 && s.uploads.usernameScoreRelation.raw_score === 3 && s.uploads.usernameScoreRelation.mismatch === 1 && s.uploads.usernameScoreRelation.shape_mismatch === 1 && s.uploads.extraValues['value:"yes"'] === 2 && s.uploads.extraValues.single_space === 15, JSON.stringify([s.uploads.usernameScoreRelation, s.uploads.extraValues]));
    check("summary: observed score range", s.uploads.storedScoreRange.min === -5 && s.uploads.storedScoreRange.max === 999999999 && s.uploads.scoreShape.negative === 1 && s.uploads.scoreShape.not_integer === 2 && s.uploads.scoreShape.digits_3 > 3, JSON.stringify([s.uploads.storedScoreRange, s.uploads.scoreShape]));
    check("summary: proposed rate limits with their trigger counts", s.rate.length === 4 && s.rate.every((r) => r.windowsTriggered === 0 && r.requestsOverLimit === 0 && r.requests > 0) && s.rate[0].limit === 30 && s.rate[0].windowSeconds === 600 && s.rate[3].limit === 10 && s.rate[3].windowSeconds === 3600, JSON.stringify(s.rate));
    check("summary: client address sources", s.clientAddress["/get"].shapes["src=x-real-ip;xri=1;xff=2;xri_eq_xff=first;sock=loopback"] === 1 && s.clientAddress["/get"].distinctClientsPerHourSummed === 2, JSON.stringify(s.clientAddress["/get"]));
    const hourly = await getJson(obs.base, "/admin/api/observation-summary?hourly=1", adminAuth);
    check("summary: hourly rows on request", !("trafficHourly" in s) && Array.isArray(hourly.json.trafficHourly) && hourly.json.trafficHourly.every((row) => Object.keys(row).join(",") === "hour,route,dimKey,count"), JSON.stringify((hourly.json.trafficHourly || [])[0]));
    const none = await getJson(obs.base, `/admin/api/observation-summary?since=${Math.floor(Date.now() / 1000) + 7200}`, adminAuth);
    check("summary: since filter", none.status === 200 && none.json.observations.length === 0 && none.json.uploads.requests === 0 && none.json.uploads.issuedShare === null, none.body.slice(0, 200));

    const offSummary = await getJson(off.base, "/admin/api/observation-summary", adminAuth);
    check("summary on an observe-off server -> 200, enabled false, empty", offSummary.status === 200 && offSummary.json.enabled === false && offSummary.json.observations.length === 0 && offSummary.json.issuedGuids.total === 0, offSummary.body.slice(0, 200));

    const summaryText = summary.body + all.body + hourly.body;
    check("admin responses hold no full key or GUID", !summaryText.includes(LIVE_KEY) && !summaryText.includes(OLD_KEY) && usedGuids.every((g) => !summaryText.includes(g)));
  }

  console.log("\n=== OBSERVE: no credential in any row or log line ===");
  {
    const rowsText = JSON.stringify(obsStorage.observations) + JSON.stringify([...obsStorage.traffic.values()]);
    const logText = observeLines.join("\n") + errorLines.join("\n");
    check("[observe] lines were emitted, one per stored row on the main server", observeLines.length > 20 && obsStorage.observations.every((o) => observeLines.some((l) => l.includes(`"reason":"${o.reason}"`) && l.includes(`"at":${o.at}`))));
    check("no full public key in rows or [observe] lines", ![LIVE_KEY, OLD_KEY, PUBLIC_KEY].some((key) => rowsText.includes(key) || logText.includes(key)));
    check("no full GUID in rows or [observe] lines", usedGuids.length > 15 && usedGuids.every((g) => !rowsText.includes(g) && !logText.includes(g)) && !rowsText.includes("typed-by-hand") && !logText.includes("typed-by-hand") && !logText.includes("made-up-guid") && !logText.includes("guid-1"));
    check("every guid_ref is a 32-char mask or empty", obsStorage.observations.every((o) => o.guidRef === "" || MASK_PATTERN.test(o.guidRef)));
    check("every stored field is within its limit", obsStorage.observations.every((o) => o.detail.length <= 1000 && o.userAgent.length <= 300 && o.ip.length <= 64 && o.keyPrefix.length <= 8));
  }

  obs.server.close();
  off.server.close();

  check("no unexpected server errors were logged", errorLines.every((l) => /Entry history write failed/.test(l) || l.startsWith("[observe] ")), JSON.stringify(errorLines));

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
