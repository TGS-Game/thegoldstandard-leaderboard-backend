// Deterministic local test suite, run over real HTTPS with a self-signed cert.
// Covers: game-endpoint regression, /health, password login, SSO
// (valid/expired/replay/tampered/alg:none/wrong-aud), token auth in parallel,
// cookie attributes (HttpOnly; Secure; SameSite=None; Partitioned), and the
// rule that CSP frame-ancestors is set on admin pages only.
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

    const rename = await request(base, {
      method: "POST",
      path: "/entry/update-username",
      body: { publicKey: PUBLIC_KEY, userGuid: "guid-1", username: "Alice2" }
    });
    check("POST /entry/update-username -> 200", rename.status === 200, `status=${rename.status}`);

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
    check("POST /entry/delete -> 200", del.status === 200, `status=${del.status}`);
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
  console.error(e);
  process.exit(1);
});
