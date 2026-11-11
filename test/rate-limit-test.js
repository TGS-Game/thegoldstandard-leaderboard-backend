// Rate limits and trust proxy. No database needed (uses the in-memory fake).
// Run: node test/rate-limit-test.js

const { createApp } = require("../src/app");
const { LeaderboardService } = require("../src/service");
const { resolveRateLimits, resolveTrustProxy, parseLimit } = require("../src/rate-limit");
const { FakeStorage } = require("./fake-storage");
const h = require("./helpers");

const check = h.check;
const baseConfig = {
  corsOrigin: "*",
  allowedPublicKeys: [],
  maxUsernameLength: 127,
  maxExtraLength: 100,
  adminPassword: "test-password-do-not-ship",
  sessionSecret: "test-session-secret",
  observe: { enabled: false }
};

async function start(extra) {
  const config = { ...baseConfig, ...extra };
  const service = new LeaderboardService(new FakeStorage(), config);
  return h.listen(createApp(service, config));
}


async function main() {
  const warns = [];
  console.warn = (...args) => warns.push(args.join(" "));

  console.log("\n=== config parsing ===");
  check("parseLimit '5/60'", JSON.stringify(parseLimit("5/60")) === JSON.stringify({ max: 5, windowSeconds: 60 }));
  check("parseLimit 'off' -> null", parseLimit("off", { max: 1, windowSeconds: 1 }) === null);
  check("parseLimit junk -> fallback", parseLimit("abc", "fb") === "fb");
  check("defaults on with no env", resolveRateLimits({}).enabled === true);
  check("RATE_LIMITS=off switches off", resolveRateLimits({ RATE_LIMITS: "off" }).enabled === false);
  check("RATE_UPLOAD_IP override", resolveRateLimits({ RATE_UPLOAD_IP: "3/10" }).limits.upload.perIp.max === 3);
  check("trust proxy: 1 on Railway", resolveTrustProxy({ RAILWAY_ENVIRONMENT_NAME: "production" }) === 1);
  check("trust proxy: off locally", resolveTrustProxy({}) === false);
  check("trust proxy: TRUST_PROXY=off beats Railway", resolveTrustProxy({ TRUST_PROXY: "off", RAILWAY_PROJECT_ID: "x" }) === false);
  check("trust proxy: TRUST_PROXY=2", resolveTrustProxy({ TRUST_PROXY: "2" }) === 2);

  console.log("\n=== no rateLimits in config -> nothing limited (existing behaviour) ===");
  {
    const app = await start({});
    let ok = 0;
    for (let i = 0; i < 30; i++) {
      const res = await h.request(app.base, { path: "/authorize" });
      if (res.status === 200) ok++;
    }
    check("30 x /authorize all 200", ok === 30, `ok=${ok}`);
    await app.close();
  }

  const tight = resolveRateLimits({
    RATE_AUTHORIZE_IP: "3/60",
    RATE_AUTHORIZE_GLOBAL: "5/60",
    RATE_UPLOAD_IP: "2/60",
    RATE_PROFILE_IP: "2/60",
    RATE_ADMIN_LOGIN_IP: "2/60"
  });

  console.log("\n=== per-IP limit with trust proxy 1 (X-Forwarded-For last hop) ===");
  {
    const app = await start({ rateLimits: tight, trustProxy: 1 });
    const fromIp = (ip, spoof) => ({ "X-Forwarded-For": spoof ? `${spoof}, ${ip}` : ip });
    const statuses = [];
    for (let i = 0; i < 4; i++) {
      statuses.push((await h.request(app.base, { path: "/authorize", headers: fromIp("203.0.113.1") })).status);
    }
    check("client A: 3 x 200 then 429", statuses.join(",") === "200,200,200,429", statuses.join(","));
    const r429 = await h.request(app.base, { path: "/authorize", headers: fromIp("203.0.113.1") });
    check("429 has Retry-After and CORS header", Number(r429.headers["retry-after"]) > 0 && r429.headers["access-control-allow-origin"] === "*", JSON.stringify(r429.headers));
    check("429 body is plain text", r429.body === "Too many requests." && /text\/plain/.test(r429.headers["content-type"]));
    const spoofed = await h.request(app.base, { path: "/authorize", headers: fromIp("203.0.113.1", "198.51.100.77") });
    check("faking an earlier X-Forwarded-For entry does not escape the limit", spoofed.status === 429, `status=${spoofed.status}`);
    const other = await h.request(app.base, { path: "/authorize", headers: fromIp("203.0.113.2") });
    check("client B still allowed (until the global cap)", other.status === 200, `status=${other.status}`);
    const other2 = await h.request(app.base, { path: "/authorize", headers: fromIp("203.0.113.3") });
    const other3 = await h.request(app.base, { path: "/authorize", headers: fromIp("203.0.113.4") });
    check("global cap 5/60: 6th allowed request overall is 429", other2.status === 429 || other3.status === 429, `${other2.status},${other3.status}`);
    check("one log line per window, not per request", warns.filter((l) => /authorize over the ip limit/.test(l)).length === 1, JSON.stringify(warns));
    check("a global-cap log line was printed", warns.some((l) => /authorize over the global limit/.test(l)));

    const up = [];
    for (let i = 0; i < 3; i++) {
      up.push((await h.request(app.base, {
        method: "POST",
        path: "/entry/upload",
        headers: fromIp("203.0.113.9"),
        body: { publicKey: "k", userGuid: `g${i}`, username: "A-GB-1", score: "1", extra: " " }
      })).status);
    }
    check("/entry/upload limited per IP (2/60)", up.join(",") === "200,200,429", up.join(","));

    const prof = [];
    for (let i = 0; i < 3; i++) {
      prof.push((await h.request(app.base, {
        method: "POST",
        path: "/player-profile",
        headers: fromIp("203.0.113.10"),
        body: { name: "A", email: `a${i}@example.com`, country: "GB", consentAccepted: "1" }
      })).status);
    }
    check("/player-profile limited per IP (2/60)", prof.join(",") === "200,200,429", prof.join(","));

    const login = [];
    for (let i = 0; i < 3; i++) {
      login.push((await h.request(app.base, {
        method: "POST",
        path: "/admin/login",
        headers: { ...fromIp("203.0.113.11"), "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ password: "wrong" }).toString()
      })).status);
    }
    check("POST /admin/login limited per IP (2/60)", login.join(",") === "302,302,429", login.join(","));

    const get = await h.request(app.base, { path: "/get?publicKey=k", headers: fromIp("203.0.113.1") });
    check("/get is never limited", get.status === 200, `status=${get.status}`);
    const health = await h.request(app.base, { path: "/health", headers: fromIp("203.0.113.1") });
    check("/health is never limited", health.status === 200);
    await app.close();
  }

  console.log("\n=== without trust proxy, X-Forwarded-For is ignored ===");
  {
    const app = await start({ rateLimits: tight, trustProxy: false });
    const statuses = [];
    for (let i = 0; i < 4; i++) {
      statuses.push((await h.request(app.base, { path: "/authorize", headers: { "X-Forwarded-For": `198.51.100.${i}` } })).status);
    }
    check("rotating X-Forwarded-For does not reset the limit", statuses.join(",") === "200,200,200,429", statuses.join(","));
    await app.close();
  }

  h.finish();
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
