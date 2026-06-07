// Cross-site iframe cookie test with REAL headless Chrome over HTTPS.
//
// Why: same-origin localhost can't catch third-party iframe cookie issues. This
// embeds the leaderboard /admin under a DIFFERENT origin (the "hub"), with
// third-party cookies phased out, and verifies the SSO-issued session cookie
// (SameSite=None; Secure; Partitioned) still round-trips inside the iframe.
//
// Pass condition: after the iframe hits /sso?token=..., the iframe's final URL
// is /admin (the panel) and NOT /admin/login. If the partitioned cookie were
// dropped, /admin would 302 to /admin/login.
//
// Run: node test/iframe-test.js

const fs = require("fs");
const path = require("path");
const https = require("https");
const http = require("http");
const crypto = require("crypto");
const { spawn } = require("child_process");

const { createApp } = require("../src/app");
const { LeaderboardService } = require("../src/service");
const { FakeStorage } = require("./fake-storage");

const CHROME = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const SSO_SECRET = "test-sso-secret";
const tls = {
  key: fs.readFileSync(path.join(__dirname, "tmp", "key.pem")),
  cert: fs.readFileSync(path.join(__dirname, "tmp", "cert.pem"))
};

function b64url(input) {
  return Buffer.from(input).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function mintJwt(jti) {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const now = Math.floor(Date.now() / 1000);
  const payload = b64url(JSON.stringify({ aud: "leaderboard", jti, iat: now, exp: now + 60 }));
  const sig = b64url(crypto.createHmac("sha256", SSO_SECRET).update(`${header}.${payload}`).digest());
  return `${header}.${payload}.${sig}`;
}

function listen(server) {
  return new Promise((res) => server.listen(0, "127.0.0.1", () => res(server.address().port)));
}
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function cdp(wsUrl) {
  const ws = new WebSocket(wsUrl);
  await new Promise((res, rej) => {
    ws.addEventListener("open", res, { once: true });
    ws.addEventListener("error", rej, { once: true });
  });
  let nextId = 1;
  const pending = new Map();
  const events = [];
  ws.addEventListener("message", (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
    } else if (msg.method) {
      events.push(msg);
    }
  });
  function send(method, params = {}, sessionId) {
    const id = nextId++;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      ws.send(JSON.stringify(payload));
    });
  }
  return { send, events, close: () => ws.close() };
}

async function main() {
  // App server (the leaderboard); hub origin filled in once we know its port.
  const storage = new FakeStorage();
  await storage.upsertEntry({ id: "x", publicKey: "k", userGuid: "g", username: "Z", score: 1, extra: "", createdAt: 1, updatedAt: 1 });

  let hubOrigin = "";
  const config = {
    port: 0, corsOrigin: "*", databaseUrl: "", allowedPublicKeys: [],
    adminToken: "", adminPassword: "pw", sessionSecret: "sess",
    sessionTtlSeconds: 43200, ssoSecret: SSO_SECRET, ssoAudience: "leaderboard",
    get hubOrigin() { return hubOrigin; },
    maxUsernameLength: 127, maxExtraLength: 100
  };
  const app = createApp(new LeaderboardService(storage, config), config);
  const appServer = https.createServer(tls, app);
  const appPort = await listen(appServer);
  const appOrigin = `https://127.0.0.1:${appPort}`;

  // Hub (parent) server on a DIFFERENT host (localhost) => cross-site.
  const token = mintJwt("iframe-jti-1");
  const hubServer = https.createServer(tls, (req, res) => {
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(`<!doctype html><html><body><h1>hub</h1>
      <iframe id="f" src="${appOrigin}/sso?token=${token}" width="600" height="400"></iframe>
      </body></html>`);
  });
  const hubPort = await listen(hubServer);
  hubOrigin = `https://localhost:${hubPort}`;
  const parentUrl = `${hubOrigin}/`;

  // Launch headless Chrome with third-party cookies phased out.
  const cdpPort = 9333;
  const profileDir = path.join(__dirname, "tmp", "chrome-profile");
  const chrome = spawn(CHROME, [
    "--headless=new",
    "--disable-gpu",
    "--no-first-run",
    "--no-default-browser-check",
    `--remote-debugging-port=${cdpPort}`,
    `--user-data-dir=${profileDir}`,
    "--ignore-certificate-errors",
    "--test-third-party-cookie-phaseout",
    "about:blank"
  ], { stdio: "ignore" });

  let pass = 0, fail = 0;
  const note = [];
  function check(name, cond, detail) {
    cond ? pass++ : fail++;
    console.log(`  ${cond ? "PASS" : "FAIL"}  ${name}${!cond && detail ? ` -> ${detail}` : ""}`);
  }

  try {
    // Wait for CDP HTTP endpoint.
    let version = null;
    for (let i = 0; i < 40; i++) {
      try {
        version = await new Promise((resolve, reject) => {
          http.get(`http://127.0.0.1:${cdpPort}/json/version`, (r) => {
            let d = ""; r.on("data", (c) => (d += c)); r.on("end", () => resolve(JSON.parse(d)));
          }).on("error", reject);
        });
        break;
      } catch (e) { await sleep(250); }
    }
    if (!version) throw new Error("Chrome CDP endpoint never came up");

    const client = await cdp(version.webSocketDebuggerUrl);
    const { targetId } = await client.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await client.send("Target.attachToTarget", { targetId, flatten: true });
    await client.send("Page.enable", {}, sessionId);
    // Reliable cert override for the self-signed cert (works in headless=new).
    await client.send("Security.enable", {}, sessionId);
    await client.send("Security.setIgnoreCertificateErrors", { ignore: true }, sessionId);
    // Cross-site iframes are out-of-process; auto-attach so we can see them.
    await client.send("Target.setAutoAttach", { autoAttach: true, flatten: true, waitForDebuggerOnStart: false }, sessionId);
    await client.send("Page.navigate", { url: parentUrl }, sessionId);

    // Give the iframe time to: load /sso -> set cookie -> 302 -> /admin.
    await sleep(3000);

    // Track the iframe target's current URL from attach + info-changed events.
    const iframeUrlByTarget = new Map();
    for (const ev of client.events) {
      if (ev.method === "Target.attachedToTarget" && ev.params.targetInfo.type === "iframe") {
        iframeUrlByTarget.set(ev.params.targetInfo.targetId, ev.params.targetInfo.url);
      }
      if (ev.method === "Target.targetInfoChanged" && ev.params.targetInfo.type === "iframe") {
        iframeUrlByTarget.set(ev.params.targetInfo.targetId, ev.params.targetInfo.url);
      }
    }
    const childUrls = [...iframeUrlByTarget.values()];
    note.push(`iframe url(s): ${JSON.stringify(childUrls)}`);

    const onAdmin = childUrls.some((u) => /\/admin(\?|$|#)/.test(u) && !/\/admin\/login/.test(u));
    const onLogin = childUrls.some((u) => /\/admin\/login/.test(u));

    check("cross-site iframe lands on /admin (partitioned cookie sent)", onAdmin, JSON.stringify(childUrls));
    check("cross-site iframe did NOT fall back to /admin/login", !onLogin, JSON.stringify(childUrls));

    client.close();
  } finally {
    chrome.kill();
    appServer.close();
    hubServer.close();
  }

  console.log("\n  " + note.join("\n  "));
  console.log(`\n  IFRAME RESULTS  PASS: ${pass}  FAIL: ${fail}`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
