// Onboarding outbox: delivery contract (2xx = safe, anything else = keep and
// retry), stable Idempotency-Key, once per email, 24 h window, and the Slack
// alert rule (one alert after 30 min, one "fixed", reminders <= 1 per 24 h,
// no alert for a blip, state survives a restart). Uses a mock onboarding-bridge
// and a mock Slack webhook, and a throwaway Postgres in TEST_DATABASE_URL.
// Run: TEST_DATABASE_URL=postgres://user@localhost:5432/throwaway node test/outbox-test.js

const { PostgresStorage } = require("../src/storage/postgres");
const { LeaderboardService } = require("../src/service");
const { createApp } = require("../src/app");
const h = require("./helpers");

const url = h.requireTestDatabase();
const check = h.check;
const SECRET = "test-shared-secret";
const ADMIN_TOKEN = "test-admin-token";

const logs = { error: [], warn: [], log: [] };
console.error = (...args) => logs.error.push(args.map(String).join(" "));
console.warn = (...args) => logs.warn.push(args.map(String).join(" "));
const printLine = console.log;
console.log = (...args) => {
  const line = args.map(String).join(" ");
  logs.log.push(line);
  if (/^\s+(PASS|FAIL)|^\n?===|RESULTS|ALL GREEN|Failures|^\s+- /.test(line)) {
    printLine(line);
  }
};

// Mock onboarding-bridge whose behaviour each test sets.
let bridgeMode = "ok"; // ok | down | hang | bad-request
const bridge = { requests: null };
// Mock Slack.
let slackMode = "ok";

async function makeService(storage, mocks, extra = {}) {
  const config = {
    corsOrigin: "*",
    allowedPublicKeys: [],
    maxUsernameLength: 127,
    maxExtraLength: 100,
    observe: { enabled: false },
    adminToken: ADMIN_TOKEN,
    onboardUrl: `${mocks.bridge.url}/api/switchmax`,
    onboardSharedSecret: SECRET,
    onboardTimeoutMs: 300,
    onboardTickMs: 3600000, // the tests drive passes by hand
    slackWebhookUrl: `${mocks.slack.url}/hook`,
    ...extra
  };
  const service = new LeaderboardService(storage, config);
  const app = await h.listen(createApp(service, config));
  return { service, app, config };
}

async function drain(service) {
  for (let i = 0; i < 20; i++) {
    await service.onboarding.kick();
    if (!service.onboarding.running) {
      return;
    }
  }
}

const profile = (base, email, extra = {}) => h.request(base, {
  method: "POST",
  path: "/player-profile",
  body: { name: "Dana", email, country: "GB", consentAccepted: "1", userGuid: `guid-${email}`, ...extra }
});
const row = async (email) => (await h.adminQuery("SELECT * FROM onboarding_outbox WHERE email = $1", [email])).rows[0];

async function main() {
  await h.dropTables([...h.ALL_TABLES, "upload_sessions", "onboarding_outbox", "alert_state"]);
  const mocks = {
    bridge: await h.startMockServer(() => {
      if (bridgeMode === "down") return { status: 503, body: { error: "down" } };
      if (bridgeMode === "hang") return "hang";
      if (bridgeMode === "bad-request") return { status: 400, body: { error: "bad" } };
      return { status: 200, body: { success: true } };
    }),
    slack: await h.startMockServer(() => (slackMode === "ok" ? { status: 200, body: "ok" } : { status: 500, body: "no" }))
  };
  bridge.requests = mocks.bridge.requests;
  const slackTexts = () => mocks.slack.requests.map((r) => JSON.parse(r.body).text);

  const storage = new PostgresStorage(url, { ssl: false });
  await storage.initialize();
  let { service, app } = await makeService(storage, mocks);
  check("startup line says the outbox is on", /outbox on/.test(service.describeOnboarding()) && /sent to Slack/.test(service.describeOnboarding()), service.describeOnboarding());

  console.log("\n=== bridge answers 200 ===");
  {
    const res = await profile(app.base, "ok1@example.com");
    check("player gets 200 {ok:true}", res.status === 200 && res.body === '{"ok":true}');
    await drain(service);
    check("bridge got exactly one request", bridge.requests.length === 1, `${bridge.requests.length}`);
    const req = bridge.requests[0];
    const body = JSON.parse(req.body);
    check("request carries the shared secret and an Idempotency-Key", req.headers["x-shared-secret"] === SECRET && /^[0-9a-f-]{36}$/.test(req.headers["idempotency-key"] || ""), JSON.stringify(req.headers));
    check("request body is the same shape as before", JSON.stringify(Object.keys(body)) === '["name","email","country","consent"]' && body.consent === true && body.email === "ok1@example.com", req.body);
    const r = await row("ok1@example.com");
    check("row marked sent and personal data cleared", r.status === "sent" && r.payload === "{}" && r.sent_at !== null, JSON.stringify(r));
    const again = await profile(app.base, "ok1@example.com");
    await drain(service);
    check("same email again (with proof) -> 200, no second Pipedrive call", again.status === 200 && bridge.requests.length === 1, `${bridge.requests.length}`);
  }

  console.log("\n=== bridge failing, then back: same Idempotency-Key, backoff ===");
  {
    bridge.requests.length = 0;
    bridgeMode = "down";
    await profile(app.base, "retry@example.com");
    await drain(service);
    let r = await row("retry@example.com");
    check("503 -> row kept as pending, attempts 1", r.status === "pending" && r.attempts === 1 && r.last_error === "HTTP 503", JSON.stringify(r));
    check("next attempt is about 60 s later", Number(r.next_attempt_at) - Math.floor(Date.now() / 1000) >= 55, `${r.next_attempt_at}`);
    await drain(service);
    check("not retried before it is due", bridge.requests.length === 1);
    bridgeMode = "hang";
    await h.adminQuery("UPDATE onboarding_outbox SET next_attempt_at = 0 WHERE email = $1", ["retry@example.com"]);
    await drain(service);
    r = await row("retry@example.com");
    check("timeout -> kept, attempts 2, second backoff step (120 s)", r.status === "pending" && r.attempts === 2 && /timeout/.test(r.last_error) && Number(r.next_attempt_at) - Math.floor(Date.now() / 1000) >= 115, JSON.stringify(r));
    bridgeMode = "bad-request";
    await h.adminQuery("UPDATE onboarding_outbox SET next_attempt_at = 0 WHERE email = $1", ["retry@example.com"]);
    await drain(service);
    r = await row("retry@example.com");
    check("400 is not 2xx either -> kept", r.status === "pending" && r.attempts === 3 && r.last_error === "HTTP 400");
    bridgeMode = "ok";
    await h.adminQuery("UPDATE onboarding_outbox SET next_attempt_at = 0 WHERE email = $1", ["retry@example.com"]);
    await drain(service);
    r = await row("retry@example.com");
    check("bridge back -> delivered", r.status === "sent", JSON.stringify(r));
    const keys = new Set(bridge.requests.map((q) => q.headers["idempotency-key"]));
    check("all 4 attempts used the same Idempotency-Key", bridge.requests.length === 4 && keys.size === 1, `${bridge.requests.length} requests, ${keys.size} keys`);
    check("short blip -> no Slack message at all", mocks.slack.requests.length === 0, JSON.stringify(slackTexts()));
  }

  console.log("\n=== waiting over 30 min: one alert, survives restart, reminder, one fixed ===");
  {
    bridgeMode = "down";
    await profile(app.base, "stuck1@example.com");
    await profile(app.base, "stuck2@example.com");
    await drain(service);
    check("under 30 min: no alert", mocks.slack.requests.length === 0);
    await h.adminQuery("UPDATE onboarding_outbox SET created_at = created_at - 1860, next_attempt_at = 0 WHERE email LIKE 'stuck%'");
    await drain(service);
    check("over 30 min: exactly one Slack message", mocks.slack.requests.length === 1, JSON.stringify(slackTexts()));
    const text = slackTexts()[0] || "";
    check("message says what, how many, the error and what to do", /2 Switch Max sign-ups have been waiting more than 30 minutes/.test(text) && /HTTP 503/.test(text) && /What to do/.test(text), text);
    check("message holds no email address", !/@/.test(text), text);
    await h.adminQuery("UPDATE onboarding_outbox SET next_attempt_at = 0 WHERE email LIKE 'stuck%'");
    await drain(service);
    await drain(service);
    check("still failing: no second message", mocks.slack.requests.length === 1);

    // Restart: a new service on the same database.
    await app.close();
    ({ service, app } = await makeService(storage, mocks));
    await drain(service);
    check("after a restart: still no repeat", mocks.slack.requests.length === 1);

    await h.adminQuery("UPDATE alert_state SET alerted_at = alerted_at - 86400 - 60 WHERE key = 'onboarding_backlog'");
    await drain(service);
    check("after 24 h: exactly one reminder", mocks.slack.requests.length === 2 && /^Reminder, still not fixed/.test(slackTexts()[1]), JSON.stringify(slackTexts()));
    await drain(service);
    check("no second reminder straight after", mocks.slack.requests.length === 2);

    bridgeMode = "ok";
    await h.adminQuery("UPDATE onboarding_outbox SET next_attempt_at = 0 WHERE email LIKE 'stuck%'");
    await drain(service);
    check("drained -> exactly one 'fixed' message", mocks.slack.requests.length === 3 && /fixed/i.test(slackTexts()[2]), JSON.stringify(slackTexts()));
    await drain(service);
    check("nothing after the fixed message", mocks.slack.requests.length === 3);
  }

  console.log("\n=== Slack down when the alert is due: retried, sent once ===");
  {
    bridgeMode = "down";
    slackMode = "down";
    await profile(app.base, "slackdown@example.com");
    await h.adminQuery("UPDATE onboarding_outbox SET created_at = created_at - 1860 WHERE email = 'slackdown@example.com'");
    await drain(service);
    const tries = mocks.slack.requests.length;
    check("Slack refused the alert (a try was made)", tries === 4);
    slackMode = "ok";
    await drain(service);
    check("next pass delivers it", mocks.slack.requests.length === 5 && /waiting more than 30 minutes/.test(slackTexts()[4]));
    await drain(service);
    check("and only once", mocks.slack.requests.length === 5);
  }

  console.log("\n=== 24 h window over -> stops, admin retry ===");
  {
    await h.adminQuery("UPDATE onboarding_outbox SET deadline_at = 1, next_attempt_at = 0 WHERE email = 'slackdown@example.com'");
    await drain(service);
    let r = await row("slackdown@example.com");
    check("past the deadline and still failing -> status failed", r.status === "failed", JSON.stringify(r));
    check("a 'stopped' line was logged", logs.error.some((l) => /retry window over/.test(l)));
    await h.adminQuery("UPDATE alert_state SET alerted_at = alerted_at - 86400 - 60");
    await drain(service);
    check("the reminder mentions the stopped one", /passed the 24 h retry window/.test(slackTexts()[slackTexts().length - 1] || ""), slackTexts()[slackTexts().length - 1]);
    const noAuth = await h.request(app.base, { method: "POST", path: "/admin/api/onboarding-outbox/retry", body: {} });
    check("retry endpoint needs admin auth", noAuth.status === 401, `${noAuth.status}`);
    const form = await h.request(app.base, { method: "POST", path: "/admin/api/onboarding-outbox/retry", headers: { Authorization: `Bearer ${ADMIN_TOKEN}`, "Content-Type": "text/plain" }, body: "x" });
    check("retry endpoint refuses non-JSON", form.status === 415, `${form.status}`);
    bridgeMode = "ok";
    const before = mocks.slack.requests.length;
    const retry = await h.request(app.base, { method: "POST", path: "/admin/api/onboarding-outbox/retry", headers: { Authorization: `Bearer ${ADMIN_TOKEN}` }, body: {} });
    check("retry -> 200 {requeued:1}", retry.status === 200 && JSON.parse(retry.body).requeued === 1, retry.body);
    await drain(service);
    r = await row("slackdown@example.com");
    check("retried row delivered", r.status === "sent");
    check("...and one fixed message", mocks.slack.requests.length === before + 1 && /fixed/i.test(slackTexts()[before]));
    const summary = await h.request(app.base, { path: "/admin/api/onboarding-outbox", headers: { Authorization: `Bearer ${ADMIN_TOKEN}` } });
    check("summary endpoint lists counts per status", summary.status === 200 && JSON.parse(summary.body).rows.some((x) => x.status === "sent"), summary.body);
  }

  console.log("\n=== outbox write fails -> one direct try + an immediate alert ===");
  {
    const slackBefore = mocks.slack.requests.length;
    const bridgeBefore = bridge.requests.length;
    await h.adminQuery("ALTER TABLE onboarding_outbox RENAME TO onboarding_outbox_hidden");
    const res = await profile(app.base, "nowhere@example.com");
    const res2 = await profile(app.base, "nowhere2@example.com");
    await h.waitFor(() => mocks.slack.requests.length > slackBefore && bridge.requests.length >= bridgeBefore + 2);
    await h.sleep(100);
    await h.adminQuery("ALTER TABLE onboarding_outbox_hidden RENAME TO onboarding_outbox");
    check("player still gets 200", res.status === 200 && res2.status === 200);
    check("direct call to the bridge was made (both)", bridge.requests.length === bridgeBefore + 2);
    check("exactly one immediate alert for the burst", mocks.slack.requests.length === slackBefore + 1 && /could not be queued for Pipedrive/.test(slackTexts()[slackBefore]), JSON.stringify(slackTexts().slice(slackBefore)));
  }

  console.log("\n=== not configured (no shared secret) ===");
  {
    await app.close();
    ({ service, app } = await makeService(storage, mocks, { onboardSharedSecret: "" }));
    check("startup line says it is off", /OFF/.test(service.describeOnboarding()), service.describeOnboarding());
    const slackBefore = mocks.slack.requests.length;
    const bridgeBefore = bridge.requests.length;
    await profile(app.base, "unconfigured@example.com");
    await h.adminQuery("UPDATE onboarding_outbox SET created_at = created_at - 7200 WHERE email = 'unconfigured@example.com'");
    await drain(service);
    const r = await row("unconfigured@example.com");
    check("lead kept as pending, nothing sent, no alert", r.status === "pending" && bridge.requests.length === bridgeBefore && mocks.slack.requests.length === slackBefore, JSON.stringify(r));
    await app.close();
    ({ service, app } = await makeService(storage, mocks));
    await drain(service);
    check("once configured it is delivered", (await row("unconfigured@example.com")).status === "sent");
  }

  console.log("\n=== log hygiene ===");
  {
    const all = [...logs.error, ...logs.warn, ...logs.log].join("\n");
    check("no email address in any log line", !/[a-z0-9]+@example\.com/.test(all), all.split("\n").filter((l) => /@/.test(l)).slice(0, 3).join(" | "));
    check("no shared secret or webhook URL in any log line", !all.includes(SECRET) && !all.includes("/hook"));
  }

  await app.close();
  await service.stop();
  await storage.close();
  await mocks.bridge.close();
  await mocks.slack.close();
  h.finish();
}

main().catch((error) => {
  printLine(error);
  process.exit(1);
});
