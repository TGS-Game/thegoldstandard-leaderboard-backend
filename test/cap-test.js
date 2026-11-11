// Daily Pipedrive cap: over ONBOARD_DAILY_CAP new sign-ups are held (kept, not
// sent); one Slack alert after 5 minutes, one "fixed" when none are held; a
// release or discard by the admin. Mock bridge + mock Slack + TEST_DATABASE_URL.
// Run: TEST_DATABASE_URL=postgres://user@localhost:5432/throwaway node test/cap-test.js

const { PostgresStorage } = require("../src/storage/postgres");
const { LeaderboardService } = require("../src/service");
const { createApp } = require("../src/app");
const h = require("./helpers");

const url = h.requireTestDatabase();
const check = h.check;
const ADMIN = { Authorization: "Bearer test-admin-token" };

const printLine = console.log;
console.log = (...args) => {
  const line = args.map(String).join(" ");
  if (/^\s+(PASS|FAIL)|^\n?===|RESULTS|ALL GREEN|Failures|^\s+- /.test(line)) printLine(line);
};
console.warn = () => {};
console.error = () => {};

async function main() {
  await h.dropTables([...h.ALL_TABLES, "upload_sessions", "onboarding_outbox", "alert_state"]);
  const bridge = await h.startMockServer(() => ({ status: 200, body: { success: true } }));
  const slack = await h.startMockServer(() => ({ status: 200, body: "ok" }));
  const texts = () => slack.requests.map((r) => JSON.parse(r.body).text);

  const storage = new PostgresStorage(url, { ssl: false });
  await storage.initialize();
  const config = {
    corsOrigin: "*",
    allowedPublicKeys: [],
    maxUsernameLength: 127,
    maxExtraLength: 100,
    observe: { enabled: false },
    adminToken: "test-admin-token",
    onboardUrl: `${bridge.url}/api/switchmax`,
    onboardSharedSecret: "test-shared-secret",
    onboardTickMs: 3600000,
    onboardDailyCap: 3,
    slackWebhookUrl: `${slack.url}/hook`
  };
  const service = new LeaderboardService(storage, config);
  const app = await h.listen(createApp(service, config));
  const drain = async () => {
    for (let i = 0; i < 20 && (await service.onboarding.kick(), service.onboarding.running); i++);
  };
  const register = (i) => h.request(app.base, { method: "POST", path: "/player-profile", body: { name: `P${i}`, email: `p${i}@example.com`, country: "GB", consentAccepted: "1" } });
  const statuses = async () => (await h.adminQuery("SELECT status, count(*)::int AS n FROM onboarding_outbox GROUP BY status ORDER BY status")).rows.map((r) => `${r.status}:${r.n}`).join(",");

  console.log("\n=== over the cap ===");
  const answers = [];
  for (let i = 1; i <= 5; i++) {
    answers.push((await register(i)).body);
  }
  await drain();
  check("every player still gets 200 {ok:true}", answers.every((b) => b === '{"ok":true}'), answers.join(" "));
  check("3 sent, 2 held", (await statuses()) === "held:2,sent:3", await statuses());
  check("bridge got exactly 3 requests", bridge.requests.length === 3, `${bridge.requests.length}`);
  check("no Slack yet (held for under 5 min)", slack.requests.length === 0);

  await h.adminQuery("UPDATE alert_state SET since = since - 301 WHERE key = 'onboarding_daily_cap'");
  await drain();
  check("after 5 min: exactly one alert", slack.requests.length === 1, JSON.stringify(texts()));
  check("alert text: 'Leaderboard blocked 2 Pipedrive sign-ups today — possible abuse'", /^Leaderboard blocked 2 Pipedrive sign-ups today — possible abuse\./.test(texts()[0] || ""), texts()[0]);
  check("alert says what to do", /What to do/.test(texts()[0]) && /retry/.test(texts()[0]) && /discard/.test(texts()[0]));
  await register(6);
  await drain();
  check("more held: no second message", slack.requests.length === 1 && (await statuses()) === "held:3,sent:3", await statuses());

  console.log("\n=== admin releases, then discards ===");
  const bad = await h.request(app.base, { method: "POST", path: "/admin/api/onboarding-outbox/retry", headers: ADMIN, body: { status: "sent" } });
  check("retry with status 'sent' -> 400", bad.status === 400, `${bad.status}`);
  const release = await h.request(app.base, { method: "POST", path: "/admin/api/onboarding-outbox/retry", headers: ADMIN, body: { status: "held" } });
  check("release held -> {requeued:3}", release.status === 200 && JSON.parse(release.body).requeued === 3, release.body);
  await drain();
  check("released ones are sent even over the cap", (await statuses()) === "sent:6" && bridge.requests.length === 6, await statuses());
  check("one 'fixed' message", slack.requests.length === 2 && /fixed/i.test(texts()[1]), JSON.stringify(texts()));

  await register(7);
  await drain();
  check("cap still applies for new ones today", (await statuses()) === "held:1,sent:6", await statuses());
  const discard = await h.request(app.base, { method: "POST", path: "/admin/api/onboarding-outbox/discard", headers: ADMIN, body: { status: "held" } });
  await drain();
  check("discard held -> {discarded:1}, never sent", discard.status === 200 && JSON.parse(discard.body).discarded === 1 && bridge.requests.length === 6, discard.body);
  check("held for under 5 min then cleared: no message (blip)", slack.requests.length === 2, JSON.stringify(texts()));
  const dropped = (await h.adminQuery("SELECT payload FROM onboarding_outbox WHERE status = 'discarded'")).rows[0];
  check("discarded row keeps no personal data", dropped && dropped.payload === "{}");
  await register(7);
  await drain();
  check("a discarded email is not queued again", bridge.requests.length === 6 && (await statuses()) === "discarded:1,sent:6");

  console.log("\n=== cap 0 = off ===");
  const open = new LeaderboardService(storage, { ...config, onboardDailyCap: 0 });
  for (let i = 10; i < 15; i++) {
    await open.onboarding.enqueue({ name: "x", email: `open${i}@example.com`, country: "GB", consent: false });
  }
  for (let i = 0; i < 20 && (await open.onboarding.kick(), open.onboarding.running); i++);
  check("with cap 0 nothing is held", !(await statuses()).includes("held"), await statuses());
  check("startup line shows the cap", /daily cap 3/.test(service.describeOnboarding()) && /daily cap off/.test(open.describeOnboarding()));

  await app.close();
  await service.stop();
  await open.stop();
  await storage.close();
  await bridge.close();
  await slack.close();
  h.finish();
}

main().catch((error) => {
  printLine(error);
  process.exit(1);
});
