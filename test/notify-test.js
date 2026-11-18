// Support site notifications: a "high_score_approved" event when a game
// upload that passed every check becomes the new #1 on its board. Uses the
// in-memory FakeStorage (plus in-memory upload sessions) and a local stub
// HTTP server for the support site, so no database is needed.
// Run: node test/notify-test.js

const { LeaderboardService } = require("../src/service");
const { createApp } = require("../src/app");
const { SupportNotifier, DEFAULT_URL } = require("../src/notify-support");
const { FakeStorage } = require("./fake-storage");
const h = require("./helpers");

const check = h.check;
const KEY = "536aec42d31fa4ec5c486c219f9821f6a145562fcb069c6f19f40786fdc38678";
const OTHER_KEY = "someotherboardkey";
const SECRET = "test-notify-secret";
const ADMIN_TOKEN = "test-admin-token";

const logs = [];
const capture = (...args) => logs.push(args.join(" "));
console.log = ((original) => (...args) => {
  capture(...args);
  original(...args);
})(console.log);
console.warn = capture;
console.error = capture;

// FakeStorage plus the upload_sessions methods, so log mode can run.
class SessionStorage extends FakeStorage {
  constructor() {
    super();
    this.sessions = new Map();
  }
  async insertUploadSession({ guid, issuedAt }) {
    this.sessions.set(guid, { guid, issuedAt, usedAt: null });
  }
  async getUploadSession(guid) {
    const row = this.sessions.get(guid);
    return row ? { ...row } : null;
  }
  async claimUploadSession(guid, at) {
    const row = this.sessions.get(guid);
    if (!row || row.usedAt !== null) {
      return false;
    }
    row.usedAt = at;
    return true;
  }
  async releaseUploadSession(guid) {
    const row = this.sessions.get(guid);
    if (row) {
      row.usedAt = null;
    }
  }
  async pruneUploadSessions() {
    return 0;
  }
}

async function start({ secret = SECRET, url, mode = "log", ascending = [], timeoutMs = 1000, storage } = {}) {
  const config = {
    corsOrigin: "*",
    allowedPublicKeys: [],
    adminToken: ADMIN_TOKEN,
    sessionSecret: "test-session-secret",
    maxUsernameLength: 127,
    maxExtraLength: 100,
    observe: { enabled: false },
    uploadSession: { mode, ttlSeconds: 3600, minPlaySeconds: 0, maxScorePerSecond: 0 },
    notifications: { eventSecret: secret, url, ascendingPublicKeys: ascending, timeoutMs, retryDelaysMs: [50, 50] }
  };
  const service = new LeaderboardService(storage || new SessionStorage(), config);
  const app = await h.listen(createApp(service, config));
  return { ...app, service };
}

const authorize = async (base) => (await h.request(base, { path: "/authorize" })).body.trim();

// Multipart-free JSON upload, as the other suites do.
async function upload(base, { guid, name, score, key = KEY }) {
  const startedAt = Date.now();
  const res = await h.request(base, {
    method: "POST",
    path: "/entry/upload",
    body: { publicKey: key, userGuid: guid, username: name, score: String(score), extra: " " }
  });
  return { ...res, ms: Date.now() - startedAt };
}

// Authorize, then upload with that GUID (the shipped game's flow).
async function play(app, name, score, key) {
  const guid = await authorize(app.base);
  const res = await upload(app.base, { guid, name, score, key });
  return { ...res, guid };
}

const events = (stub) => stub.requests.map((r) => ({ ...r, json: JSON.parse(r.body) }));
const settle = () => h.sleep(150);

async function main() {
  console.log("\n=== secret unset: nothing is sent, one log line ===");
  {
    const stub = await h.startMockServer(() => ({ status: 202, body: { status: "scheduled" } }));
    logs.length = 0;
    const app = await start({ secret: "", url: `${stub.url}/api/notifications/events` });
    await play(app, "Ann", 100);
    const res = await play(app, "Ben", 200);
    await play(app, "Cy", 300);
    await settle();
    check("off: upload still 200", res.status === 200, `${res.status}`);
    check("off: no call to the support site", stub.requests.length === 0, `${stub.requests.length}`);
    const offLines = logs.filter((l) => l.includes("notifications: off (no secret)"));
    check("off: exactly one 'notifications: off (no secret)' line", offLines.length === 1, JSON.stringify(offLines));
    check("off: describe() says off", app.service.describeNotifications() === "notifications: off (no secret)");
    await app.close();
    await stub.close();
  }

  console.log("\n=== new #1: one event with the right body and header ===");
  {
    const stub = await h.startMockServer(() => ({ status: 202, body: { status: "scheduled", notification_id: 1 } }));
    const app = await start({ url: `${stub.url}/api/notifications/events` });
    const first = await play(app, "Ann", 100);
    await settle();
    check("empty board: the first-ever entry does not fire", stub.requests.length === 0, `${stub.requests.length}`);
    check("empty board: upload 200", first.status === 200);

    const top = await play(app, "Ben-GB-2", 250);
    check("new #1: upload 200", top.status === 200, `${top.status} ${top.body}`);
    await h.waitFor(() => stub.requests.length >= 1, 2000);
    await settle();
    const sent = events(stub);
    check("new #1: exactly one event", sent.length === 1, `${sent.length}`);
    const e = sent[0] || { json: {}, headers: {} };
    check("event: POST to the events path", e.method === "POST" && e.url === "/api/notifications/events", `${e.method} ${e.url}`);
    check("event: Bearer secret header", e.headers.authorization === `Bearer ${SECRET}`);
    check("event: JSON content type", String(e.headers["content-type"]).startsWith("application/json"));
    check("event: type high_score_approved", e.json.type === "high_score_approved", e.json.type);
    const entry = await app.service.storage.getEntry(KEY, top.guid);
    check(
      "event: data {player_name, score, entry_id}",
      e.json.data && e.json.data.player_name === "Ben-GB-2" && e.json.data.score === 250 && e.json.data.entry_id === entry.id &&
        Object.keys(e.json.data).sort().join(",") === "entry_id,player_name,score",
      JSON.stringify(e.json.data)
    );
    const guidRef = app.service.maskUserGuid(KEY, top.guid);
    check(
      "event: idempotency_key leaderboard:highscore:<publicKey>:<guidRef>:<score>",
      e.json.idempotency_key === `leaderboard:highscore:${KEY}:${guidRef}:250`,
      e.json.idempotency_key
    );
    check("event: the real GUID is never sent", !e.body.includes(top.guid));

    console.log("\n=== not a new top: nothing ===");
    stub.requests.length = 0;
    await play(app, "Cy", 200); // below the top
    await play(app, "Dee", 250); // ties the top: does not strictly beat it
    await settle();
    check("lower score and a tie: no event", stub.requests.length === 0, `${stub.requests.length}`);

    console.log("\n=== the #1 improves their own score: fires; a lower re-upload does not ===");
    {
      // Same player (same entry GUID) uploading again: the game re-uses the
      // entry GUID, so register it as a fresh session.
      app.service.storage.sessions.set(top.guid, { guid: top.guid, issuedAt: Math.floor(Date.now() / 1000), usedAt: null });
      const better = await upload(app.base, { guid: top.guid, name: "Ben-GB-3", score: 300 });
      await h.waitFor(() => stub.requests.length >= 1, 2000);
      await settle();
      check("own #1 improved: 200 and one event", better.status === 200 && stub.requests.length === 1, `${stub.requests.length}`);
      stub.requests.length = 0;
      app.service.storage.sessions.set(top.guid, { guid: top.guid, issuedAt: Math.floor(Date.now() / 1000), usedAt: null });
      await upload(app.base, { guid: top.guid, name: "Ben-GB-1", score: 150 });
      await settle();
      check("lower re-upload by the #1: no event", stub.requests.length === 0, `${stub.requests.length}`);
    }

    console.log("\n=== log mode let it through: nothing ===");
    stub.requests.length = 0;
    const unknown = await upload(app.base, { guid: "made-up-guid", name: "Eve", score: 9999 });
    const used = await authorize(app.base);
    await upload(app.base, { guid: used, name: "Fay", score: 50 });
    await settle();
    const reused = await upload(app.base, { guid: used, name: "Fay", score: 99999 });
    await settle();
    check("unknown GUID (log mode, would refuse): stored, 200", unknown.status === 200);
    check("re-used GUID (log mode, would refuse): stored, 200", reused.status === 200);
    check("log-mode-flagged uploads: no event even though they top the board", stub.requests.length === 0, `${stub.requests.length}`);
    check("log mode: the would-refuse lines were logged", logs.some((l) => l.includes("would refuse")));

    console.log("\n=== admin edits: nothing ===");
    stub.requests.length = 0;
    const adminPost = await h.request(app.base, {
      method: "POST",
      path: "/admin/api/entries",
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
      body: { publicKey: KEY, userGuid: "admin-made", username: "Staff", score: 5000000 }
    });
    const adminPut = await h.request(app.base, {
      method: "PUT",
      path: `/admin/api/entries/${KEY}/${encodeURIComponent(top.guid)}`,
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
      body: { username: "Ben", score: 6000000 }
    });
    await settle();
    check("admin create/edit: accepted", adminPost.status < 300 && adminPut.status < 300, `${adminPost.status} ${adminPut.status}`);
    check("admin create/edit of a new #1: no event", stub.requests.length === 0, `${stub.requests.length}`);

    console.log("\n=== other boards ===");
    await play(app, "Gus", 10, OTHER_KEY);
    await play(app, "Hal", 20, OTHER_KEY);
    await settle();
    check("a board that is not the game's key: no event", stub.requests.length === 0, `${stub.requests.length}`);
    await app.close();
    await stub.close();
  }

  console.log("\n=== ascending board (lower wins) ===");
  {
    const stub = await h.startMockServer(() => ({ status: 202, body: {} }));
    const app = await start({ url: stub.url, ascending: [KEY] });
    await play(app, "Ann", 100);
    await play(app, "Ben", 120);
    await settle();
    check("ascending: a higher score is not a new top", stub.requests.length === 0, `${stub.requests.length}`);
    await play(app, "Cy", 90);
    await h.waitFor(() => stub.requests.length >= 1, 2000);
    check("ascending: a lower score is a new top", stub.requests.length === 1 && events(stub)[0].json.data.score === 90);
    await app.close();
    await stub.close();
  }

  console.log("\n=== upload checks off: an accepted new #1 fires ===");
  {
    const stub = await h.startMockServer(() => ({ status: 202, body: {} }));
    const app = await start({ url: stub.url, mode: "off" });
    await upload(app.base, { guid: "g1", name: "Ann", score: 10 });
    await upload(app.base, { guid: "g2", name: "Ben", score: 20 });
    await h.waitFor(() => stub.requests.length >= 1, 2000);
    check("mode off: one event", stub.requests.length === 1, `${stub.requests.length}`);
    await app.close();
    await stub.close();
  }

  console.log("\n=== 5xx: retried with the same key; 4xx: not retried ===");
  {
    const stub = await h.startMockServer((_req, i) => (i < 2 ? { status: 503, body: {} } : { status: 202, body: {} }));
    const app = await start({ url: stub.url });
    await play(app, "Ann", 1);
    const res = await play(app, "Ben", 2);
    check("5xx: upload 200", res.status === 200);
    await h.waitFor(() => stub.requests.length >= 3, 3000);
    await h.sleep(300);
    const sent = events(stub);
    check("5xx: 3 tries in total (503, 503, 202)", sent.length === 3, `${sent.length}`);
    check("5xx: every try has the same idempotency_key and body", sent.every((r) => r.body === sent[0].body));
    check("5xx: delivered logged", logs.some((l) => l.includes("[notify] high_score_approved: delivered")));
    await app.close();
    await stub.close();

    const stub2 = await h.startMockServer(() => ({ status: 500, body: {} }));
    const app2 = await start({ url: stub2.url });
    await play(app2, "Ann", 1);
    await play(app2, "Ben", 2);
    await h.waitFor(() => stub2.requests.length >= 3, 3000);
    await h.sleep(400);
    check("5xx forever: gives up after 3 tries", stub2.requests.length === 3, `${stub2.requests.length}`);
    await app2.close();
    await stub2.close();

    for (const status of [400, 401, 403]) {
      const stub3 = await h.startMockServer(() => ({ status, body: {} }));
      const app3 = await start({ url: stub3.url });
      await play(app3, "Ann", 1);
      await play(app3, "Ben", 2);
      await h.waitFor(() => stub3.requests.length >= 1, 2000);
      await h.sleep(400);
      check(`HTTP ${status}: one try, no retry`, stub3.requests.length === 1, `${stub3.requests.length}`);
      await app3.close();
      await stub3.close();
    }
  }

  console.log("\n=== support site down or hung: upload still fast and OK ===");
  {
    const dead = await h.startMockServer(() => ({ status: 202 }));
    const deadUrl = dead.url;
    await dead.close(); // nothing listens on this port now
    const app = await start({ url: deadUrl });
    await play(app, "Ann", 1);
    const res = await play(app, "Ben", 2);
    check("down: upload 200", res.status === 200, `${res.status}`);
    check("down: upload answered fast (<300 ms)", res.ms < 300, `${res.ms} ms`);
    await h.sleep(400);
    check("down: gave up after 3 tries, logged", logs.some((l) => l.includes("gave up after 3 tries")));
    const health = await h.request(app.base, { path: "/health" });
    check("down: service still healthy", health.status === 200);
    await app.close();

    const hung = await h.startMockServer(() => "hang");
    const app2 = await start({ url: hung.url, timeoutMs: 200 });
    await play(app2, "Ann", 1);
    const res2 = await play(app2, "Ben", 2);
    check("hung: upload 200", res2.status === 200);
    check("hung: upload answered fast (<300 ms)", res2.ms < 300, `${res2.ms} ms`);
    await h.waitFor(() => hung.requests.length >= 3, 3000);
    await h.sleep(300);
    check("hung: timed out and retried (3 tries)", hung.requests.length === 3, `${hung.requests.length}`);
    check("hung: timeout logged", logs.some((l) => l.includes("timeout after 200 ms")));
    await app2.close();
    await hung.close();
  }

  console.log("\n=== the secret is never logged; defaults ===");
  check("no log line contains the secret", !logs.some((l) => l.includes(SECRET)));
  check("default URL per contract", new SupportNotifier({}).url === DEFAULT_URL &&
    DEFAULT_URL === "https://support.thegoldstandard.com/api/notifications/events");
  check("default timeout 5 s", new SupportNotifier({}).timeoutMs === 5000);
  const on = new SupportNotifier({ secret: SECRET, url: "https://support.example.test/api/notifications/events" });
  check("describe() on: origin only, no secret", on.describe() === "notifications: on (events to https://support.example.test)");

  h.finish();
}

main().catch((error) => {
  capture(String(error && error.stack));
  process.stdout.write(`${error && error.stack}\n`);
  process.exit(1);
});
