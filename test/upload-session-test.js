// Upload checks: score range (INTEGER overflow), and the /authorize GUID as a
// single-use upload session (off / log / enforce, min play time, TTL, score
// per second). Needs a throwaway Postgres in TEST_DATABASE_URL.
// Run: TEST_DATABASE_URL=postgres://user@localhost:5432/throwaway node test/upload-session-test.js

const { PostgresStorage } = require("../src/storage/postgres");
const { LeaderboardService } = require("../src/service");
const { createApp } = require("../src/app");
const h = require("./helpers");

const url = h.requireTestDatabase();
const check = h.check;
const KEY = "536aec42d31fa4ec5c486c219f9821f6a145562fcb069c6f19f40786fdc38678";

const warns = [];
console.warn = (...args) => warns.push(args.join(" "));

async function start(storage, extra) {
  const config = {
    corsOrigin: "*",
    allowedPublicKeys: [],
    maxUsernameLength: 127,
    maxExtraLength: 100,
    observe: { enabled: false },
    ...extra
  };
  const service = new LeaderboardService(storage, config);
  const app = await h.listen(createApp(service, config));
  return { ...app, service };
}

const upload = (base, userGuid, score = 1234) => h.request(base, {
  method: "POST",
  path: "/entry/upload",
  body: { publicKey: KEY, userGuid, username: `Dana-GB-${score / 100}`, score: String(score), extra: " " }
});
const authorize = async (base) => (await h.request(base, { path: "/authorize" })).body.trim();
const backdate = (guid, seconds) => h.adminQuery("UPDATE upload_sessions SET issued_at = issued_at - $2 WHERE guid = $1", [guid, seconds]);
const sessionRow = async (guid) => (await h.adminQuery("SELECT * FROM upload_sessions WHERE guid = $1", [guid])).rows[0];

async function main() {
  await h.dropTables([...h.ALL_TABLES, "upload_sessions"]);
  const storage = new PostgresStorage(url, { ssl: false });
  await storage.initialize();

  console.log("\n=== score range ===");
  {
    const app = await start(storage, { uploadSession: { mode: "off" } });
    const big = await upload(app.base, "g-big", 2147483648);
    check("score 2147483648 -> 400 (was a 500 from Postgres)", big.status === 400 && big.body === "score is out of range.", `${big.status} ${big.body}`);
    const max = await upload(app.base, "g-max", 2147483647);
    check("score 2147483647 -> 200", max.status === 200, `${max.status} ${max.body}`);
    const low = await upload(app.base, "g-low", -2147483649);
    check("score below INTEGER min -> 400", low.status === 400, `${low.status}`);
    await app.close();

    const capped = await start(storage, { uploadSession: { mode: "off" }, maxScore: 100000 });
    check("MAX_SCORE=100000: 100000 -> 200", (await upload(capped.base, "g-c1", 100000)).status === 200);
    check("MAX_SCORE=100000: 100001 -> 400", (await upload(capped.base, "g-c2", 100001)).status === 400);
    await capped.close();
  }

  console.log("\n=== mode off: today's behaviour, nothing recorded ===");
  {
    const app = await start(storage, { uploadSession: { mode: "off" } });
    const guid = await authorize(app.base);
    const rows = await h.adminQuery("SELECT count(*)::int AS n FROM upload_sessions");
    check("off: /authorize records nothing", rows.rows[0].n === 0, JSON.stringify(rows.rows));
    check("off: upload with a made-up GUID -> 200", (await upload(app.base, "made-up-1")).status === 200);
    check("off: upload with an issued GUID -> 200", (await upload(app.base, guid)).status === 200);
    await app.close();
  }

  console.log("\n=== mode log (the default): records and logs, never refuses ===");
  {
    warns.length = 0;
    const app = await start(storage, { uploadSession: { mode: "log", ttlSeconds: 3600, minPlaySeconds: 0 } });
    const guid = await authorize(app.base);
    const row = await sessionRow(guid);
    check("log: /authorize records the GUID", row && row.used_at === null, JSON.stringify(row));
    check("log: upload with that GUID -> 200, no warning", (await upload(app.base, guid)).status === 200 && warns.length === 0, JSON.stringify(warns));
    await h.waitFor(async () => (await sessionRow(guid)).used_at !== null);
    check("log: GUID marked used after the upload", (await sessionRow(guid)).used_at !== null);
    const again = await upload(app.base, guid);
    check("log: second upload with it -> still 200", again.status === 200);
    check("log: ...and logged as reason=used", warns.some((l) => /would refuse.*reason=used/.test(l)), JSON.stringify(warns));
    const unknown = await upload(app.base, "00000000-0000-4000-8000-000000000000");
    check("log: unknown GUID -> 200 and logged reason=unknown", unknown.status === 200 && warns.some((l) => /reason=unknown/.test(l)));
    check("log lines carry the masked guidRef, never the GUID", warns.every((l) => !l.includes(guid) && /guidRef=[0-9a-f]{32}/.test(l)), JSON.stringify(warns));
    await app.close();
  }

  console.log("\n=== mode enforce ===");
  {
    warns.length = 0;
    const app = await start(storage, { uploadSession: { mode: "enforce", ttlSeconds: 3600, minPlaySeconds: 5, maxScorePerSecond: 10 } });
    const unknown = await upload(app.base, "11111111-1111-4111-8111-111111111111", 10);
    check("enforce: unknown GUID -> 403 Upload refused.", unknown.status === 403 && unknown.body === "Upload refused.", `${unknown.status} ${unknown.body}`);

    const fast = await authorize(app.base);
    const tooFast = await upload(app.base, fast, 10);
    check("enforce: upload 0 s after /authorize (min 5 s) -> 403", tooFast.status === 403 && warns.some((l) => /reason=too_fast/.test(l)));
    check("enforce: a refused upload does NOT use up the GUID", (await sessionRow(fast)).used_at === null);
    await backdate(fast, 10);
    const ok = await upload(app.base, fast, 50);
    check("enforce: same GUID after 10 s, score 50 (<= 10/s) -> 200", ok.status === 200, `${ok.status} ${ok.body}`);
    const reuse = await upload(app.base, fast, 50);
    check("enforce: second upload with the same GUID -> 403 (single use)", reuse.status === 403 && warns.some((l) => /reason=used/.test(l)));

    const greedy = await authorize(app.base);
    await backdate(greedy, 10);
    const tooHigh = await upload(app.base, greedy, 500);
    check("enforce: score 500 after 10 s at max 10/s -> 403 implausible_score", tooHigh.status === 403 && warns.some((l) => /reason=implausible_score/.test(l)));

    const old = await authorize(app.base);
    await backdate(old, 7200);
    const expired = await upload(app.base, old, 10);
    check("enforce: GUID older than the TTL -> 403 expired", expired.status === 403 && warns.some((l) => /reason=expired/.test(l)));

    const race = await authorize(app.base);
    await backdate(race, 10);
    const both = await Promise.all([upload(app.base, race, 20), upload(app.base, race, 30)]);
    const codes = both.map((r) => r.status).sort().join(",");
    check("enforce: two uploads at once with one GUID -> exactly one 200", codes === "200,403", codes);

    // The entry store fails after the GUID was claimed: the claim is undone.
    const flaky = await authorize(app.base);
    await backdate(flaky, 10);
    const realUpsert = storage.upsertEntry.bind(storage);
    let failOnce = true;
    storage.upsertEntry = async (entry) => {
      if (failOnce) {
        failOnce = false;
        throw new Error("simulated write failure");
      }
      return realUpsert(entry);
    };
    const errors = [];
    const originalError = console.error;
    console.error = (...args) => errors.push(args.map(String).join(" "));
    const failed = await upload(app.base, flaky, 10);
    console.error = originalError;
    check("enforce: entry write fails -> 500", failed.status === 500, `${failed.status}`);
    await h.waitFor(async () => (await sessionRow(flaky)).used_at === null);
    const retry = await upload(app.base, flaky, 10);
    check("enforce: ...and the player's retry with the same GUID -> 200", retry.status === 200, `${retry.status} ${retry.body}`);
    storage.upsertEntry = realUpsert;

    // The session table is gone: enforce fails closed with 503, log mode carries on.
    await h.adminQuery("ALTER TABLE upload_sessions RENAME TO upload_sessions_hidden");
    const quiet = [];
    console.error = (...args) => quiet.push(args.map(String).join(" "));
    const auth503 = await h.request(app.base, { path: "/authorize" });
    check("enforce: /authorize -> 503 when the GUID cannot be recorded", auth503.status === 503, `${auth503.status}`);
    const logApp = await start(storage, { uploadSession: { mode: "log" } });
    const auth200 = await h.request(logApp.base, { path: "/authorize" });
    check("log: /authorize still 200 when it cannot be recorded", auth200.status === 200);
    const up200 = await upload(logApp.base, auth200.body.trim(), 10);
    check("log: upload still 200 when the lookup fails", up200.status === 200, `${up200.status}`);
    console.error = originalError;
    check("failures logged at most once a minute per service (2 services here)", quiet.filter((l) => /\[upload-session\]/.test(l)).length === 2, JSON.stringify(quiet));
    await h.adminQuery("ALTER TABLE upload_sessions_hidden RENAME TO upload_sessions");
    await logApp.close();
    await app.close();
  }

  console.log("\n=== storage without upload sessions (SQLite) ===");
  {
    const { FakeStorage } = require("./fake-storage");
    const service = new LeaderboardService(new FakeStorage(), { uploadSession: { mode: "enforce" }, allowedPublicKeys: [], observe: { enabled: false } });
    check("mode falls back to off, and says why", service.uploadSession.mode === "off" && /Postgres only/.test(service.describeUploadSession()), service.describeUploadSession());
  }

  console.log("\n=== prune ===");
  {
    const g = "prune-me";
    await h.adminQuery("INSERT INTO upload_sessions (guid, issued_at) VALUES ($1, 1)", [g]);
    await storage.pruneUploadSessions(1000);
    check("pruneUploadSessions removes old rows", !(await sessionRow(g)));
  }

  await storage.close();
  h.finish();
}

main().catch((error) => {
  console.log(error);
  process.exit(1);
});
