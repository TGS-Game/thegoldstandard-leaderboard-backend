// Postgres pool hardening: a dropped connection must not crash the process,
// an unreachable database must fail fast (so /health answers 503 quickly),
// and a stuck statement must be cut off.
//
// Run: TEST_DATABASE_URL=postgres://user@localhost:5432/throwaway node test/pg-pool-test.js

const net = require("net");
const { PostgresStorage } = require("../src/storage/postgres");
const { LeaderboardService } = require("../src/service");
const { createApp } = require("../src/app");
const h = require("./helpers");

const url = h.requireTestDatabase();

async function main() {
  await h.dropTables(h.ALL_TABLES);

  const errors = [];
  const originalError = console.error;
  console.error = (...args) => errors.push(args.map(String).join(" "));

  console.log("\n=== pool on a working database ===");
  const storage = new PostgresStorage(url, { ssl: false, connectTimeoutMs: 1000, statementTimeoutMs: 500 });
  await storage.initialize();
  check("ping works", await storage.ping().then(() => true, () => false));
  check("pool has an 'error' listener", storage.pool.listenerCount("error") >= 1);

  console.log("\n=== idle connections killed by the server ===");
  // Make sure there are idle clients in the pool, then kill them server-side.
  await Promise.all([storage.ping(), storage.ping(), storage.ping()]);
  const killed = await h.adminQuery(
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid() AND state = 'idle'"
  );
  check("killed at least one idle backend", killed.rowCount >= 1, `rowCount=${killed.rowCount}`);
  await h.sleep(300);
  check("process still alive and logged the pool error", errors.some((l) => /Postgres idle client error/.test(l)), JSON.stringify(errors));
  check("next ping reconnects and works", await storage.ping().then(() => true, (e) => e.message));

  console.log("\n=== statement timeout ===");
  const slowStart = Date.now();
  const slow = await storage.pool.query("SELECT pg_sleep(3)").then(() => "finished", (e) => e.message);
  const slowMs = Date.now() - slowStart;
  check("a 3 s statement is cancelled by statement_timeout", /statement timeout|canceling/i.test(slow) && slowMs < 2500, `${slow} after ${slowMs}ms`);
  await storage.close();

  console.log("\n=== database that accepts TCP but never answers ===");
  const blackHole = net.createServer(() => {});
  await new Promise((r) => blackHole.listen(0, "127.0.0.1", r));
  const deadUrl = `postgres://nobody@127.0.0.1:${blackHole.address().port}/nothing`;
  const dead = new PostgresStorage(deadUrl, { ssl: false, connectTimeoutMs: 700, statementTimeoutMs: 500 });
  const service = new LeaderboardService(dead, { allowedPublicKeys: [], maxUsernameLength: 127, maxExtraLength: 100, observe: { enabled: false } });
  const app = h.listen(createApp(service, { corsOrigin: "*" }));
  const { base, close } = await app;
  const start = Date.now();
  const health = await h.request(base, { path: "/health" });
  const healthMs = Date.now() - start;
  check("/health answers 503 when Postgres hangs", health.status === 503, `status=${health.status}`);
  check("/health answers within the connect timeout (< 2 s)", healthMs < 2000, `${healthMs}ms`);
  await close();
  await dead.close().catch(() => {});
  blackHole.close();

  console.error = originalError;
  h.finish();
}

const check = h.check;
main().catch((error) => {
  console.error(error);
  process.exit(1);
});
