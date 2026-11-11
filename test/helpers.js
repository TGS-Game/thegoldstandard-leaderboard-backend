// Shared helpers for the Postgres-backed tests (test/*-test.js). These need a
// throwaway local Postgres: set TEST_DATABASE_URL, e.g.
//   postgres://lbtest@localhost:55491/lbtest
// Every test drops and recreates its own tables, so never point this at a
// database that matters.

const http = require("http");
const { Client } = require("pg");

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL || "";

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

function finish() {
  console.log("\n================ RESULTS ================");
  console.log(`  PASS: ${pass}   FAIL: ${fail}`);
  if (fail > 0) {
    console.log("\nFailures:");
    for (const line of failures) {
      console.log(`  - ${line}`);
    }
  } else {
    console.log("  ALL GREEN");
  }
  process.exit(fail > 0 ? 1 : 0);
}

function requireTestDatabase() {
  if (!TEST_DATABASE_URL) {
    console.log("SKIP: set TEST_DATABASE_URL to a throwaway Postgres database to run this test.");
    process.exit(0);
  }
  return TEST_DATABASE_URL;
}

// Runs SQL on a separate connection (not the pool under test).
async function adminQuery(sql, params) {
  const client = new Client({ connectionString: TEST_DATABASE_URL });
  await client.connect();
  try {
    return await client.query(sql, params);
  } finally {
    await client.end();
  }
}

async function dropTables(names) {
  for (const name of names) {
    await adminQuery(`DROP TABLE IF EXISTS ${name} CASCADE`);
  }
}

const ALL_TABLES = [
  "entries",
  "player_profiles",
  "entry_history",
  "issued_guids",
  "security_observations",
  "traffic_hourly"
];

// Starts a plain HTTP server on a free port that records every request and
// answers with whatever respond(req, body, index) returns:
// { status, body, delayMs } or the string "hang" (never answers).
function startMockServer(respond) {
  const requests = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => {
      const record = { method: req.method, url: req.url, headers: req.headers, body, at: Date.now() };
      requests.push(record);
      const answer = respond ? respond(record, requests.length - 1) : { status: 200, body: "ok" };
      if (answer === "hang") {
        return;
      }
      const send = () => {
        res.writeHead(answer.status || 200, { "Content-Type": "application/json" });
        res.end(typeof answer.body === "string" ? answer.body : JSON.stringify(answer.body || {}));
      };
      if (answer.delayMs) {
        setTimeout(send, answer.delayMs);
      } else {
        send();
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ server, requests, url: `http://127.0.0.1:${port}`, close: () => new Promise((r) => { server.closeAllConnections(); server.close(r); }) });
    });
  });
}

// HTTP request helper for the app under test (plain HTTP).
function request(base, { method = "GET", path = "/", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, base);
    const allHeaders = { ...headers };
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
    const req = http.request(url, { method, headers: allHeaders }, (res) => {
      let data = "";
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on("error", reject);
    if (payload !== undefined) {
      req.write(payload);
    }
    req.end();
  });
}

function listen(app) {
  return new Promise((resolve) => {
    const server = http.createServer(app);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ server, base: `http://127.0.0.1:${port}`, close: () => new Promise((r) => { server.closeAllConnections(); server.close(r); }) });
    });
  });
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(predicate, timeoutMs = 5000, stepMs = 25) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) {
      return true;
    }
    await sleep(stepMs);
  }
  return false;
}

module.exports = {
  TEST_DATABASE_URL,
  ALL_TABLES,
  check,
  finish,
  requireTestDatabase,
  adminQuery,
  dropTables,
  startMockServer,
  request,
  listen,
  sleep,
  waitFor
};
