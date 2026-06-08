// Headless-Chrome UI test for the redesigned /admin panel. Boots a local HTTPS
// server (fake in-memory storage seeded with 2 keys, entries, profiles), logs in
// with the password, and drives the real page to verify:
//   - auto-load on open (entries appear with NO clicks)
//   - no horizontal scroll on desktop
//   - title "TGS Leaderboard"; old navy banner text gone
//   - several keys -> header dropdown; switching it reloads entries
//   - editor is a row across the top (fields share one row)
//   - create / edit / delete entries still work
//   - Player Profiles auto-loads on first tab open
//
// Run: node test/admin-ui-test.cjs   (cert must exist in test/tmp)

const fs = require("fs");
const path = require("path");
const https = require("https");
const http = require("http");
const { spawn } = require("child_process");

const { createApp } = require("../src/app");
const { LeaderboardService } = require("../src/service");
const { FakeStorage } = require("./fake-storage");

const CHROME = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const PASSWORD = "admin-ui-test-pw";
const CDP_PORT = 9455;
const profileDir = path.join(__dirname, "tmp", "admin-ui-chrome-profile");
const tls = {
  key: fs.readFileSync(path.join(__dirname, "tmp", "key.pem")),
  cert: fs.readFileSync(path.join(__dirname, "tmp", "cert.pem")),
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let pass = 0, fail = 0;
const chk = (n, c, d) => { c ? pass++ : fail++; console.log(`  ${c ? "PASS" : "FAIL"}  ${n}${!c && d ? ` -> ${d}` : ""}`); };

function seedStorage() {
  const s = new FakeStorage();
  const e = (publicKey, userGuid, username, score, t) => ({ id: `${publicKey}-${userGuid}`, publicKey, userGuid, username, score, extra: "x", createdAt: t, updatedAt: t });
  s.entries.set("key-alpha guid-a1", e("key-alpha", "guid-a1", "Alice", 100, 1000));
  s.entries.set("key-alpha guid-a2", e("key-alpha", "guid-a2", "Bob", 250, 1001));
  s.entries.set("key-bravo guid-b1", e("key-bravo", "guid-b1", "Cara", 999, 1002));
  s.profiles.set("p1@example.com", { id: "p1", name: "Pat", email: "p1@example.com", country: "US", consentAccepted: true, userGuid: "guid-a1", createdAt: 1000, updatedAt: 1000 });
  s.profiles.set("p2@example.com", { id: "p2", name: "Sam", email: "p2@example.com", country: "UK", consentAccepted: false, userGuid: "", createdAt: 1001, updatedAt: 1001 });
  return s;
}

function startServer() {
  const config = {
    port: 0, corsOrigin: "*", databaseUrl: "", allowedPublicKeys: [],
    adminToken: "", adminPassword: PASSWORD, sessionSecret: "ui-test-sess",
    sessionTtlSeconds: 43200, ssoSecret: "", ssoAudience: "leaderboard", hubOrigin: "",
    maxUsernameLength: 127, maxExtraLength: 100,
  };
  const app = createApp(new LeaderboardService(seedStorage(), config), config);
  return new Promise((resolve) => {
    const server = https.createServer(tls, app);
    server.listen(0, "127.0.0.1", () => resolve({ server, base: `https://127.0.0.1:${server.address().port}` }));
  });
}

async function cdp(wsUrl) {
  const ws = new WebSocket(wsUrl);
  await new Promise((res, rej) => { ws.addEventListener("open", res, { once: true }); ws.addEventListener("error", rej, { once: true }); });
  let nextId = 1; const pending = new Map(); const handlers = [];
  ws.addEventListener("message", (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) { const p = pending.get(m.id); pending.delete(m.id); m.error ? p.reject(new Error(JSON.stringify(m.error))) : p.resolve(m.result); }
    else if (m.method) handlers.forEach((h) => h(m));
  });
  const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const id = nextId++; const pl = { id, method, params }; if (sessionId) pl.sessionId = sessionId;
    pending.set(id, { resolve, reject }); ws.send(JSON.stringify(pl));
  });
  return { send, on: (h) => handlers.push(h), close: () => ws.close() };
}

async function main() {
  const { server, base } = await startServer();
  const chrome = spawn(CHROME, [
    "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
    `--remote-debugging-port=${CDP_PORT}`, `--user-data-dir=${profileDir}`, "--ignore-certificate-errors",
    "about:blank",
  ], { stdio: "ignore" });

  try {
    let version = null;
    for (let i = 0; i < 40; i++) {
      try { version = await new Promise((res, rej) => { http.get(`http://127.0.0.1:${CDP_PORT}/json/version`, (r) => { let d = ""; r.on("data", c => d += c); r.on("end", () => res(JSON.parse(d))); }).on("error", rej); }); break; } catch { await sleep(250); }
    }
    if (!version) throw new Error("Chrome CDP never came up");
    const client = await cdp(version.webSocketDebuggerUrl);
    const { targetId } = await client.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await client.send("Target.attachToTarget", { targetId, flatten: true });
    const S = sessionId;
    await client.send("Page.enable", {}, S);
    await client.send("Runtime.enable", {}, S);
    await client.send("Security.enable", {}, S);
    await client.send("Security.setIgnoreCertificateErrors", { ignore: true }, S);
    await client.send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false }, S);
    // Auto-accept the delete confirm() dialog.
    client.on((m) => { if (m.method === "Page.javascriptDialogOpening") client.send("Page.handleJavaScriptDialog", { accept: true }, S); });

    const evalJs = async (expr) => (await client.send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true }, S)).result.value;
    const waitFor = async (expr, ms = 5000) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (await evalJs(expr)) return true; await sleep(150); } return false; };

    // --- Log in ---
    await client.send("Page.navigate", { url: `${base}/admin/login` }, S);
    await sleep(1200);
    await evalJs(`(()=>{const i=document.querySelector('input[name=password]');i.value=${JSON.stringify(PASSWORD)};document.querySelector('form').submit();return 1;})()`);
    await sleep(1800);

    const onAdmin = await evalJs("location.pathname === '/admin'");
    chk("logged in, on /admin", onAdmin, await evalJs("location.pathname"));

    // --- Auto-load + header + layout ---
    chk("title is 'TGS Leaderboard'", await evalJs("!!document.querySelector('h1') && document.querySelector('h1').textContent.trim() === 'TGS Leaderboard'"), await evalJs("document.querySelector('h1') && document.querySelector('h1').textContent"));
    chk("old banner text removed", !(await evalJs("document.body.innerText.includes('admin workspace')")));
    chk("no old left controls (publicKey input / Load Keys)", await evalJs("!document.getElementById('publicKey') && !document.getElementById('loadKeys') && !document.getElementById('knownKeys')"));

    const rowsLoaded = await waitFor("document.querySelectorAll('#entriesBody tr').length >= 2 && !document.querySelector('#entriesBody td.small')");
    chk("entries AUTO-LOADED on open (no clicks)", rowsLoaded, `rows=${await evalJs("document.querySelectorAll('#entriesBody tr').length")}`);
    chk("auto-loaded the first key (key-alpha): Alice present", await evalJs("document.querySelector('#entriesBody').innerText.includes('Alice')"));

    chk("several keys -> header dropdown present", await evalJs("!!document.getElementById('keySelect')"));
    chk("dropdown has 2 keys, value=key-alpha", await evalJs("(()=>{const s=document.getElementById('keySelect');return s && s.options.length===2 && s.value==='key-alpha';})()"));

    const noHScroll = await evalJs("document.documentElement.scrollWidth <= document.documentElement.clientWidth");
    chk("NO horizontal scroll on desktop (1280px)", noHScroll, `scrollW=${await evalJs("document.documentElement.scrollWidth")} clientW=${await evalJs("document.documentElement.clientWidth")}`);

    // Editor across the top: GUID and Score inputs share the same row (similar y).
    const sameRow = await evalJs("(()=>{const a=document.getElementById('userGuid').getBoundingClientRect();const b=document.getElementById('score').getBoundingClientRect();return Math.abs(a.top-b.top)<8;})()");
    chk("editor fields are a row across the top", sameRow);

    // Log out lives in the header (top-right), in line with the title, no footer.
    chk("logout is in the header, no footer", await evalJs("!!document.querySelector('.page-head #logout') && !document.querySelector('.page-foot')"));
    chk("logout sits above the editor card (top of page)", await evalJs("document.getElementById('logout').getBoundingClientRect().bottom <= document.querySelector('.card').getBoundingClientRect().top"));
    chk("logout in line with the title (desktop)", await evalJs("(()=>{const l=document.getElementById('logout').getBoundingClientRect();const h=document.querySelector('h1').getBoundingClientRect();return Math.abs(l.top-h.top)<80;})()"));

    // --- Create ---
    await evalJs(`(()=>{document.getElementById('userGuid').value='guid-a3';document.getElementById('username').value='Dave';document.getElementById('score').value='500';document.getElementById('extra').value='x';document.getElementById('saveEntry').click();return 1;})()`);
    const created = await waitFor("document.querySelector('#entriesBody').innerText.includes('Dave')");
    chk("CREATE entry (Dave) appears in table", created, `rows=${await evalJs("document.querySelectorAll('#entriesBody tr').length")}`);

    // --- Edit (click the Dave row to load it, change score, save) ---
    await evalJs(`(()=>{const rows=[...document.querySelectorAll('#entriesBody tr')];const r=rows.find(x=>x.innerText.includes('guid-a3'));r.click();return 1;})()`);
    await sleep(300);
    chk("clicking a row fills the editor", await evalJs("document.getElementById('userGuid').value === 'guid-a3'"));
    await evalJs(`(()=>{document.getElementById('score').value='600';document.getElementById('saveEntry').click();return 1;})()`);
    const edited = await waitFor("(()=>{const rows=[...document.querySelectorAll('#entriesBody tr')];const r=rows.find(x=>x.innerText.includes('guid-a3'));return r && r.innerText.includes('600');})()");
    chk("EDIT entry (Dave score -> 600)", edited);

    // --- Delete (Dave still in editor) ---
    await evalJs(`(()=>{const rows=[...document.querySelectorAll('#entriesBody tr')];const r=rows.find(x=>x.innerText.includes('guid-a3'));r.click();return 1;})()`);
    await sleep(200);
    await evalJs("document.getElementById('deleteEntry').click()");
    const deleted = await waitFor("!document.querySelector('#entriesBody').innerText.includes('guid-a3')");
    chk("DELETE entry (Dave) removed from table", deleted);

    // --- Profiles auto-load on first tab open ---
    await evalJs("document.getElementById('tabProfiles').click()");
    const profilesLoaded = await waitFor("document.querySelectorAll('#profilesBody tr').length >= 2 && !document.querySelector('#profilesBody td.small')");
    chk("Player Profiles AUTO-LOAD on first open (no Refresh click)", profilesLoaded, `rows=${await evalJs("document.querySelectorAll('#profilesBody tr').length")}`);

    // --- Key switch reloads entries for the other key ---
    await evalJs("document.getElementById('tabEntries').click()");
    await evalJs("(()=>{const s=document.getElementById('keySelect');s.value='key-bravo';s.dispatchEvent(new Event('change'));return 1;})()");
    const switched = await waitFor("document.querySelector('#entriesBody').innerText.includes('Cara') && !document.querySelector('#entriesBody').innerText.includes('Alice')");
    chk("switching key dropdown reloads entries (Cara on key-bravo)", switched);

    // --- Mobile usability: narrow viewport still loads, no page-level h-scroll ---
    await client.send("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 2, mobile: true }, S);
    await client.send("Page.navigate", { url: `${base}/admin` }, S);
    await waitFor("document.querySelectorAll('#entriesBody tr').length >= 1 && !document.querySelector('#entriesBody td.small')");
    const mobileOk = await evalJs("document.documentElement.scrollWidth <= document.documentElement.clientWidth + 2");
    chk("mobile (390px): no page-level horizontal scroll, entries load", mobileOk, `scrollW=${await evalJs("document.documentElement.scrollWidth")} clientW=${await evalJs("document.documentElement.clientWidth")}`);
    // Logout still in the header and not overlapping the title or key field on mobile.
    const mobileLogout = await evalJs("(()=>{const l=document.getElementById('logout').getBoundingClientRect();const h=document.querySelector('h1').getBoundingClientRect();const k=document.getElementById('keyControl').getBoundingClientRect();const noOverlap=(a,b)=>(a.right<=b.left||a.left>=b.right||a.bottom<=b.top||a.top>=b.bottom);return !!document.querySelector('.page-head #logout') && noOverlap(l,h) && noOverlap(l,k);})()");
    chk("mobile: logout in header, no overlap with title or key", mobileLogout);

    client.close();
  } finally {
    chrome.kill();
    server.close();
  }

  console.log(`\n  ADMIN UI RESULTS  PASS: ${pass}  FAIL: ${fail}`);
  process.exit(fail > 0 ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
