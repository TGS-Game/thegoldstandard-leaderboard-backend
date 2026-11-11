// POST /player-profile must not let a stranger overwrite someone's profile.
// No database needed (in-memory fake). Run: node test/profile-test.js

const { createApp } = require("../src/app");
const { LeaderboardService } = require("../src/service");
const { FakeStorage } = require("./fake-storage");
const h = require("./helpers");

const check = h.check;
const warns = [];
console.warn = (...args) => warns.push(args.join(" "));

async function main() {
  const storage = new FakeStorage();
  const config = { corsOrigin: "*", allowedPublicKeys: [], maxUsernameLength: 127, maxExtraLength: 100, observe: { enabled: false } };
  const service = new LeaderboardService(storage, config);
  const notified = [];
  service.notifyOnboarding = (lead) => notified.push(lead);
  const app = await h.listen(createApp(service, config));
  const post = (body) => h.request(app.base, { method: "POST", path: "/player-profile", body });
  const stored = () => ({ ...storage.profiles.get("dana@example.com") });

  const first = await post({ name: "Dana", email: "Dana@Example.com", country: "GB", consentAccepted: "1", userGuid: "guid-dana" });
  check("new email -> 200 {ok:true}", first.status === 200 && first.body === '{"ok":true}');
  check("new email -> profile stored", stored().name === "Dana" && stored().consentAccepted === true && stored().userGuid === "guid-dana");
  check("new email -> onboarding notified once", notified.length === 1);

  const hijack = await post({ name: "Mallory", email: "dana@example.com", country: "XX", consentAccepted: "1" });
  check("same email, no userGuid -> same 200 {ok:true}", hijack.status === 200 && hijack.body === '{"ok":true}');
  check("...name/country NOT overwritten", stored().name === "Dana" && stored().country === "GB", JSON.stringify(stored()));
  check("...no onboarding call", notified.length === 1);

  const wrongGuid = await post({ name: "Mallory", email: "dana@example.com", country: "XX", consentAccepted: "1", userGuid: "guid-mallory" });
  check("same email, wrong userGuid -> 200, profile kept, guid kept", wrongGuid.status === 200 && stored().name === "Dana" && stored().userGuid === "guid-dana");

  const withdraw = await post({ name: "Mallory", email: "dana@example.com", country: "XX", consentAccepted: "0" });
  check("consent withdrawal without proof -> applied", withdraw.status === 200 && stored().consentAccepted === false);
  check("...but name/country still kept", stored().name === "Dana" && stored().country === "GB");
  const regrant = await post({ name: "Mallory", email: "dana@example.com", country: "XX", consentAccepted: "1" });
  check("consent cannot be granted back without proof", regrant.status === 200 && stored().consentAccepted === false);

  const owner = await post({ name: "Dana B", email: "dana@example.com", country: "IE", consentAccepted: "1", userGuid: "guid-dana" });
  check("with the stored userGuid -> overwritten", owner.status === 200 && stored().name === "Dana B" && stored().country === "IE" && stored().consentAccepted === true);
  check("log lines never contain the email", warns.length >= 3 && warns.every((l) => !/@/.test(l)), JSON.stringify(warns));

  await app.close();
  h.finish();
}

main().catch((error) => {
  console.log(error);
  process.exit(1);
});
