const path = require("path");
const dotenv = require("dotenv");

dotenv.config();

function parsePositiveInt(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function parseCsv(value) {
  if (!value) {
    return [];
  }

  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseOptionalPositiveInt(value) {
  return parsePositiveInt(value, undefined);
}

// Anything except an explicit "off" (or 0/false/no) leaves the switch on.
function parseSwitch(value) {
  const text = typeof value === "string" ? value.trim().toLowerCase() : "";
  return !["off", "0", "false", "no"].includes(text);
}

const sqlitePath = process.env.SQLITE_PATH
  ? path.resolve(process.cwd(), process.env.SQLITE_PATH)
  : path.resolve(process.cwd(), "data", "leaderboard.sqlite");

module.exports = {
  port: parsePositiveInt(process.env.PORT, 8787),
  corsOrigin: process.env.CORS_ORIGIN || "*",
  databaseUrl: process.env.DATABASE_URL || "",
  sqlitePath,
  allowedPublicKeys: parseCsv(process.env.ALLOWED_PUBLIC_KEYS),
  adminToken: process.env.ADMIN_TOKEN || "",
  // Session login for the admin panel (used by the embedded hub flow).
  adminPassword: process.env.ADMIN_PASSWORD || "",
  sessionSecret: process.env.SESSION_SECRET || "",
  // Signed-in session lifetime. 12 hours by default.
  sessionTtlSeconds: parsePositiveInt(process.env.SESSION_TTL_SECONDS, 43200),
  // DIRECT_ADMIN_LOGIN=off switches off the password login form, so the hub's
  // /sso is the only way in for a person. ADMIN_TOKEN header auth is unaffected.
  directAdminLogin: parseSwitch(process.env.DIRECT_ADMIN_LOGIN),
  // Hub single sign-on: short-lived HS256 JWT, aud "leaderboard".
  ssoSecret: process.env.LEADERBOARD_SSO_SECRET || "",
  ssoAudience: process.env.LEADERBOARD_SSO_AUDIENCE || "leaderboard",
  // Origin allowed to embed the admin panel in an iframe (CSP frame-ancestors).
  hubOrigin: process.env.HUB_ORIGIN || "",
  // Optional key for masking other players' GUIDs in GET /get. When blank the
  // service falls back to a key derived from SESSION_SECRET, then to a random
  // per-process value (see resolveGuidMaskKey in service.js).
  guidMaskSecret: process.env.GUID_MASK_SECRET || "",
  maxUsernameLength: parsePositiveInt(process.env.MAX_USERNAME_LENGTH, 127),
  maxExtraLength: parsePositiveInt(process.env.MAX_EXTRA_LENGTH, 100),
  // External onboarding bridge: player registrations are mirrored here.
  // Fire-and-forget — never blocks or fails game registration.
  onboardUrl:
    process.env.ONBOARD_URL ||
    "https://onboarding-bridge-production.up.railway.app/api/switchmax",
  onboardSharedSecret: process.env.ONBOARD_SHARED_SECRET || "",
  // How long to wait on the onboarding call before giving up (ms).
  onboardTimeoutMs: parsePositiveInt(process.env.ONBOARD_TIMEOUT_MS, 5000),
  // Observe mode: log-only security telemetry, nothing is ever rejected. All
  // optional; blank values fall back to the defaults in observe.js.
  observe: {
    // SECURITY_OBSERVE=off is the kill switch for every observation write.
    enabled: parseSwitch(process.env.SECURITY_OBSERVE),
    expectedPublicKeys: parseCsv(process.env.OBSERVE_EXPECTED_PUBLIC_KEYS),
    maxScore: parseOptionalPositiveInt(process.env.OBSERVE_MAX_SCORE),
    maxUsernameLength: parseOptionalPositiveInt(process.env.OBSERVE_MAX_USERNAME_LENGTH),
    // Proposed rate limits as "<requests>/<window seconds>", e.g. 30/600.
    rateAuthorize: process.env.OBSERVE_RATE_AUTHORIZE || "",
    rateUpload: process.env.OBSERVE_RATE_UPLOAD || "",
    rateUploadGuid: process.env.OBSERVE_RATE_UPLOAD_GUID || "",
    rateProfile: process.env.OBSERVE_RATE_PROFILE || "",
    maxRowsPerHour: parseOptionalPositiveInt(process.env.OBSERVE_MAX_ROWS_PER_HOUR),
    maxIssuedPerHour: parseOptionalPositiveInt(process.env.OBSERVE_MAX_ISSUED_PER_HOUR)
  }
};
