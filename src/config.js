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
  // Hub single sign-on: short-lived HS256 JWT, aud "leaderboard".
  ssoSecret: process.env.LEADERBOARD_SSO_SECRET || "",
  ssoAudience: process.env.LEADERBOARD_SSO_AUDIENCE || "leaderboard",
  // Origin allowed to embed the admin panel in an iframe (CSP frame-ancestors).
  hubOrigin: process.env.HUB_ORIGIN || "",
  maxUsernameLength: parsePositiveInt(process.env.MAX_USERNAME_LENGTH, 127),
  maxExtraLength: parsePositiveInt(process.env.MAX_EXTRA_LENGTH, 100)
};
