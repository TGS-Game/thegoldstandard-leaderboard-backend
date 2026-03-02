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
  maxUsernameLength: parsePositiveInt(process.env.MAX_USERNAME_LENGTH, 127),
  maxExtraLength: parsePositiveInt(process.env.MAX_EXTRA_LENGTH, 100)
};
