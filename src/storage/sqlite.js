const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");

class SqliteStorage {
  constructor(filePath) {
    const dir = path.dirname(filePath);
    fs.mkdirSync(dir, { recursive: true });
    this.db = new Database(filePath);
    this.db.pragma("journal_mode = WAL");
  }

  async initialize() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS entries (
        id TEXT PRIMARY KEY,
        public_key TEXT NOT NULL,
        user_guid TEXT NOT NULL,
        username TEXT NOT NULL,
        score INTEGER NOT NULL,
        extra TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        UNIQUE(public_key, user_guid)
      );

      CREATE INDEX IF NOT EXISTS idx_entries_public_key ON entries(public_key);
      CREATE INDEX IF NOT EXISTS idx_entries_public_key_score ON entries(public_key, score);
      CREATE INDEX IF NOT EXISTS idx_entries_public_key_username ON entries(public_key, username);

      CREATE TABLE IF NOT EXISTS player_profiles (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        country TEXT NOT NULL,
        consent_accepted INTEGER NOT NULL,
        user_guid TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_player_profiles_email ON player_profiles(email);
      CREATE INDEX IF NOT EXISTS idx_player_profiles_created_at ON player_profiles(created_at DESC);
    `);
  }

  async listEntries(publicKey) {
    const rows = this.db.prepare(`
      SELECT
        id,
        public_key,
        user_guid,
        username,
        score,
        extra,
        created_at,
        updated_at
      FROM entries
      WHERE public_key = ?
    `).all(publicKey);

    return rows.map(mapEntry);
  }

  async listPublicKeys() {
    const rows = this.db.prepare(`
      SELECT DISTINCT public_key
      FROM entries
      ORDER BY public_key ASC
    `).all();

    return rows.map((row) => row.public_key);
  }

  async getEntry(publicKey, userGuid) {
    const row = this.db.prepare(`
      SELECT
        id,
        public_key,
        user_guid,
        username,
        score,
        extra,
        created_at,
        updated_at
      FROM entries
      WHERE public_key = ? AND user_guid = ?
      LIMIT 1
    `).get(publicKey, userGuid);

    return row ? mapEntry(row) : null;
  }

  async upsertEntry(entry) {
    this.db.prepare(`
      INSERT INTO entries (
        id,
        public_key,
        user_guid,
        username,
        score,
        extra,
        created_at,
        updated_at
      ) VALUES (
        @id,
        @publicKey,
        @userGuid,
        @username,
        @score,
        @extra,
        @createdAt,
        @updatedAt
      )
      ON CONFLICT(public_key, user_guid) DO UPDATE SET
        username = excluded.username,
        score = excluded.score,
        extra = excluded.extra,
        updated_at = excluded.updated_at
    `).run({
      id: entry.id,
      publicKey: entry.publicKey,
      userGuid: entry.userGuid,
      username: entry.username,
      score: entry.score,
      extra: entry.extra,
      createdAt: entry.createdAt,
      updatedAt: entry.updatedAt
    });
  }

  async updateUsername(publicKey, userGuid, username, updatedAt) {
    const result = this.db.prepare(`
      UPDATE entries
      SET username = ?, updated_at = ?
      WHERE public_key = ? AND user_guid = ?
    `).run(username, updatedAt, publicKey, userGuid);

    return result.changes > 0;
  }

  async deleteEntry(publicKey, userGuid) {
    const result = this.db.prepare(`
      DELETE FROM entries
      WHERE public_key = ? AND user_guid = ?
    `).run(publicKey, userGuid);

    return result.changes > 0;
  }

  async getPlayerProfileByEmail(email) {
    const row = this.db.prepare(`
      SELECT
        id,
        name,
        email,
        country,
        consent_accepted,
        user_guid,
        created_at,
        updated_at
      FROM player_profiles
      WHERE email = ?
      LIMIT 1
    `).get(email);

    return row ? mapPlayerProfile(row) : null;
  }

  async upsertPlayerProfile(profile) {
    this.db.prepare(`
      INSERT INTO player_profiles (
        id,
        name,
        email,
        country,
        consent_accepted,
        user_guid,
        created_at,
        updated_at
      ) VALUES (
        @id,
        @name,
        @email,
        @country,
        @consentAccepted,
        @userGuid,
        @createdAt,
        @updatedAt
      )
      ON CONFLICT(email) DO UPDATE SET
        name = excluded.name,
        country = excluded.country,
        consent_accepted = excluded.consent_accepted,
        user_guid = CASE
          WHEN excluded.user_guid <> '' THEN excluded.user_guid
          ELSE player_profiles.user_guid
        END,
        updated_at = excluded.updated_at
    `).run({
      id: profile.id,
      name: profile.name,
      email: profile.email,
      country: profile.country,
      consentAccepted: profile.consentAccepted ? 1 : 0,
      userGuid: profile.userGuid,
      createdAt: profile.createdAt,
      updatedAt: profile.updatedAt
    });
  }

  async listPlayerProfiles() {
    const rows = this.db.prepare(`
      SELECT
        id,
        name,
        email,
        country,
        consent_accepted,
        user_guid,
        created_at,
        updated_at
      FROM player_profiles
      ORDER BY created_at DESC, id ASC
    `).all();

    return rows.map(mapPlayerProfile);
  }

  async close() {
    this.db.close();
  }
}

function mapEntry(row) {
  return {
    id: row.id,
    publicKey: row.public_key,
    userGuid: row.user_guid,
    username: row.username,
    score: Number(row.score),
    extra: row.extra,
    createdAt: Number(row.created_at),
    updatedAt: Number(row.updated_at)
  };
}

function mapPlayerProfile(row) {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    country: row.country,
    consentAccepted: Boolean(row.consent_accepted),
    userGuid: row.user_guid,
    createdAt: Number(row.created_at),
    updatedAt: Number(row.updated_at)
  };
}

module.exports = {
  SqliteStorage
};
