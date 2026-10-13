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

    this.initializeEntryHistory();
  }

  // Audit trail of entry changes. Only creates a new table and its indexes. A
  // failure here is logged and swallowed so it can never stop the service from
  // booting; history writes then fail (and are swallowed) until it is fixed.
  initializeEntryHistory() {
    try {
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS entry_history (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          at INTEGER NOT NULL,
          action TEXT NOT NULL,
          source TEXT NOT NULL,
          public_key TEXT NOT NULL,
          user_guid TEXT NOT NULL,
          entry_id TEXT,
          old_username TEXT,
          old_score INTEGER,
          old_extra TEXT,
          old_created_at INTEGER,
          old_updated_at INTEGER,
          new_username TEXT,
          new_score INTEGER,
          new_extra TEXT,
          ip TEXT NOT NULL DEFAULT '',
          user_agent TEXT NOT NULL DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_entry_history_public_key_user_guid ON entry_history(public_key, user_guid);
        CREATE INDEX IF NOT EXISTS idx_entry_history_at ON entry_history(at);
      `);
    } catch (error) {
      console.error(`Entry history table setup failed: ${error.message}`);
    }
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

  async insertEntryHistory(record) {
    this.db.prepare(`
      INSERT INTO entry_history (
        at,
        action,
        source,
        public_key,
        user_guid,
        entry_id,
        old_username,
        old_score,
        old_extra,
        old_created_at,
        old_updated_at,
        new_username,
        new_score,
        new_extra,
        ip,
        user_agent
      ) VALUES (
        @at,
        @action,
        @source,
        @publicKey,
        @userGuid,
        @entryId,
        @oldUsername,
        @oldScore,
        @oldExtra,
        @oldCreatedAt,
        @oldUpdatedAt,
        @newUsername,
        @newScore,
        @newExtra,
        @ip,
        @userAgent
      )
    `).run({
      at: record.at,
      action: record.action,
      source: record.source,
      publicKey: record.publicKey,
      userGuid: record.userGuid,
      entryId: record.entryId,
      oldUsername: record.oldUsername,
      oldScore: record.oldScore,
      oldExtra: record.oldExtra,
      oldCreatedAt: record.oldCreatedAt,
      oldUpdatedAt: record.oldUpdatedAt,
      newUsername: record.newUsername,
      newScore: record.newScore,
      newExtra: record.newExtra,
      ip: record.ip,
      userAgent: record.userAgent
    });
  }

  // Newest first. publicKey and userGuid are optional filters ('' = any).
  async listEntryHistory({ publicKey, userGuid, limit }) {
    const conditions = [];
    const values = [];

    if (publicKey) {
      conditions.push("public_key = ?");
      values.push(publicKey);
    }

    if (userGuid) {
      conditions.push("user_guid = ?");
      values.push(userGuid);
    }

    values.push(limit);
    const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

    const rows = this.db.prepare(`
      SELECT
        id,
        at,
        action,
        source,
        public_key,
        user_guid,
        entry_id,
        old_username,
        old_score,
        old_extra,
        old_created_at,
        old_updated_at,
        new_username,
        new_score,
        new_extra,
        ip,
        user_agent
      FROM entry_history
      ${where}
      ORDER BY at DESC, id DESC
      LIMIT ?
    `).all(...values);

    return rows.map(mapEntryHistory);
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

  async ping() {
    // Lightweight liveness check against the actual data store.
    this.db.prepare("SELECT 1").get();
    return true;
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

function mapEntryHistory(row) {
  return {
    id: Number(row.id),
    at: Number(row.at),
    action: row.action,
    source: row.source,
    publicKey: row.public_key,
    userGuid: row.user_guid,
    entryId: row.entry_id,
    oldUsername: row.old_username,
    oldScore: nullableNumber(row.old_score),
    oldExtra: row.old_extra,
    oldCreatedAt: nullableNumber(row.old_created_at),
    oldUpdatedAt: nullableNumber(row.old_updated_at),
    newUsername: row.new_username,
    newScore: nullableNumber(row.new_score),
    newExtra: row.new_extra,
    ip: row.ip,
    userAgent: row.user_agent
  };
}

// Keep NULL as null instead of 0.
function nullableNumber(value) {
  return value === null || value === undefined ? null : Number(value);
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
