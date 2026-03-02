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

module.exports = {
  SqliteStorage
};
