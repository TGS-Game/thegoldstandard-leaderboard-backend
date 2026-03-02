const { Pool } = require("pg");

class PostgresStorage {
  constructor(connectionString) {
    this.pool = new Pool({
      connectionString,
      ssl: { rejectUnauthorized: false }
    });
  }

  async initialize() {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS entries (
        id TEXT PRIMARY KEY,
        public_key TEXT NOT NULL,
        user_guid TEXT NOT NULL,
        username TEXT NOT NULL,
        score INTEGER NOT NULL,
        extra TEXT NOT NULL DEFAULT '',
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        UNIQUE(public_key, user_guid)
      );
    `);

    await this.pool.query(`
      CREATE INDEX IF NOT EXISTS idx_entries_public_key ON entries(public_key);
    `);

    await this.pool.query(`
      CREATE INDEX IF NOT EXISTS idx_entries_public_key_score ON entries(public_key, score);
    `);

    await this.pool.query(`
      CREATE INDEX IF NOT EXISTS idx_entries_public_key_username ON entries(public_key, username);
    `);
  }

  async listEntries(publicKey) {
    const result = await this.pool.query(`
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
      WHERE public_key = $1
    `, [publicKey]);

    return result.rows.map(mapEntry);
  }

  async listPublicKeys() {
    const result = await this.pool.query(`
      SELECT DISTINCT public_key
      FROM entries
      ORDER BY public_key ASC
    `);

    return result.rows.map((row) => row.public_key);
  }

  async getEntry(publicKey, userGuid) {
    const result = await this.pool.query(`
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
      WHERE public_key = $1 AND user_guid = $2
      LIMIT 1
    `, [publicKey, userGuid]);

    return result.rows[0] ? mapEntry(result.rows[0]) : null;
  }

  async upsertEntry(entry) {
    await this.pool.query(`
      INSERT INTO entries (
        id,
        public_key,
        user_guid,
        username,
        score,
        extra,
        created_at,
        updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      ON CONFLICT(public_key, user_guid) DO UPDATE SET
        username = excluded.username,
        score = excluded.score,
        extra = excluded.extra,
        updated_at = excluded.updated_at
    `, [
      entry.id,
      entry.publicKey,
      entry.userGuid,
      entry.username,
      entry.score,
      entry.extra,
      entry.createdAt,
      entry.updatedAt
    ]);
  }

  async updateUsername(publicKey, userGuid, username, updatedAt) {
    const result = await this.pool.query(`
      UPDATE entries
      SET username = $1, updated_at = $2
      WHERE public_key = $3 AND user_guid = $4
    `, [username, updatedAt, publicKey, userGuid]);

    return result.rowCount > 0;
  }

  async deleteEntry(publicKey, userGuid) {
    const result = await this.pool.query(`
      DELETE FROM entries
      WHERE public_key = $1 AND user_guid = $2
    `, [publicKey, userGuid]);

    return result.rowCount > 0;
  }

  async close() {
    await this.pool.end();
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
  PostgresStorage
};
