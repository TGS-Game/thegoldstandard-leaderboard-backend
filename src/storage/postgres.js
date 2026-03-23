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

    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS player_profiles (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        country TEXT NOT NULL,
        consent_accepted BOOLEAN NOT NULL,
        user_guid TEXT NOT NULL DEFAULT '',
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
      );
    `);

    await this.pool.query(`
      CREATE INDEX IF NOT EXISTS idx_player_profiles_email ON player_profiles(email);
    `);

    await this.pool.query(`
      CREATE INDEX IF NOT EXISTS idx_player_profiles_created_at ON player_profiles(created_at DESC);
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

  async getPlayerProfileByEmail(email) {
    const result = await this.pool.query(`
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
      WHERE email = $1
      LIMIT 1
    `, [email]);

    return result.rows[0] ? mapPlayerProfile(result.rows[0]) : null;
  }

  async upsertPlayerProfile(profile) {
    await this.pool.query(`
      INSERT INTO player_profiles (
        id,
        name,
        email,
        country,
        consent_accepted,
        user_guid,
        created_at,
        updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      ON CONFLICT(email) DO UPDATE SET
        name = excluded.name,
        country = excluded.country,
        consent_accepted = excluded.consent_accepted,
        user_guid = CASE
          WHEN excluded.user_guid <> '' THEN excluded.user_guid
          ELSE player_profiles.user_guid
        END,
        updated_at = excluded.updated_at
    `, [
      profile.id,
      profile.name,
      profile.email,
      profile.country,
      profile.consentAccepted,
      profile.userGuid,
      profile.createdAt,
      profile.updatedAt
    ]);
  }

  async listPlayerProfiles() {
    const result = await this.pool.query(`
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
    `);

    return result.rows.map(mapPlayerProfile);
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
  PostgresStorage
};
