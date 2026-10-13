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

    await this.initializeEntryHistory();
    await this.initializeObservation();
  }

  // Audit trail of entry changes. Only ever creates a NEW table and its own
  // indexes: no ALTER, no foreign key, nothing that locks or rewrites entries.
  // A failure here is logged and swallowed so it can never stop the service
  // from booting; history writes then fail (and are swallowed) until it is fixed.
  async initializeEntryHistory() {
    try {
      await this.pool.query(`
        CREATE TABLE IF NOT EXISTS entry_history (
          id BIGSERIAL PRIMARY KEY,
          at BIGINT NOT NULL,
          action TEXT NOT NULL,
          source TEXT NOT NULL,
          public_key TEXT NOT NULL,
          user_guid TEXT NOT NULL,
          entry_id TEXT,
          old_username TEXT,
          old_score INTEGER,
          old_extra TEXT,
          old_created_at BIGINT,
          old_updated_at BIGINT,
          new_username TEXT,
          new_score INTEGER,
          new_extra TEXT,
          ip TEXT NOT NULL DEFAULT '',
          user_agent TEXT NOT NULL DEFAULT ''
        );
      `);

      await this.pool.query(`
        CREATE INDEX IF NOT EXISTS idx_entry_history_public_key_user_guid ON entry_history(public_key, user_guid);
      `);

      await this.pool.query(`
        CREATE INDEX IF NOT EXISTS idx_entry_history_at ON entry_history(at);
      `);
    } catch (error) {
      console.error(`Entry history table setup failed: ${error.message}`);
    }
  }

  // Observe-mode tables (see observe.js). Same rules as entry_history: only NEW
  // tables and their own indexes, nothing that touches or locks entries or
  // player_profiles. Each table is set up on its own, and a failure is logged
  // and swallowed so the service still boots; its writes then fail quietly.
  async initializeObservation() {
    const tables = {
      issued_guids: [`
        CREATE TABLE IF NOT EXISTS issued_guids (
          guid TEXT PRIMARY KEY,
          issued_at BIGINT NOT NULL,
          ip TEXT NOT NULL DEFAULT '',
          ip_source TEXT NOT NULL DEFAULT '',
          user_agent TEXT NOT NULL DEFAULT ''
        );
      `, `
        CREATE INDEX IF NOT EXISTS idx_issued_guids_issued_at ON issued_guids(issued_at);
      `],
      security_observations: [`
        CREATE TABLE IF NOT EXISTS security_observations (
          id BIGSERIAL PRIMARY KEY,
          at BIGINT NOT NULL,
          route TEXT NOT NULL,
          reason TEXT NOT NULL,
          ip TEXT NOT NULL DEFAULT '',
          ip_source TEXT NOT NULL DEFAULT '',
          user_agent TEXT NOT NULL DEFAULT '',
          key_prefix TEXT NOT NULL DEFAULT '',
          guid_ref TEXT NOT NULL DEFAULT '',
          detail TEXT NOT NULL DEFAULT ''
        );
      `, `
        CREATE INDEX IF NOT EXISTS idx_security_observations_at ON security_observations(at);
      `, `
        CREATE INDEX IF NOT EXISTS idx_security_observations_reason_at ON security_observations(reason, at);
      `],
      traffic_hourly: [`
        CREATE TABLE IF NOT EXISTS traffic_hourly (
          hour BIGINT NOT NULL,
          route TEXT NOT NULL,
          dim_key TEXT NOT NULL,
          count BIGINT NOT NULL DEFAULT 0,
          PRIMARY KEY (hour, route, dim_key)
        );
      `]
    };

    for (const [table, statements] of Object.entries(tables)) {
      try {
        for (const statement of statements) {
          await this.pool.query(statement);
        }
      } catch (error) {
        console.error(`Observation table setup failed (${table}): ${error.message}`);
      }
    }
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

  async insertEntryHistory(record) {
    await this.pool.query(`
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
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
    `, [
      record.at,
      record.action,
      record.source,
      record.publicKey,
      record.userGuid,
      record.entryId,
      record.oldUsername,
      record.oldScore,
      record.oldExtra,
      record.oldCreatedAt,
      record.oldUpdatedAt,
      record.newUsername,
      record.newScore,
      record.newExtra,
      record.ip,
      record.userAgent
    ]);
  }

  // Newest first. publicKey and userGuid are optional filters ('' = any).
  async listEntryHistory({ publicKey, userGuid, limit }) {
    const conditions = [];
    const values = [];

    if (publicKey) {
      values.push(publicKey);
      conditions.push(`public_key = $${values.length}`);
    }

    if (userGuid) {
      values.push(userGuid);
      conditions.push(`user_guid = $${values.length}`);
    }

    values.push(limit);
    const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

    const result = await this.pool.query(`
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
      LIMIT $${values.length}
    `, values);

    return result.rows.map(mapEntryHistory);
  }

  // Range of the scores stored by game uploads since a time (observe summary).
  async getUploadScoreRange(since) {
    const result = await this.pool.query(`
      SELECT
        COUNT(*) AS count,
        MIN(new_score) AS min_score,
        MAX(new_score) AS max_score
      FROM entry_history
      WHERE at >= $1 AND action IN ('upload_insert', 'upload_overwrite')
    `, [since]);

    return mapScoreRange(result.rows[0]);
  }

  async insertIssuedGuid(record) {
    await this.pool.query(`
      INSERT INTO issued_guids (
        guid,
        issued_at,
        ip,
        ip_source,
        user_agent
      ) VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT(guid) DO NOTHING
    `, [
      record.guid,
      record.issuedAt,
      record.ip,
      record.ipSource,
      record.userAgent
    ]);
  }

  async isGuidIssued(guid) {
    const result = await this.pool.query(`
      SELECT 1
      FROM issued_guids
      WHERE guid = $1
      LIMIT 1
    `, [guid]);

    return result.rows.length > 0;
  }

  async countIssuedGuids(since) {
    const result = await this.pool.query(`
      SELECT
        ip_source,
        COUNT(*) AS count,
        COUNT(DISTINCT ip) AS distinct_ips
      FROM issued_guids
      WHERE issued_at >= $1
      GROUP BY ip_source
      ORDER BY ip_source ASC
    `, [since]);

    return mapIssuedCounts(result.rows);
  }

  async insertSecurityObservation(record) {
    await this.pool.query(`
      INSERT INTO security_observations (
        at,
        route,
        reason,
        ip,
        ip_source,
        user_agent,
        key_prefix,
        guid_ref,
        detail
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    `, [
      record.at,
      record.route,
      record.reason,
      record.ip,
      record.ipSource,
      record.userAgent,
      record.keyPrefix,
      record.guidRef,
      record.detail
    ]);
  }

  // Newest first. reason and route are optional filters ('' = any).
  async listSecurityObservations({ reason, route, since, limit }) {
    const conditions = ["at >= $1"];
    const values = [since];

    if (reason) {
      values.push(reason);
      conditions.push(`reason = $${values.length}`);
    }

    if (route) {
      values.push(route);
      conditions.push(`route = $${values.length}`);
    }

    values.push(limit);

    const result = await this.pool.query(`
      SELECT
        id,
        at,
        route,
        reason,
        ip,
        ip_source,
        user_agent,
        key_prefix,
        guid_ref,
        detail
      FROM security_observations
      WHERE ${conditions.join(" AND ")}
      ORDER BY at DESC, id DESC
      LIMIT $${values.length}
    `, values);

    return result.rows.map(mapSecurityObservation);
  }

  // Counts per reason and route. Rows with and without a guid_ref are grouped
  // apart, which separates the per-GUID rate rows from the per-IP ones.
  async summarizeSecurityObservations(since) {
    const result = await this.pool.query(`
      SELECT
        reason,
        route,
        (guid_ref <> '') AS has_guid_ref,
        COUNT(*) AS count,
        COUNT(DISTINCT ip) AS distinct_ips,
        COUNT(DISTINCT guid_ref) AS distinct_guid_refs,
        MIN(at) AS first_at,
        MAX(at) AS last_at
      FROM security_observations
      WHERE at >= $1
      GROUP BY reason, route, (guid_ref <> '')
      ORDER BY reason ASC, route ASC, has_guid_ref ASC
    `, [since]);

    return result.rows.map(mapObservationSummary);
  }

  // Upsert-increment, one statement per batch. The (hour, route, dimKey) of the
  // rows passed in are unique, which ON CONFLICT DO UPDATE requires.
  async incrementTrafficHourly(rows) {
    for (let start = 0; start < rows.length; start += 500) {
      const batch = rows.slice(start, start + 500);
      await this.pool.query(`
        INSERT INTO traffic_hourly (hour, route, dim_key, count)
        SELECT * FROM unnest($1::bigint[], $2::text[], $3::text[], $4::bigint[])
        ON CONFLICT (hour, route, dim_key) DO UPDATE SET
          count = traffic_hourly.count + excluded.count
      `, [
        batch.map((row) => row.hour),
        batch.map((row) => row.route),
        batch.map((row) => row.dimKey),
        batch.map((row) => row.count)
      ]);
    }
  }

  async summarizeTraffic(since) {
    const result = await this.pool.query(`
      SELECT
        route,
        dim_key,
        SUM(count) AS count
      FROM traffic_hourly
      WHERE hour >= $1
      GROUP BY route, dim_key
      ORDER BY route ASC, dim_key ASC
    `, [since]);

    return result.rows.map(mapTraffic);
  }

  async listTrafficHourly(since, limit) {
    const result = await this.pool.query(`
      SELECT
        hour,
        route,
        dim_key,
        count
      FROM traffic_hourly
      WHERE hour >= $1
      ORDER BY hour DESC, route ASC, dim_key ASC
      LIMIT $2
    `, [since, limit]);

    return result.rows.map(mapTraffic);
  }

  // Retention for the three observe-mode tables only.
  async pruneObservationData(cutoff) {
    await this.pool.query("DELETE FROM issued_guids WHERE issued_at < $1", [cutoff]);
    await this.pool.query("DELETE FROM security_observations WHERE at < $1", [cutoff]);
    await this.pool.query("DELETE FROM traffic_hourly WHERE hour < $1", [cutoff]);
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

  async ping() {
    // Lightweight liveness check against the actual data store.
    await this.pool.query("SELECT 1");
    return true;
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

// BIGINT columns arrive as strings; keep NULL as null instead of 0.
function nullableNumber(value) {
  return value === null || value === undefined ? null : Number(value);
}

function mapScoreRange(row) {
  return {
    count: Number(row.count),
    min: nullableNumber(row.min_score),
    max: nullableNumber(row.max_score)
  };
}

function mapIssuedCounts(rows) {
  const bySource = rows.map((row) => ({
    ipSource: row.ip_source,
    count: Number(row.count),
    distinctIps: Number(row.distinct_ips)
  }));

  return {
    total: bySource.reduce((total, row) => total + row.count, 0),
    bySource
  };
}

function mapSecurityObservation(row) {
  return {
    id: Number(row.id),
    at: Number(row.at),
    route: row.route,
    reason: row.reason,
    ip: row.ip,
    ipSource: row.ip_source,
    userAgent: row.user_agent,
    keyPrefix: row.key_prefix,
    guidRef: row.guid_ref,
    detail: row.detail
  };
}

function mapObservationSummary(row) {
  return {
    reason: row.reason,
    route: row.route,
    hasGuidRef: Boolean(row.has_guid_ref),
    count: Number(row.count),
    distinctIps: Number(row.distinct_ips),
    distinctGuidRefs: Number(row.distinct_guid_refs),
    firstAt: Number(row.first_at),
    lastAt: Number(row.last_at)
  };
}

// `hour` is absent on the per-period totals.
function mapTraffic(row) {
  return {
    ...(row.hour === undefined ? {} : { hour: Number(row.hour) }),
    route: row.route,
    dimKey: row.dim_key,
    count: Number(row.count)
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
