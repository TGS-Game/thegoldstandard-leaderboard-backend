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
    this.initializeObservation();
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

  // Observe-mode tables (see observe.js). Only new tables and their indexes;
  // each is set up on its own, and a failure is logged and swallowed so the
  // service still boots.
  initializeObservation() {
    const tables = {
      issued_guids: `
        CREATE TABLE IF NOT EXISTS issued_guids (
          guid TEXT PRIMARY KEY,
          issued_at INTEGER NOT NULL,
          ip TEXT NOT NULL DEFAULT '',
          ip_source TEXT NOT NULL DEFAULT '',
          user_agent TEXT NOT NULL DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_issued_guids_issued_at ON issued_guids(issued_at);
      `,
      security_observations: `
        CREATE TABLE IF NOT EXISTS security_observations (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          at INTEGER NOT NULL,
          route TEXT NOT NULL,
          reason TEXT NOT NULL,
          ip TEXT NOT NULL DEFAULT '',
          ip_source TEXT NOT NULL DEFAULT '',
          user_agent TEXT NOT NULL DEFAULT '',
          key_prefix TEXT NOT NULL DEFAULT '',
          guid_ref TEXT NOT NULL DEFAULT '',
          detail TEXT NOT NULL DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_security_observations_at ON security_observations(at);
        CREATE INDEX IF NOT EXISTS idx_security_observations_reason_at ON security_observations(reason, at);
      `,
      traffic_hourly: `
        CREATE TABLE IF NOT EXISTS traffic_hourly (
          hour INTEGER NOT NULL,
          route TEXT NOT NULL,
          dim_key TEXT NOT NULL,
          count INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY (hour, route, dim_key)
        );
      `
    };

    for (const [table, statements] of Object.entries(tables)) {
      try {
        this.db.exec(statements);
      } catch (error) {
        console.error(`Observation table setup failed (${table}): ${error.message}`);
      }
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

  // Range of the scores stored by game uploads since a time (observe summary).
  async getUploadScoreRange(since) {
    const row = this.db.prepare(`
      SELECT
        COUNT(*) AS count,
        MIN(new_score) AS min_score,
        MAX(new_score) AS max_score
      FROM entry_history
      WHERE at >= ? AND action IN ('upload_insert', 'upload_overwrite')
    `).get(since);

    return mapScoreRange(row);
  }

  async insertIssuedGuid(record) {
    this.db.prepare(`
      INSERT INTO issued_guids (
        guid,
        issued_at,
        ip,
        ip_source,
        user_agent
      ) VALUES (
        @guid,
        @issuedAt,
        @ip,
        @ipSource,
        @userAgent
      )
      ON CONFLICT(guid) DO NOTHING
    `).run({
      guid: record.guid,
      issuedAt: record.issuedAt,
      ip: record.ip,
      ipSource: record.ipSource,
      userAgent: record.userAgent
    });
  }

  async isGuidIssued(guid) {
    const row = this.db.prepare(`
      SELECT 1 AS found
      FROM issued_guids
      WHERE guid = ?
      LIMIT 1
    `).get(guid);

    return Boolean(row);
  }

  async countIssuedGuids(since) {
    const rows = this.db.prepare(`
      SELECT
        ip_source,
        COUNT(*) AS count,
        COUNT(DISTINCT ip) AS distinct_ips
      FROM issued_guids
      WHERE issued_at >= ?
      GROUP BY ip_source
      ORDER BY ip_source ASC
    `).all(since);

    return mapIssuedCounts(rows);
  }

  async insertSecurityObservation(record) {
    this.db.prepare(`
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
      ) VALUES (
        @at,
        @route,
        @reason,
        @ip,
        @ipSource,
        @userAgent,
        @keyPrefix,
        @guidRef,
        @detail
      )
    `).run({
      at: record.at,
      route: record.route,
      reason: record.reason,
      ip: record.ip,
      ipSource: record.ipSource,
      userAgent: record.userAgent,
      keyPrefix: record.keyPrefix,
      guidRef: record.guidRef,
      detail: record.detail
    });
  }

  // Newest first. reason and route are optional filters ('' = any).
  async listSecurityObservations({ reason, route, since, limit }) {
    const conditions = ["at >= ?"];
    const values = [since];

    if (reason) {
      conditions.push("reason = ?");
      values.push(reason);
    }

    if (route) {
      conditions.push("route = ?");
      values.push(route);
    }

    values.push(limit);

    const rows = this.db.prepare(`
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
      LIMIT ?
    `).all(...values);

    return rows.map(mapSecurityObservation);
  }

  // Counts per reason and route. Rows with and without a guid_ref are grouped
  // apart, which separates the per-GUID rate rows from the per-IP ones.
  async summarizeSecurityObservations(since) {
    const rows = this.db.prepare(`
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
      WHERE at >= ?
      GROUP BY reason, route, (guid_ref <> '')
      ORDER BY reason ASC, route ASC, has_guid_ref ASC
    `).all(since);

    return rows.map(mapObservationSummary);
  }

  // Upsert-increment, all rows in one transaction.
  async incrementTrafficHourly(rows) {
    const statement = this.db.prepare(`
      INSERT INTO traffic_hourly (hour, route, dim_key, count)
      VALUES (@hour, @route, @dimKey, @count)
      ON CONFLICT(hour, route, dim_key) DO UPDATE SET
        count = count + excluded.count
    `);

    this.db.transaction((batch) => {
      for (const row of batch) {
        statement.run({ hour: row.hour, route: row.route, dimKey: row.dimKey, count: row.count });
      }
    })(rows);
  }

  async summarizeTraffic(since) {
    const rows = this.db.prepare(`
      SELECT
        route,
        dim_key,
        SUM(count) AS count
      FROM traffic_hourly
      WHERE hour >= ?
      GROUP BY route, dim_key
      ORDER BY route ASC, dim_key ASC
    `).all(since);

    return rows.map(mapTraffic);
  }

  async listTrafficHourly(since, limit) {
    const rows = this.db.prepare(`
      SELECT
        hour,
        route,
        dim_key,
        count
      FROM traffic_hourly
      WHERE hour >= ?
      ORDER BY hour DESC, route ASC, dim_key ASC
      LIMIT ?
    `).all(since, limit);

    return rows.map(mapTraffic);
  }

  // Retention for the three observe-mode tables only.
  async pruneObservationData(cutoff) {
    this.db.prepare("DELETE FROM issued_guids WHERE issued_at < ?").run(cutoff);
    this.db.prepare("DELETE FROM security_observations WHERE at < ?").run(cutoff);
    this.db.prepare("DELETE FROM traffic_hourly WHERE hour < ?").run(cutoff);
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
  SqliteStorage
};
