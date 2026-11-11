const crypto = require("crypto");
const { nowUnixSeconds, resolveMinTimestamp } = require("./time");
const { SecurityObserver } = require("./observe");

// Stored request metadata is clamped so a hostile header cannot bloat history.
const MAX_HISTORY_IP_LENGTH = 200;
const MAX_HISTORY_USER_AGENT_LENGTH = 300;
const DEFAULT_HISTORY_LIMIT = 100;
const MAX_HISTORY_LIMIT = 500;
// The score column is a 32-bit INTEGER.
const INT32_MAX = 2147483647;
const INT32_MIN = -2147483648;
const SESSION_ERROR_LOG_INTERVAL_SECONDS = 60;
const UPLOAD_SESSION_PRUNE_INTERVAL_MS = 60 * 60 * 1000;

class LeaderboardService {
  constructor(storage, config) {
    this.storage = storage;
    this.config = config;
    // Key for the opaque tokens that replace other players' GUIDs in GET /get.
    this.guidMaskKey = resolveGuidMaskKey(config);
    // Log-only security telemetry (see observe.js). It reuses the /get mask so
    // its rows never hold a real GUID.
    this.observer = new SecurityObserver({
      storage,
      config,
      maskGuid: (publicKey, userGuid) => this.maskUserGuid(publicKey, userGuid)
    });
    this.uploadSession = resolveUploadSession(config, storage);
    this.lastSessionErrorLogAt = 0;
    this.pruneTimer = null;
  }

  // Background jobs. Called by server.js (not by the tests' createApp).
  start() {
    if (this.uploadSession.mode !== "off" && !this.pruneTimer) {
      const prune = () => {
        const cutoff = nowUnixSeconds() - this.uploadSession.ttlSeconds - 24 * 60 * 60;
        Promise.resolve()
          .then(() => this.storage.pruneUploadSessions(cutoff))
          .catch((error) => this.logSessionError("prune", error));
      };
      this.pruneTimer = setInterval(prune, UPLOAD_SESSION_PRUNE_INTERVAL_MS);
      this.pruneTimer.unref();
    }
  }

  stop() {
    if (this.pruneTimer) {
      clearInterval(this.pruneTimer);
      this.pruneTimer = null;
    }
  }

  describeUploadSession() {
    const s = this.uploadSession;
    if (s.mode === "off") {
      return `Upload session checks: off${s.unsupported ? " (this storage does not support them; Postgres only)" : ""}.`;
    }
    return `Upload session checks: ${s.mode} (ttl ${s.ttlSeconds}s, min play ${s.minPlaySeconds}s, ` +
      `max score/s ${s.maxScorePerSecond || "off"}, max score ${this.config.maxScore || INT32_MAX}).`;
  }

  // The returned GUID is also the upload's session token: it is recorded so
  // an upload can be checked against it (known, unused, timing).
  async authorize() {
    const guid = crypto.randomUUID();
    if (this.uploadSession.mode !== "off") {
      try {
        await this.storage.insertUploadSession({ guid, issuedAt: nowUnixSeconds() });
      } catch (error) {
        this.logSessionError("record", error);
        if (this.uploadSession.mode === "enforce") {
          // A GUID that was not recorded could never be used to upload.
          throw createHttpError(503, "Service unavailable.");
        }
      }
    }
    return guid;
  }

  // Returns null (nothing to do), { claimedAt } (enforce: already marked
  // used) or { markAfter } (log: mark used once the entry is stored). Throws
  // 403 when enforce refuses the upload, 503 when the check cannot run.
  async checkUploadSession(publicKey, userGuid, score) {
    const settings = this.uploadSession;
    if (settings.mode === "off") {
      return null;
    }
    const enforce = settings.mode === "enforce";
    const now = nowUnixSeconds();

    let row;
    try {
      row = await this.storage.getUploadSession(userGuid);
    } catch (error) {
      this.logSessionError("lookup", error);
      if (enforce) {
        throw createHttpError(503, "Service unavailable.");
      }
      return null;
    }

    const reason = uploadSessionVerdict(row, now, score, settings);
    const describe = () =>
      `reason=${reason} guidRef=${this.maskUserGuid(publicKey, userGuid)} ` +
      `elapsedSeconds=${row ? now - row.issuedAt : "n/a"} score=${score}`;

    if (!enforce) {
      if (reason) {
        console.warn(`[upload-session] would refuse (log mode, stored anyway): ${describe()}`);
      }
      return { markAfter: Boolean(row && row.usedAt === null), now };
    }

    if (reason) {
      console.warn(`[upload-session] refused: ${describe()}`);
      throw createHttpError(403, "Upload refused.");
    }

    let claimed;
    try {
      claimed = await this.storage.claimUploadSession(userGuid, now);
    } catch (error) {
      this.logSessionError("claim", error);
      throw createHttpError(503, "Service unavailable.");
    }
    if (!claimed) {
      console.warn(`[upload-session] refused: reason=used (concurrent upload) guidRef=${this.maskUserGuid(publicKey, userGuid)}`);
      throw createHttpError(403, "Upload refused.");
    }
    return { claimedAt: now };
  }

  logSessionError(stage, error) {
    const now = nowUnixSeconds();
    if (now - this.lastSessionErrorLogAt < SESSION_ERROR_LOG_INTERVAL_SECONDS) {
      return;
    }
    this.lastSessionErrorLogAt = now;
    console.error(`[upload-session] ${stage} failed: ${String(error && error.message).slice(0, 200)}`);
  }

  async getLeaderboard(query) {
    const publicKey = this.requirePublicKey(query.publicKey);
    const allEntries = await this.storage.listEntries(publicKey);

    const filtered = filterAndRankEntries(allEntries, {
      isInAscendingOrder: query.isInAscendingOrder,
      username: query.username,
      skip: query.skip,
      take: query.take,
      timePeriod: query.timePeriod,
      viewerGuid: query.userGuid
    });

    // The GUID is the only credential for writing an entry, so the real value
    // goes out only on the caller's own row. Every other row carries a stable
    // opaque token in the same field (same shape, still a non-empty string).
    const viewerGuid = normalizeOptionalString(query.userGuid);
    return filtered.map((entry) =>
      toClientEntry(
        entry,
        entry.userGuid === viewerGuid
          ? entry.userGuid
          : this.maskUserGuid(entry.publicKey, entry.userGuid)
      )
    );
  }

  // HMAC-SHA256(maskKey, publicKey + ":" + userGuid), hex, first 32 chars.
  // Deterministic for a given key, so repeated /get calls return the same token.
  maskUserGuid(publicKey, userGuid) {
    return crypto
      .createHmac("sha256", this.guidMaskKey)
      .update(`${publicKey}:${userGuid}`)
      .digest("hex")
      .slice(0, 32);
  }

  async uploadEntry(body, meta) {
    const publicKey = this.requirePublicKey(body.publicKey);
    const userGuid = this.requireUserGuid(body.userGuid);
    const username = this.normalizeUsername(body.username);
    const score = this.normalizeScore(body.score, this.config.maxScore);
    const extra = this.normalizeExtra(body.extra);

    const session = await this.checkUploadSession(publicKey, userGuid, score);

    const timestamp = nowUnixSeconds();
    let existing;
    let id;
    try {
      existing = await this.storage.getEntry(publicKey, userGuid);
      id = existing ? existing.id : crypto.randomUUID();

      await this.storage.upsertEntry({
        id,
        publicKey,
        userGuid,
        username,
        score,
        extra,
        createdAt: existing ? existing.createdAt : timestamp,
        updatedAt: timestamp
      });
    } catch (error) {
      if (session && session.claimedAt) {
        // Nothing was stored: give the GUID back so the player can retry.
        Promise.resolve()
          .then(() => this.storage.releaseUploadSession(userGuid, session.claimedAt))
          .catch((releaseError) => this.logSessionError("release", releaseError));
      }
      throw error;
    }

    if (session && session.markAfter) {
      // Log mode: mark the GUID used so a second upload with it shows up as
      // "used". Not awaited; a failure only costs that statistic.
      Promise.resolve()
        .then(() => this.storage.claimUploadSession(userGuid, session.now))
        .catch((error) => this.logSessionError("mark used", error));
    }

    // Reuses the row already loaded above: no extra read for history.
    this.recordEntryHistory({
      action: existing ? "upload_overwrite" : "upload_insert",
      source: "public",
      publicKey,
      userGuid,
      before: existing,
      after: { id, username, score, extra },
      meta
    });

    // Only read by observe mode; the route's response does not use it.
    return { existed: Boolean(existing) };
  }

  // Admin-only since stage 1 (the route checks auth before calling this).
  async updateUsername(body, meta) {
    const publicKey = this.requirePublicKey(body.publicKey);
    const userGuid = this.requireUserGuid(body.userGuid);
    const username = this.normalizeUsername(body.username);
    const before = await this.readEntryForHistory(publicKey, userGuid);

    const updated = await this.storage.updateUsername(
      publicKey,
      userGuid,
      username,
      nowUnixSeconds()
    );

    if (!updated) {
      throw createHttpError(404, "Entry not found.");
    }

    this.recordEntryHistory({
      action: "rename",
      source: historySource(meta),
      publicKey,
      userGuid,
      before,
      after: {
        username,
        score: before ? before.score : null,
        extra: before ? before.extra : null
      },
      meta
    });
  }

  // Admin-only since stage 1 (the route checks auth before calling this).
  async deleteEntry(body, meta) {
    const publicKey = this.requirePublicKey(body.publicKey);
    const userGuid = this.requireUserGuid(body.userGuid);
    const before = await this.readEntryForHistory(publicKey, userGuid);

    const deleted = await this.storage.deleteEntry(publicKey, userGuid);
    if (!deleted) {
      throw createHttpError(404, "Entry not found.");
    }

    this.recordEntryHistory({
      action: "delete",
      source: historySource(meta),
      publicKey,
      userGuid,
      before,
      after: null,
      meta
    });
  }

  async getPersonalEntry(query) {
    const publicKey = this.requirePublicKey(query.publicKey);
    const userGuid = this.requireUserGuid(query.userGuid);
    const allEntries = await this.storage.listEntries(publicKey);

    const ranked = rankEntriesForResponse(allEntries, {
      isInAscendingOrder: false,
      timePeriod: 0
    });

    const entry = ranked.find((item) => item.userGuid === userGuid);
    if (!entry) {
      return {
        Username: "",
        Score: 0,
        Date: 0,
        Extra: "",
        Rank: 0,
        UserGuid: userGuid
      };
    }

    // Only ever the caller's own row: it is looked up by the GUID they supplied.
    return toClientEntry(entry, entry.userGuid);
  }

  async getEntryCount(query) {
    const publicKey = this.requirePublicKey(query.publicKey);
    const entries = await this.storage.listEntries(publicKey);
    return entries.length;
  }

  async uploadPlayerProfile(body) {
    const name = this.normalizePlayerName(body.name);
    const email = this.normalizePlayerEmail(body.email);
    const country = this.normalizeCountry(body.country);
    const consentAccepted = this.normalizeConsent(body.consentAccepted);
    const userGuid = this.normalizeOptionalUserGuid(body.userGuid);
    const timestamp = nowUnixSeconds();
    const existing = await this.storage.getPlayerProfileByEmail(email);

    await this.storage.upsertPlayerProfile({
      id: existing ? existing.id : crypto.randomUUID(),
      name,
      email,
      country,
      consentAccepted,
      userGuid: userGuid || (existing ? existing.userGuid : ""),
      createdAt: existing ? existing.createdAt : timestamp,
      updatedAt: timestamp
    });

    // Mirror the registration to the external onboarding bridge. This is
    // intentionally NOT awaited: registration has already succeeded, and the
    // onboarding call must never delay or fail the player's response.
    this.notifyOnboarding({
      name,
      email,
      country,
      consent: consentAccepted
    });
  }

  // Fire-and-forget POST to the onboarding bridge. Any slowness, error, or
  // unreachable endpoint is logged and swallowed — it can never throw into,
  // or block, uploadPlayerProfile.
  notifyOnboarding({ name, email, country, consent }) {
    const url = this.config.onboardUrl;
    const secret = this.config.onboardSharedSecret;

    if (!url || !secret) {
      console.warn(
        "Onboarding notify skipped: ONBOARD_URL or ONBOARD_SHARED_SECRET is not configured."
      );
      return;
    }

    Promise.resolve()
      .then(() =>
        fetch(url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-shared-secret": secret
          },
          body: JSON.stringify({ name, email, country, consent }),
          signal: AbortSignal.timeout(this.config.onboardTimeoutMs)
        })
      )
      .then((response) => {
        if (!response.ok) {
          console.error(
            `Onboarding notify failed: HTTP ${response.status} from onboarding bridge.`
          );
        }
      })
      .catch((error) => {
        console.error(`Onboarding notify error: ${error.message}`);
      });
  }

  async checkHealth() {
    // Returns true only if the underlying data store responds.
    await this.storage.ping();
    return true;
  }

  async getAdminPublicKeys() {
    return this.storage.listPublicKeys();
  }

  async getAdminPlayerProfiles() {
    return this.storage.listPlayerProfiles();
  }

  async getAdminEntries(query) {
    const publicKey = this.requirePublicKey(query.publicKey);
    const entries = await this.storage.listEntries(publicKey);
    const ranked = rankEntriesForResponse(entries, {
      isInAscendingOrder: query.isInAscendingOrder,
      timePeriod: query.timePeriod
    });

    return ranked.map((entry) => ({
      id: entry.id,
      publicKey: entry.publicKey,
      userGuid: entry.userGuid,
      username: entry.username,
      score: entry.score,
      extra: entry.extra,
      createdAt: entry.createdAt,
      updatedAt: entry.updatedAt,
      rank: entry.rank
    }));
  }

  // Read-only audit trail, newest first. Both filters are optional.
  async getAdminEntryHistory(query) {
    const parsedLimit = Number.parseInt(query.limit, 10);
    const limit = Number.isFinite(parsedLimit) && parsedLimit > 0
      ? Math.min(parsedLimit, MAX_HISTORY_LIMIT)
      : DEFAULT_HISTORY_LIMIT;

    return this.storage.listEntryHistory({
      publicKey: normalizeOptionalString(query.publicKey),
      userGuid: normalizeOptionalString(query.userGuid),
      limit
    });
  }

  // Observe-mode rows, newest first. Filters: reason, route, since, limit.
  async getAdminObservations(query) {
    return this.observer.listObservations(query);
  }

  // Observe-mode report for a period (default: the last 7 days).
  async getAdminObservationSummary(query) {
    return this.observer.getSummary(query);
  }

  async adminUpsertEntry(body, meta) {
    const publicKey = this.requirePublicKey(body.publicKey);
    const userGuid = this.requireUserGuid(body.userGuid);
    const username = this.normalizeUsername(body.username);
    const score = this.normalizeScore(body.score);
    const extra = this.normalizeExtra(body.extra);
    const timestamp = nowUnixSeconds();
    const existing = await this.storage.getEntry(publicKey, userGuid);
    const id = existing ? existing.id : crypto.randomUUID();

    await this.storage.upsertEntry({
      id,
      publicKey,
      userGuid,
      username,
      score,
      extra,
      createdAt: existing ? existing.createdAt : timestamp,
      updatedAt: timestamp
    });

    this.recordEntryHistory({
      action: existing ? "admin_upsert_overwrite" : "admin_upsert_insert",
      source: "admin",
      publicKey,
      userGuid,
      before: existing,
      after: { id, username, score, extra },
      meta
    });
  }

  async adminDeleteEntry(params, meta) {
    const publicKey = this.requirePublicKey(params.publicKey);
    const userGuid = this.requireUserGuid(params.userGuid);
    const before = await this.readEntryForHistory(publicKey, userGuid);
    const deleted = await this.storage.deleteEntry(publicKey, userGuid);
    if (!deleted) {
      throw createHttpError(404, "Entry not found.");
    }

    this.recordEntryHistory({
      action: "admin_delete",
      source: "admin",
      publicKey,
      userGuid,
      before,
      after: null,
      meta
    });
  }

  // Loads the row as it is BEFORE a rename/delete so history can keep it. A
  // failed read only costs the "old" columns; it never fails the request.
  async readEntryForHistory(publicKey, userGuid) {
    try {
      return await this.storage.getEntry(publicKey, userGuid);
    } catch (error) {
      console.error(
        `Entry history pre-read failed (key ${shortId(publicKey)}): ${error.message}`
      );
      return null;
    }
  }

  // Appends one audit row for an entry mutation that has already succeeded.
  // Intentionally NOT awaited, and every failure is logged and swallowed: a
  // slow or broken history write can never delay or fail the game's request.
  recordEntryHistory({ action, source, publicKey, userGuid, before, after, meta }) {
    const requestMeta = meta || {};
    const record = {
      at: nowUnixSeconds(),
      action,
      source,
      publicKey,
      userGuid,
      entryId: before ? before.id : (after && after.id) || null,
      oldUsername: before ? before.username : null,
      oldScore: before ? before.score : null,
      oldExtra: before ? before.extra : null,
      oldCreatedAt: before ? before.createdAt : null,
      oldUpdatedAt: before ? before.updatedAt : null,
      newUsername: after ? after.username : null,
      newScore: after ? after.score : null,
      newExtra: after ? after.extra : null,
      ip: clampText(requestMeta.ip, MAX_HISTORY_IP_LENGTH),
      userAgent: clampText(requestMeta.userAgent, MAX_HISTORY_USER_AGENT_LENGTH)
    };

    Promise.resolve()
      .then(() => this.storage.insertEntryHistory(record))
      .catch((error) => {
        console.error(
          `Entry history write failed (${action}, key ${shortId(publicKey)}): ${error.message}`
        );
      });
  }

  requirePublicKey(publicKey) {
    const value = typeof publicKey === "string" ? publicKey.trim() : "";
    if (!value) {
      throw createHttpError(400, "publicKey is required.");
    }

    if (
      this.config.allowedPublicKeys.length > 0 &&
      !this.config.allowedPublicKeys.includes(value)
    ) {
      throw createHttpError(403, "publicKey is not allowed.");
    }

    return value;
  }

  requireUserGuid(userGuid) {
    const value = typeof userGuid === "string" ? userGuid.trim() : "";
    if (!value) {
      throw createHttpError(400, "userGuid is required.");
    }
    return value;
  }

  normalizeUsername(username) {
    const value = typeof username === "string" ? username.trim() : "";
    if (!value) {
      throw createHttpError(400, "username is required.");
    }

    return value.slice(0, this.config.maxUsernameLength);
  }

  normalizeExtra(extra) {
    const value = typeof extra === "string" ? extra : "";
    return value.slice(0, this.config.maxExtraLength);
  }

  // maxScore: the configured MAX_SCORE for game uploads; admin edits pass
  // nothing and get the full INTEGER range. Out of range is a 400 (it used to
  // reach Postgres and come back as a 500 "out of range" error).
  normalizeScore(score, maxScore) {
    const parsed = Number.parseInt(score, 10);
    if (!Number.isFinite(parsed)) {
      throw createHttpError(400, "score must be an integer.");
    }

    const max = Math.min(Number.isInteger(maxScore) && maxScore > 0 ? maxScore : INT32_MAX, INT32_MAX);
    if (parsed > max || parsed < INT32_MIN) {
      throw createHttpError(400, "score is out of range.");
    }

    return parsed;
  }

  normalizePlayerName(name) {
    const value = typeof name === "string" ? name.trim() : "";
    if (!value) {
      throw createHttpError(400, "name is required.");
    }

    if (value.length > 100) {
      throw createHttpError(400, "name is too long.");
    }

    return value;
  }

  normalizePlayerEmail(email) {
    const value = typeof email === "string" ? email.trim().toLowerCase() : "";
    if (!value) {
      throw createHttpError(400, "email is required.");
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
      throw createHttpError(400, "email is invalid.");
    }

    if (value.length > 255) {
      throw createHttpError(400, "email is too long.");
    }

    return value;
  }

  normalizeCountry(country) {
    const value = typeof country === "string" ? country.trim() : "";
    if (!value) {
      throw createHttpError(400, "country is required.");
    }

    if (value.length > 100) {
      throw createHttpError(400, "country is too long.");
    }

    return value;
  }

  normalizeConsent(consentAccepted) {
    if (
      consentAccepted === true ||
      consentAccepted === 1 ||
      consentAccepted === "1" ||
      consentAccepted === "true"
    ) {
      return true;
    }

    if (
      consentAccepted === false ||
      consentAccepted === 0 ||
      consentAccepted === "0" ||
      consentAccepted === "false" ||
      consentAccepted === "" ||
      consentAccepted == null
    ) {
      return false;
    }

    throw createHttpError(400, "consentAccepted must be a boolean value.");
  }

  normalizeOptionalUserGuid(userGuid) {
    const value = typeof userGuid === "string" ? userGuid.trim() : "";
    if (!value) {
      return "";
    }

    return value.slice(0, 100);
  }
}

// Upload-session settings. No uploadSession config (tests, old callers) or a
// storage without the table (SQLite) means off.
function resolveUploadSession(config, storage) {
  const source = (config && config.uploadSession) || {};
  const mode = ["log", "enforce"].includes(source.mode) ? source.mode : "off";
  const supported = Boolean(storage && typeof storage.getUploadSession === "function");
  return {
    mode: supported ? mode : "off",
    unsupported: mode !== "off" && !supported,
    ttlSeconds: Number.isInteger(source.ttlSeconds) && source.ttlSeconds > 0 ? source.ttlSeconds : 30 * 24 * 60 * 60,
    minPlaySeconds: Number.isInteger(source.minPlaySeconds) && source.minPlaySeconds > 0 ? source.minPlaySeconds : 0,
    maxScorePerSecond: Number.isInteger(source.maxScorePerSecond) && source.maxScorePerSecond > 0 ? source.maxScorePerSecond : 0
  };
}

// "" when the upload passes, else why not.
function uploadSessionVerdict(row, now, score, settings) {
  if (!row) {
    return "unknown";
  }
  if (row.usedAt !== null && row.usedAt !== undefined) {
    return "used";
  }
  const elapsed = Math.max(0, now - row.issuedAt);
  if (elapsed < settings.minPlaySeconds) {
    return "too_fast";
  }
  if (elapsed > settings.ttlSeconds) {
    return "expired";
  }
  if (settings.maxScorePerSecond > 0 && score > settings.maxScorePerSecond * Math.max(elapsed, 1)) {
    return "implausible_score";
  }
  return "";
}

function filterAndRankEntries(entries, options) {
  const ranked = rankEntriesForResponse(entries, options);
  const username = normalizeOptionalString(options.username);
  const skip = clampToZero(options.skip);
  const take = clampToZero(options.take);

  if (username) {
    const index = ranked.findIndex((entry) => entry.username.toLowerCase() === username.toLowerCase());
    if (index < 0) {
      return [];
    }

    const start = Math.max(0, index - skip);
    const end = take > 0 ? index + take + 1 : index + 1;
    return ranked.slice(start, end);
  }

  if (skip > 0 || take > 0) {
    if (take > 0) {
      return ranked.slice(skip, skip + take);
    }

    return ranked.slice(skip);
  }

  return ranked;
}

function rankEntriesForResponse(entries, options) {
  const minTimestamp = resolveMinTimestamp(options.timePeriod);
  const isAscending = toBool(options.isInAscendingOrder);

  return entries
    .filter((entry) => entry.updatedAt >= minTimestamp)
    .sort((left, right) => compareEntries(left, right, isAscending))
    .map((entry, index) => ({
      ...entry,
      rank: index + 1
    }));
}

function compareEntries(left, right, isAscending) {
  const scoreDelta = isAscending ? left.score - right.score : right.score - left.score;
  if (scoreDelta !== 0) {
    return scoreDelta;
  }

  const dateDelta = left.updatedAt - right.updatedAt;
  if (dateDelta !== 0) {
    return dateDelta;
  }

  return left.id.localeCompare(right.id);
}

// clientUserGuid is the real GUID for the caller's own row, a mask otherwise.
function toClientEntry(entry, clientUserGuid) {
  return {
    Username: entry.username,
    Score: entry.score,
    Date: entry.updatedAt,
    Extra: entry.extra,
    Rank: entry.rank,
    UserGuid: clientUserGuid
  };
}

// Mask key order: GUID_MASK_SECRET, else a key derived from SESSION_SECRET
// (derived, so the cookie-signing secret is never used directly for a second
// purpose), else a random per-process value. The random fallback keeps tokens
// stable only until the next restart.
function resolveGuidMaskKey(config) {
  if (config.guidMaskSecret) {
    return config.guidMaskSecret;
  }

  if (config.sessionSecret) {
    return crypto
      .createHmac("sha256", config.sessionSecret)
      .update("guid-mask-key-v1")
      .digest();
  }

  return crypto.randomBytes(32);
}

// The /entry/* admin-only routes pass source "admin"; default is "public".
function historySource(meta) {
  return meta && meta.source === "admin" ? "admin" : "public";
}

function clampText(value, maxLength) {
  return typeof value === "string" ? value.slice(0, maxLength) : "";
}

// Log-safe prefix of a key or GUID: never more than the first 8 characters.
function shortId(value) {
  return typeof value === "string" ? value.slice(0, 8) : "";
}

function normalizeOptionalString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function clampToZero(value) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

function toBool(value) {
  return value === true || value === 1 || value === "1" || value === "true";
}

function createHttpError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

module.exports = {
  LeaderboardService,
  createHttpError
};
