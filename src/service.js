const crypto = require("crypto");
const { nowUnixSeconds, resolveMinTimestamp } = require("./time");

class LeaderboardService {
  constructor(storage, config) {
    this.storage = storage;
    this.config = config;
  }

  async authorize() {
    return crypto.randomUUID();
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

    return filtered.map(toClientEntry);
  }

  async uploadEntry(body) {
    const publicKey = this.requirePublicKey(body.publicKey);
    const userGuid = this.requireUserGuid(body.userGuid);
    const username = this.normalizeUsername(body.username);
    const score = this.normalizeScore(body.score);
    const extra = this.normalizeExtra(body.extra);

    const timestamp = nowUnixSeconds();
    const existing = await this.storage.getEntry(publicKey, userGuid);

    await this.storage.upsertEntry({
      id: existing ? existing.id : crypto.randomUUID(),
      publicKey,
      userGuid,
      username,
      score,
      extra,
      createdAt: existing ? existing.createdAt : timestamp,
      updatedAt: timestamp
    });
  }

  async updateUsername(body) {
    const publicKey = this.requirePublicKey(body.publicKey);
    const userGuid = this.requireUserGuid(body.userGuid);
    const username = this.normalizeUsername(body.username);

    const updated = await this.storage.updateUsername(
      publicKey,
      userGuid,
      username,
      nowUnixSeconds()
    );

    if (!updated) {
      throw createHttpError(404, "Entry not found.");
    }
  }

  async deleteEntry(body) {
    const publicKey = this.requirePublicKey(body.publicKey);
    const userGuid = this.requireUserGuid(body.userGuid);

    const deleted = await this.storage.deleteEntry(publicKey, userGuid);
    if (!deleted) {
      throw createHttpError(404, "Entry not found.");
    }
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

    return toClientEntry(entry);
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

  async adminUpsertEntry(body) {
    const publicKey = this.requirePublicKey(body.publicKey);
    const userGuid = this.requireUserGuid(body.userGuid);
    const username = this.normalizeUsername(body.username);
    const score = this.normalizeScore(body.score);
    const extra = this.normalizeExtra(body.extra);
    const timestamp = nowUnixSeconds();
    const existing = await this.storage.getEntry(publicKey, userGuid);

    await this.storage.upsertEntry({
      id: existing ? existing.id : crypto.randomUUID(),
      publicKey,
      userGuid,
      username,
      score,
      extra,
      createdAt: existing ? existing.createdAt : timestamp,
      updatedAt: timestamp
    });
  }

  async adminDeleteEntry(params) {
    const publicKey = this.requirePublicKey(params.publicKey);
    const userGuid = this.requireUserGuid(params.userGuid);
    const deleted = await this.storage.deleteEntry(publicKey, userGuid);
    if (!deleted) {
      throw createHttpError(404, "Entry not found.");
    }
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

  normalizeScore(score) {
    const parsed = Number.parseInt(score, 10);
    if (!Number.isFinite(parsed)) {
      throw createHttpError(400, "score must be an integer.");
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

function toClientEntry(entry) {
  return {
    Username: entry.username,
    Score: entry.score,
    Date: entry.updatedAt,
    Extra: entry.extra,
    Rank: entry.rank,
    UserGuid: entry.userGuid
  };
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
