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

  async getAdminPublicKeys() {
    return this.storage.listPublicKeys();
  }

  async getAdminEntries(query) {
    const publicKey = this.requirePublicKey(query.publicKey);
    const entries = await this.storage.listEntries(publicKey);
    const ranked = rankEntriesForResponse(entries, {
      isInAscendingOrder: query.isInAscendingOrder,
      timePeriod: query.timePeriod
    });
    const mapped = ranked.map((entry) => ({
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

    return sortAdminEntries(mapped, {
      sortBy: query.sortBy,
      sortDirection: query.sortDirection
    });
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

function sortAdminEntries(entries, options) {
  const sortBy = normalizeSortBy(options.sortBy);
  const sortDirection = normalizeSortDirection(options.sortDirection);
  const directionMultiplier = sortDirection === "asc" ? 1 : -1;

  return [...entries].sort((left, right) => {
    let valueDelta = 0;

    if (sortBy === "rank") {
      valueDelta = left.rank - right.rank;
    } else if (sortBy === "time") {
      valueDelta = left.updatedAt - right.updatedAt;
    } else {
      valueDelta = left.score - right.score;
    }

    if (valueDelta !== 0) {
      return valueDelta * directionMultiplier;
    }

    const rankDelta = left.rank - right.rank;
    if (rankDelta !== 0) {
      return rankDelta;
    }

    return left.id.localeCompare(right.id);
  });
}

function normalizeSortBy(value) {
  const normalized = normalizeOptionalString(value).toLowerCase();
  if (normalized === "rank" || normalized === "score" || normalized === "time") {
    return normalized;
  }
  return "rank";
}

function normalizeSortDirection(value) {
  const normalized = normalizeOptionalString(value).toLowerCase();
  if (normalized === "asc" || normalized === "desc") {
    return normalized;
  }
  return "asc";
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
