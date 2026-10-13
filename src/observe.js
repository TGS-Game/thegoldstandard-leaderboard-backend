// Observe mode: log-only security telemetry for the game-facing routes.
//
// HARD RULE for everything in this file: it only watches. It never rejects,
// delays or alters a request, and it has no enforcement path at all. Every
// observation runs from the response's "finish" event (so the response has
// already been sent), inside try/catch, and every database write goes through a
// small bounded background queue. A slow, broken or hung database can therefore
// cost observations, never a request.

const { nowUnixSeconds } = require("./time");

// The shipped game's public key. It is not a secret: it is printed in the web
// pages that embed the leaderboard widget.
const LIVE_PUBLIC_KEY = "536aec42d31fa4ec5c486c219f9821f6a145562fcb069c6f19f40786fdc38678";

// Proposed limits. Nothing is enforced: crossing one only records a row.
const DEFAULTS = {
  enabled: true,
  expectedPublicKeys: [LIVE_PUBLIC_KEY],
  maxScore: 100000000,
  maxUsernameLength: 60,
  rateAuthorize: { max: 30, windowSeconds: 600 },
  rateUpload: { max: 20, windowSeconds: 600 },
  rateUploadGuid: { max: 5, windowSeconds: 600 },
  rateProfile: { max: 10, windowSeconds: 3600 },
  // Write-volume bounds.
  maxRowsPerHour: 500, // security_observations rows per reason per hour
  maxIssuedPerHour: 2000, // issued_guids rows per hour
  // Memory bounds.
  maxRateKeys: 10000,
  maxRecentGuids: 5000,
  maxDistinctIps: 2000, // per route per hour
  maxDimensions: 200, // distinct client-contract keys per route per hour
  maxPendingTraffic: 5000,
  maxQueue: 1000,
  flushIntervalSeconds: 300,
  pruneIntervalSeconds: 3600,
  retentionSeconds: 90 * 24 * 60 * 60
};

// Distinct-value caps for the smaller traffic dimension kinds.
const KIND_CAPS = { key: 50, extra: 30, addr: 60 };
const DEFAULT_KIND_CAP = 60;

const QUEUE_CONCURRENCY = 2; // leaves the rest of the pg pool to the game
const HOUR_SECONDS = 3600;
const MAX_IP_LENGTH = 64;
const MAX_USER_AGENT_LENGTH = 300;
const MAX_ISSUED_USER_AGENT_LENGTH = 120;
const MAX_DETAIL_LENGTH = 1000;
const MAX_DIMENSION_LENGTH = 200;
const PROFILE_NAME_LIMIT = 60;
const PROFILE_COUNTRY_LIMIT = 60;
const PROFILE_EMAIL_LIMIT = 254;
const DEFAULT_OBSERVATION_LIMIT = 100;
const MAX_OBSERVATION_LIMIT = 1000;
const DEFAULT_SUMMARY_SECONDS = 7 * 24 * 60 * 60;
const MAX_HOURLY_ROWS = 5000;
const FAILURE_LOG_INTERVAL_SECONDS = 60;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const USERNAME_PATTERN = /^(.+)-([^-]+)-(-?\d+(?:[.,]\d+)?)$/;

// Watched routes, keyed by "METHOD path". The label is taken from this table,
// never from the request, so a client cannot invent route names.
const ROUTES = {
  "GET /authorize": { label: "/authorize", rate: "rateAuthorize" },
  "GET /get": { label: "/get", fields: "query", hasKey: true },
  "GET /entry/get": { label: "/entry/get", fields: "query", hasKey: true },
  "GET /entry/count": { label: "/entry/count", fields: "query", hasKey: true },
  "POST /entry/upload": { label: "/entry/upload", fields: "body", hasKey: true, rate: "rateUpload" },
  "POST /entry/update-username": { label: "/entry/update-username", fields: "body", hasKey: true },
  "POST /entry/delete": { label: "/entry/delete", fields: "body", hasKey: true },
  "POST /player-profile": { label: "/player-profile", fields: "body", rate: "rateProfile" }
};

class SecurityObserver {
  // maskGuid(publicKey, userGuid) is the service's /get masking function, so
  // guid_ref values here line up with the tokens players already see.
  constructor({ storage, config, maskGuid }) {
    this.storage = storage;
    this.maskGuid = maskGuid;
    this.settings = resolveSettings(config && config.observe);
    this.enabled = this.settings.enabled;
    this.now = typeof this.settings.now === "function" ? this.settings.now : nowUnixSeconds;

    this.rateCounters = new Map(); // "route|scope|key" -> { start, count, windowSeconds }
    this.recentGuids = new Map(); // guid -> issued at (covers the insert/lookup race)
    this.pendingTraffic = new Map(); // "hour\nroute\ndimKey" -> count not yet flushed
    this.queue = [];
    this.inFlight = 0;
    this.flushTimer = null;
    this.lastFlushAt = this.now();
    this.lastPruneAt = 0;
    this.lastFailureLogAt = new Map();
    // Since process start; reported by the summary endpoint.
    this.stats = { queued: 0, dropped: 0, writeErrors: 0, handlerErrors: 0 };
    this.resetHour(hourOf(this.now()));
  }

  // Per-hour state: caps and distinct sets start again every hour.
  resetHour(hour) {
    this.hour = hour;
    this.seenDimensions = new Map(); // "route\nkind" -> Set of dimension values
    this.seenIps = new Map(); // route -> Set of client addresses
    this.rowsThisHour = new Map(); // reason -> rows written
    this.issuedThisHour = 0;
  }

  // Periodic flush of the traffic aggregate. Unref'd so it never keeps the
  // process alive. Requests also trigger a flush when one is overdue.
  start() {
    if (!this.enabled || this.flushTimer) {
      return;
    }
    this.flushTimer = setInterval(() => {
      try {
        this.maintain(this.now(), true);
      } catch (error) {
        this.noteHandlerError(error);
      }
    }, this.settings.flushIntervalSeconds * 1000);
    this.flushTimer.unref();
  }

  // Shutdown hook: one last flush. Resolves either way.
  async stop() {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    await this.flushTraffic();
  }

  // Express middleware. Its whole effect on the request path is registering a
  // listener and calling next().
  middleware() {
    return (req, res, next) => {
      try {
        this.watch(req, res);
      } catch (error) {
        this.noteHandlerError(error);
      }
      next();
    };
  }

  watch(req, res) {
    if (!this.enabled) {
      return;
    }
    const route = matchRoute(req);
    if (!route) {
      return;
    }
    // "finish" fires after the response has been handed to the socket. An
    // exception inside an event listener would be uncaught, hence the catch.
    res.on("finish", () => {
      try {
        this.observe(route, req, res);
      } catch (error) {
        this.noteHandlerError(error);
      }
    });
  }

  // Called by the /authorize route with the GUID it is about to return.
  guidIssued(res, guid) {
    try {
      if (!this.enabled || typeof guid !== "string") {
        return;
      }
      this.rememberGuid(guid, this.now());
      res.locals.observeIssuedGuid = guid;
    } catch (error) {
      this.noteHandlerError(error);
    }
  }

  // Called by the upload route once the entry is stored, so the observation
  // knows whether this GUID already had an entry before the upload.
  uploadStored(res, result) {
    try {
      if (!this.enabled) {
        return;
      }
      res.locals.observeEntryExisted = Boolean(result && result.existed);
    } catch (error) {
      this.noteHandlerError(error);
    }
  }

  observe(route, req, res) {
    const now = this.now();
    if (hourOf(now) !== this.hour) {
      this.resetHour(hourOf(now));
    }

    const address = resolveClientAddress(req);
    const fields = readFields(req, route);
    const context = {
      at: now,
      route: route.label,
      ip: address.ip,
      ipSource: address.source,
      userAgent: headerValue(req, "user-agent").slice(0, MAX_USER_AGENT_LENGTH),
      status: res.statusCode
    };

    if (route.label === "/entry/upload") {
      // Masked the same way as in /get: the real GUID never reaches a row.
      const userGuid = stringField(fields.userGuid).trim();
      context.guidRef = userGuid ? this.maskGuid(stringField(fields.publicKey).trim(), userGuid) : "";
    }

    this.count(context, "c", contractDimension(req, route, fields, res.statusCode));
    this.count(context, "addr", address.shape);
    this.noteDistinctIp(context);

    if (route.hasKey) {
      this.observePublicKey(context, fields);
    }
    if (route.rate) {
      this.countRate(context, "ip", context.ip || "unknown", this.settings[route.rate], "");
    }
    if (route.label === "/authorize") {
      this.registerIssuedGuid(context, res.locals.observeIssuedGuid);
    } else if (route.label === "/entry/upload") {
      this.observeUpload(context, fields, res.locals.observeEntryExisted);
    } else if (route.label === "/player-profile") {
      this.observeProfile(context, fields);
    }

    this.maintain(now, false);
  }

  observePublicKey(context, fields) {
    const publicKey = stringField(fields.publicKey).trim();
    if (!publicKey) {
      return;
    }
    const expected = this.settings.expectedPublicKeys.includes(publicKey);
    context.keyPrefix = publicKey.slice(0, 8);
    this.count(context, "key", `${context.keyPrefix}:${publicKey.length}:${expected ? "expected" : "unexpected"}`);
    if (!expected) {
      this.record(context, "unexpected_public_key", { length: publicKey.length });
    }
  }

  // Writes the registry row for a GUID that /authorize just returned.
  registerIssuedGuid(context, guid) {
    if (context.status !== 200 || typeof guid !== "string" || !guid) {
      return;
    }
    if (this.issuedThisHour >= this.settings.maxIssuedPerHour) {
      this.count(context, "registry", "skipped_hourly_cap");
      return;
    }
    this.issuedThisHour += 1;
    this.count(context, "registry", "issued");
    this.enqueue("issued guid insert", () =>
      this.storage.insertIssuedGuid({
        guid,
        issuedAt: context.at,
        ip: context.ip,
        ipSource: context.ipSource,
        userAgent: context.userAgent.slice(0, MAX_ISSUED_USER_AGENT_LENGTH)
      })
    );
  }

  observeUpload(context, fields, entryExisted) {
    const userGuid = stringField(fields.userGuid).trim();
    const uuidShaped = UUID_PATTERN.test(userGuid);

    // --- score ---
    const score = parseStrictInteger(fields.score);
    if (score === null) {
      this.count(context, "score", "not_integer");
      this.record(context, "score_out_of_bounds", { problem: "not_integer", value: clip(fields.score, 30) });
    } else if (score < 0) {
      this.count(context, "score", "negative");
      this.record(context, "score_out_of_bounds", { problem: "negative", value: score });
    } else {
      this.count(context, "score", `digits_${String(score).length}`);
      if (score > this.settings.maxScore) {
        this.record(context, "score_out_of_bounds", { problem: "above_max", value: score, max: this.settings.maxScore });
      }
    }

    // --- username (lengths and the score relation only, never the name) ---
    const username = stringField(fields.username).trim();
    const shape = describeUsername(username, score);
    this.count(context, "username", shape.relation);
    if (["shape_mismatch", "mismatch", "score_not_integer"].includes(shape.relation)) {
      this.record(context, "username_shape", shape);
    }
    if (username.length > this.settings.maxUsernameLength) {
      this.record(context, "username_too_long", { length: username.length, limit: this.settings.maxUsernameLength });
    }

    // --- extra: the shipped game always sends exactly one space ---
    const extraPresent = typeof fields.extra === "string";
    const extra = extraPresent ? fields.extra : "";
    if (extra === " ") {
      this.count(context, "extra", "single_space");
    } else {
      const value = extra.trim().toLowerCase().slice(0, 20);
      this.count(context, "extra", extraPresent ? `value:${JSON.stringify(value)}` : "absent");
      this.record(context, "extra_unexpected", { value, length: extra.length, present: extraPresent });
    }

    // --- guid ---
    if (!uuidShaped) {
      this.record(context, "guid_shape", { length: userGuid.length, present: Boolean(userGuid) });
    }
    if (!userGuid) {
      this.count(context, "guid", "missing");
      return;
    }
    this.countRate(context, "guid", context.guidRef, this.settings.rateUploadGuid, context.guidRef);
    this.checkGuidIssued(context, userGuid, uuidShaped, entryExisted);
  }

  // Was this GUID handed out by /authorize? Runs after the response is sent:
  // an in-memory hit answers immediately, otherwise one queued registry read.
  checkGuidIssued(context, userGuid, uuidShaped, entryExisted) {
    if (this.recentGuids.has(userGuid)) {
      this.count(context, "guid", "issued");
      return;
    }
    const existed = typeof entryExisted === "boolean" ? entryExisted : null;
    this.enqueue("issued guid lookup", async () => {
      let issued;
      try {
        issued = await this.storage.isGuidIssued(userGuid);
      } catch (error) {
        this.count(context, "guid", "lookup_failed");
        throw error;
      }
      if (issued) {
        this.count(context, "guid", "issued");
        return;
      }
      this.count(
        context,
        "guid",
        existed === null ? "not_issued_upload_failed" : existed ? "not_issued_existing_entry" : "not_issued_new_entry"
      );
      this.record(context, "guid_not_issued", { uuidShaped, entryExisted: existed });
    });
  }

  observeProfile(context, fields) {
    const name = stringField(fields.name).trim();
    const email = stringField(fields.email).trim();
    const country = stringField(fields.country).trim();
    const detail = {
      nameLength: name.length,
      emailLength: email.length,
      countryLength: country.length,
      emailValid: EMAIL_PATTERN.test(email),
      nameTooLong: name.length > PROFILE_NAME_LIMIT,
      emailTooLong: email.length > PROFILE_EMAIL_LIMIT,
      countryTooLong: country.length > PROFILE_COUNTRY_LIMIT,
      hasUserGuid: Boolean(stringField(fields.userGuid).trim())
    };
    if (!detail.emailValid || detail.nameTooLong || detail.emailTooLong || detail.countryTooLong) {
      this.record(context, "profile_fields", detail);
    }
  }

  // Fixed-window counter. Records ONE would_rate_limit row when a window first
  // goes over its limit; later requests in that window only bump an aggregate.
  countRate(context, scope, key, limit, guidRef) {
    if (!limit || !key) {
      return;
    }
    const counterKey = `${context.route}|${scope}|${key}`;
    let counter = this.rateCounters.get(counterKey);
    if (!counter || context.at >= counter.start + counter.windowSeconds) {
      this.rateCounters.delete(counterKey);
      this.makeRoomForRateCounter(context.at);
      counter = { start: context.at, count: 0, windowSeconds: limit.windowSeconds };
      this.rateCounters.set(counterKey, counter);
    }
    counter.count += 1;

    if (counter.count <= limit.max) {
      return;
    }
    this.count(context, "rate", `${scope}:requests_over_limit`);
    if (counter.count === limit.max + 1) {
      this.count(context, "rate", `${scope}:windows_triggered`);
      // guid_ref is set only on the per-GUID rows, which tells the scopes apart.
      this.record(
        { ...context, guidRef },
        "would_rate_limit",
        { scope, count: counter.count, limit: limit.max, windowSeconds: limit.windowSeconds }
      );
    }
  }

  // Keeps the counter map bounded: drop expired windows first, then the oldest.
  makeRoomForRateCounter(now) {
    if (this.rateCounters.size < this.settings.maxRateKeys) {
      return;
    }
    this.sweepRateCounters(now);
    while (this.rateCounters.size >= this.settings.maxRateKeys) {
      this.rateCounters.delete(this.rateCounters.keys().next().value);
    }
  }

  sweepRateCounters(now) {
    for (const [key, counter] of this.rateCounters) {
      if (now >= counter.start + counter.windowSeconds) {
        this.rateCounters.delete(key);
      }
    }
  }

  rememberGuid(guid, at) {
    this.recentGuids.set(guid, at);
    while (this.recentGuids.size > this.settings.maxRecentGuids) {
      this.recentGuids.delete(this.recentGuids.keys().next().value);
    }
  }

  noteDistinctIp(context) {
    if (!context.ip) {
      return;
    }
    let seen = this.seenIps.get(context.route);
    if (!seen) {
      seen = new Set();
      this.seenIps.set(context.route, seen);
    }
    if (seen.has(context.ip)) {
      return;
    }
    if (seen.size >= this.settings.maxDistinctIps) {
      return; // capped: the stored count is then a floor, not exact
    }
    seen.add(context.ip);
    this.count(context, "ips", "distinct");
  }

  // Adds one to an hourly aggregate. `kind` groups related dimensions and has
  // its own cap on distinct values per route per hour; overflow goes to "other".
  count(context, kind, dimension) {
    const hour = hourOf(context.at);
    let value = String(dimension).slice(0, MAX_DIMENSION_LENGTH);

    if (hour === this.hour) {
      const seenKey = `${context.route}\n${kind}`;
      let seen = this.seenDimensions.get(seenKey);
      if (!seen) {
        seen = new Set();
        this.seenDimensions.set(seenKey, seen);
      }
      if (!seen.has(value)) {
        const cap = kind === "c" ? this.settings.maxDimensions : (KIND_CAPS[kind] || DEFAULT_KIND_CAP);
        if (seen.size >= cap) {
          value = "other";
        } else {
          seen.add(value);
        }
      }
    }

    this.addPending(hour, context.route, `${kind}|${value}`, 1);
  }

  addPending(hour, route, dimKey, amount) {
    const key = `${hour}\n${route}\n${dimKey}`;
    const current = this.pendingTraffic.get(key);
    if (current === undefined && this.pendingTraffic.size >= this.settings.maxPendingTraffic) {
      return;
    }
    this.pendingTraffic.set(key, (current || 0) + amount);
  }

  // Stores one observation row and prints the same redacted line. Capped per
  // reason per hour; the row that hits the cap is followed by one summary row.
  record(context, reason, detail) {
    this.count(context, "obs", reason);

    const written = this.rowsThisHour.get(reason) || 0;
    if (written > this.settings.maxRowsPerHour) {
      this.count(context, "obs_suppressed", reason);
      return;
    }
    this.rowsThisHour.set(reason, written + 1);

    const capReached = written === this.settings.maxRowsPerHour;
    if (capReached) {
      this.count(context, "obs_suppressed", reason);
    }
    const row = {
      at: context.at,
      route: context.route,
      reason: capReached ? "observations_suppressed" : reason,
      ip: context.ip,
      ipSource: context.ipSource,
      userAgent: context.userAgent,
      keyPrefix: context.keyPrefix || "",
      guidRef: context.guidRef || "",
      detail: encodeDetail(
        capReached
          ? { suppressedReason: reason, capPerHour: this.settings.maxRowsPerHour }
          : { ...detail, status: context.status }
      )
    };

    console.log(`[observe] ${JSON.stringify(row)}`);
    this.enqueue("observation insert", () => this.storage.insertSecurityObservation(row));
  }

  // Flush + prune when due. `force` is the timer path.
  maintain(now, force) {
    if (force || now - this.lastFlushAt >= this.settings.flushIntervalSeconds) {
      this.sweepRateCounters(now);
      this.flushTraffic();
    }
    if (now - this.lastPruneAt >= this.settings.pruneIntervalSeconds) {
      this.lastPruneAt = now;
      const cutoff = now - this.settings.retentionSeconds;
      this.enqueue("prune", () => this.storage.pruneObservationData(cutoff));
    }
  }

  // Moves the in-memory aggregate into traffic_hourly (upsert-increment). On a
  // failed write the counts go back into memory for the next attempt. The
  // returned promise always resolves.
  flushTraffic() {
    return new Promise((resolve) => {
      try {
        this.lastFlushAt = this.now();
        const rows = [];
        for (const [key, count] of this.pendingTraffic) {
          const [hour, route, dimKey] = key.split("\n");
          rows.push({ hour: Number(hour), route, dimKey, count });
        }
        this.pendingTraffic.clear();
        if (!this.enabled || rows.length === 0) {
          resolve();
          return;
        }

        const done = (ok) => {
          if (!ok) {
            this.restorePending(rows);
          }
          resolve();
        };
        this.enqueue("traffic flush", () => this.storage.incrementTrafficHourly(rows), done);
      } catch (error) {
        this.noteHandlerError(error);
        resolve();
      }
    });
  }

  // Puts unflushed counts back, skipping hours too old to be worth retrying.
  restorePending(rows) {
    try {
      const oldestHour = hourOf(this.now()) - 6 * HOUR_SECONDS;
      for (const row of rows) {
        if (row.hour >= oldestHour) {
          this.addPending(row.hour, row.route, row.dimKey, row.count);
        }
      }
    } catch (error) {
      this.noteHandlerError(error);
    }
  }

  // Bounded background queue for every observation read/write. Nothing awaits
  // it from a request. When the queue is full the job is dropped and counted.
  enqueue(label, task, done) {
    if (!this.enabled || this.queue.length >= this.settings.maxQueue) {
      this.stats.dropped += 1;
      if (done) {
        done(false);
      }
      return;
    }
    this.stats.queued += 1;
    this.queue.push({ label, task, done });
    this.drain();
  }

  drain() {
    while (this.inFlight < QUEUE_CONCURRENCY && this.queue.length > 0) {
      const job = this.queue.shift();
      this.inFlight += 1;
      Promise.resolve()
        .then(() => job.task())
        .then(() => true, (error) => {
          this.noteWriteFailure(job.label, error);
          return false;
        })
        .then((ok) => {
          this.inFlight -= 1;
          try {
            if (job.done) {
              job.done(ok);
            }
          } catch (error) {
            this.noteHandlerError(error);
          }
          this.drain();
        });
    }
  }

  // One log line per job type per minute at most, so a database outage cannot
  // flood the logs.
  noteWriteFailure(label, error) {
    this.stats.writeErrors += 1;
    const now = this.now();
    const last = this.lastFailureLogAt.get(label);
    if (last !== undefined && now - last < FAILURE_LOG_INTERVAL_SECONDS) {
      return;
    }
    this.lastFailureLogAt.set(label, now);
    const message = String(error && error.message ? error.message : error).slice(0, 200);
    console.error(`[observe] ${label} failed: ${message}`);
  }

  noteHandlerError(error) {
    try {
      this.stats.handlerErrors += 1;
      this.noteWriteFailure("handler", error);
    } catch (ignored) {
      // Nothing may escape from observation code.
    }
  }

  // --- admin reads (awaited: these are admin requests, not game requests) ---

  async listObservations(query) {
    const parsedLimit = Number.parseInt(query.limit, 10);
    const limit = Number.isFinite(parsedLimit) && parsedLimit > 0
      ? Math.min(parsedLimit, MAX_OBSERVATION_LIMIT)
      : DEFAULT_OBSERVATION_LIMIT;

    const rows = await this.storage.listSecurityObservations({
      reason: stringField(query.reason).trim(),
      route: stringField(query.route).trim(),
      since: parseSince(query.since, 0),
      limit
    });
    return rows.map((row) => ({ ...row, detail: decodeDetail(row.detail) }));
  }

  async getSummary(query) {
    const now = this.now();
    const since = parseSince(query.since, now - DEFAULT_SUMMARY_SECONDS);

    // Include the last few minutes still held in memory, without waiting long.
    await Promise.race([this.flushTraffic(), delay(1500)]);

    const [observations, traffic, issued, scoreRange, hourly] = await Promise.all([
      this.storage.summarizeSecurityObservations(since),
      this.storage.summarizeTraffic(since),
      this.storage.countIssuedGuids(since),
      this.storage.getUploadScoreRange(since).catch(() => null),
      toBool(query.hourly) ? this.storage.listTrafficHourly(since, MAX_HOURLY_ROWS) : null
    ]);

    const summary = buildSummary({ observations, traffic, issued, scoreRange, settings: this.settings });
    return {
      enabled: this.enabled,
      since,
      until: now,
      expectedPublicKeys: this.settings.expectedPublicKeys.map(describeKey),
      limits: {
        maxScore: this.settings.maxScore,
        maxUsernameLength: this.settings.maxUsernameLength,
        maxRowsPerHour: this.settings.maxRowsPerHour,
        maxIssuedPerHour: this.settings.maxIssuedPerHour
      },
      ...summary,
      ...(hourly ? { trafficHourly: hourly } : {}),
      process: { ...this.stats, queueLength: this.queue.length, inFlight: this.inFlight }
    };
  }
}

// Turns the grouped rows into the report shape. Everything is derived from the
// stored aggregates, so it survives restarts.
function buildSummary({ observations, traffic, issued, scoreRange, settings }) {
  const byRoute = {};
  const routeBucket = (route) => {
    if (!byRoute[route]) {
      byRoute[route] = {};
    }
    return byRoute[route];
  };

  for (const row of traffic) {
    const separator = row.dimKey.indexOf("|");
    const kind = separator < 0 ? "c" : row.dimKey.slice(0, separator);
    const value = separator < 0 ? row.dimKey : row.dimKey.slice(separator + 1);
    const bucket = routeBucket(row.route);
    if (!bucket[kind]) {
      bucket[kind] = {};
    }
    bucket[kind][value] = (bucket[kind][value] || 0) + row.count;
  }

  const kindOf = (route, kind) => (byRoute[route] && byRoute[route][kind]) || {};
  const sum = (values) => Object.values(values).reduce((total, value) => total + value, 0);

  // Client contract: per route, marginal counts for each field of the tuple.
  const contract = {};
  const publicKeys = [];
  const clientAddress = {};
  for (const route of Object.keys(byRoute).sort()) {
    const tuples = kindOf(route, "c");
    const fields = { contentType: {}, origin: {}, unityVersion: {}, userAgent: {}, userGuid: {}, status: {} };
    const names = { ct: "contentType", o: "origin", uv: "unityVersion", ua: "userAgent", g: "userGuid", s: "status" };
    for (const [tuple, count] of Object.entries(tuples)) {
      for (const part of tuple.split(";")) {
        const equals = part.indexOf("=");
        const name = names[part.slice(0, equals)];
        if (equals > 0 && name) {
          const value = part.slice(equals + 1);
          fields[name][value] = (fields[name][value] || 0) + count;
        }
      }
    }
    contract[route] = { requests: sum(tuples), ...fields, combinations: tuples };

    for (const [value, count] of Object.entries(kindOf(route, "key"))) {
      const [keyPrefix, length, verdict] = value.split(":");
      publicKeys.push({ route, keyPrefix, length: Number(length) || 0, expected: verdict === "expected", count });
    }

    clientAddress[route] = {
      // Floor of the per-hour distinct counts added up (capped per hour).
      distinctClientsPerHourSummed: kindOf(route, "ips").distinct || 0,
      shapes: kindOf(route, "addr")
    };
  }

  const guid = kindOf("/entry/upload", "guid");
  const issuedCount = guid.issued || 0;
  const notIssued = (guid.not_issued_existing_entry || 0) +
    (guid.not_issued_new_entry || 0) +
    (guid.not_issued_upload_failed || 0);
  const checked = issuedCount + notIssued;

  const rate = [];
  const rateRoutes = [
    ["/authorize", "ip", settings.rateAuthorize],
    ["/entry/upload", "ip", settings.rateUpload],
    ["/entry/upload", "guid", settings.rateUploadGuid],
    ["/player-profile", "ip", settings.rateProfile]
  ];
  for (const [route, scope, limit] of rateRoutes) {
    const counts = kindOf(route, "rate");
    const rows = observations.filter((row) =>
      row.reason === "would_rate_limit" && row.route === route && row.hasGuidRef === (scope === "guid"));
    rate.push({
      route,
      scope,
      limit: limit.max,
      windowSeconds: limit.windowSeconds,
      requests: sum(kindOf(route, "c")),
      windowsTriggered: counts[`${scope}:windows_triggered`] || 0,
      requestsOverLimit: counts[`${scope}:requests_over_limit`] || 0,
      distinctClients: rows.reduce(
        (total, row) => total + (scope === "guid" ? row.distinctGuidRefs : row.distinctIps), 0)
    });
  }

  return {
    observations,
    contract,
    publicKeys,
    uploads: {
      requests: sum(kindOf("/entry/upload", "c")),
      guidIssued: issuedCount,
      guidNotIssued: notIssued,
      guidNotIssuedExistingEntry: guid.not_issued_existing_entry || 0,
      guidNotIssuedNewEntry: guid.not_issued_new_entry || 0,
      guidNotIssuedUploadFailed: guid.not_issued_upload_failed || 0,
      guidMissing: guid.missing || 0,
      guidLookupFailed: guid.lookup_failed || 0,
      issuedShare: checked > 0 ? Math.round((issuedCount / checked) * 10000) / 10000 : null,
      usernameScoreRelation: kindOf("/entry/upload", "username"),
      extraValues: kindOf("/entry/upload", "extra"),
      scoreShape: kindOf("/entry/upload", "score"),
      // Exact range of the scores actually stored by game uploads (entry_history).
      storedScoreRange: scoreRange
    },
    issuedGuids: {
      ...issued,
      skippedByHourlyCap: kindOf("/authorize", "registry").skipped_hourly_cap || 0
    },
    rate,
    clientAddress,
    observationTotals: Object.fromEntries(
      Object.keys(byRoute).sort().map((route) => [route, {
        recorded: kindOf(route, "obs"),
        suppressed: kindOf(route, "obs_suppressed")
      }])
    )
  };
}

// --- settings ----------------------------------------------------------------

// Merges the optional config over the defaults; anything missing or malformed
// falls back, so the service runs unchanged with no observe config at all.
function resolveSettings(input) {
  const source = input && typeof input === "object" ? input : {};
  const settings = { ...DEFAULTS };

  if (source.enabled === false) {
    settings.enabled = false;
  }
  const expectedKeys = Array.isArray(source.expectedPublicKeys)
    ? source.expectedPublicKeys.filter((key) => typeof key === "string" && key)
    : [];
  if (expectedKeys.length > 0) {
    settings.expectedPublicKeys = expectedKeys;
  }
  for (const name of Object.keys(DEFAULTS)) {
    const fallback = DEFAULTS[name];
    if (typeof fallback === "number" && Number.isInteger(source[name]) && source[name] > 0) {
      settings[name] = source[name];
    } else if (fallback && typeof fallback === "object" && !Array.isArray(fallback)) {
      settings[name] = resolveRateLimit(source[name], fallback);
    }
  }
  if (typeof source.now === "function") {
    settings.now = source.now; // test clock
  }
  return settings;
}

// Accepts { max, windowSeconds } or the env form "30/600".
function resolveRateLimit(value, fallback) {
  let max;
  let windowSeconds;
  if (typeof value === "string") {
    const match = /^\s*(\d+)\s*\/\s*(\d+)\s*$/.exec(value);
    if (match) {
      max = Number(match[1]);
      windowSeconds = Number(match[2]);
    }
  } else if (value && typeof value === "object") {
    max = value.max;
    windowSeconds = value.windowSeconds;
  }
  return Number.isInteger(max) && max > 0 && Number.isInteger(windowSeconds) && windowSeconds > 0
    ? { max, windowSeconds }
    : { ...fallback };
}

// --- request helpers ---------------------------------------------------------

// Express routes case-insensitively and ignores a trailing slash; do the same.
function matchRoute(req) {
  const rawPath = typeof req.path === "string" ? req.path : "";
  const path = rawPath.length > 1 ? rawPath.replace(/\/+$/, "").toLowerCase() : rawPath;
  const key = `${req.method} ${path}`;
  return Object.prototype.hasOwnProperty.call(ROUTES, key) ? ROUTES[key] : null;
}

function readFields(req, route) {
  const fields = route.fields ? req[route.fields] : null;
  return fields && typeof fields === "object" ? fields : {};
}

function headerValue(req, name) {
  const value = req.headers[name];
  return typeof value === "string" ? value : "";
}

function stringField(value) {
  return typeof value === "string" ? value : "";
}

// Best-effort client address WITHOUT touching `trust proxy`: x-real-ip, else
// the LAST x-forwarded-for entry (the one the nearest proxy appended), else the
// socket. `shape` describes which headers were present and whether they agree,
// so a week of data shows which source production can rely on.
function resolveClientAddress(req) {
  const realIp = cleanAddress(headerValue(req, "x-real-ip"));
  const forwarded = headerValue(req, "x-forwarded-for")
    .split(",")
    .map(cleanAddress)
    .filter(Boolean);
  const first = forwarded[0] || "";
  const last = forwarded[forwarded.length - 1] || "";
  const socket = cleanAddress((req.socket && req.socket.remoteAddress) || "");

  let ip = socket;
  let source = "socket";
  if (realIp) {
    ip = realIp;
    source = "x-real-ip";
  } else if (last) {
    ip = last;
    source = "x-forwarded-for-last";
  }

  let agreement = "-";
  if (realIp && forwarded.length > 0) {
    const matchesFirst = realIp === first;
    const matchesLast = realIp === last;
    agreement = matchesFirst && matchesLast ? "both" : matchesFirst ? "first" : matchesLast ? "last" : "none";
  }

  return {
    ip,
    source,
    shape: `src=${source};xri=${realIp ? 1 : 0};xff=${Math.min(forwarded.length, 4)};xri_eq_xff=${agreement};sock=${classifyAddress(socket)}`
  };
}

function cleanAddress(value) {
  return String(value).trim().toLowerCase().replace(/^::ffff:/, "").slice(0, MAX_IP_LENGTH);
}

function classifyAddress(address) {
  if (!address) {
    return "none";
  }
  if (address === "::1" || address.startsWith("127.")) {
    return "loopback";
  }
  if (address.includes(":")) {
    return /^f[cd]/.test(address) || address.startsWith("fe80") ? "private6" : "public6";
  }
  const octets = address.split(".").map(Number);
  if (octets[0] === 10 || (octets[0] === 192 && octets[1] === 168) || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31)) {
    return "private";
  }
  if (octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127) {
    return "cgnat";
  }
  return "public";
}

// One compact tuple per request: content-type family, Origin host, Unity
// version, user-agent family, userGuid presence, response status.
function contractDimension(req, route, fields, status) {
  const hasGuid = route.fields ? (stringField(fields.userGuid).trim() ? "1" : "0") : "-";
  return [
    `ct=${contentTypeFamily(headerValue(req, "content-type"))}`,
    `o=${originHost(headerValue(req, "origin"))}`,
    `uv=${token(headerValue(req, "x-unity-version"), 20) || "-"}`,
    `ua=${userAgentFamily(headerValue(req, "user-agent"))}`,
    `g=${hasGuid}`,
    `s=${status}`
  ].join(";");
}

function contentTypeFamily(contentType) {
  const value = contentType.toLowerCase();
  if (!value) {
    return "none";
  }
  if (value.startsWith("multipart/form-data")) {
    return "multipart";
  }
  if (value.startsWith("application/json")) {
    return "json";
  }
  if (value.startsWith("application/x-www-form-urlencoded")) {
    return "urlencoded";
  }
  return "other";
}

function originHost(origin) {
  if (!origin) {
    return "-";
  }
  try {
    return token(new URL(origin).host, 60) || "invalid";
  } catch (error) {
    return "invalid";
  }
}

// Browsers collapse to "browser:<engine>:<platform>"; anything else keeps its
// first product token (e.g. "UnityPlayer/2022.3.10f1"), truncated.
function userAgentFamily(userAgent) {
  if (!userAgent) {
    return "none";
  }
  if (userAgent.startsWith("Mozilla/")) {
    const engine = /Edg\//.test(userAgent) ? "Edge"
      : /Firefox\//.test(userAgent) ? "Firefox"
        : /Chrome\/|CriOS\//.test(userAgent) ? "Chrome"
          : /Safari\//.test(userAgent) ? "Safari"
            : "other";
    const platform = /Android/.test(userAgent) ? "Android"
      : /iPhone|iPad|iPod/.test(userAgent) ? "iOS"
        : /Windows/.test(userAgent) ? "Windows"
          : /Macintosh/.test(userAgent) ? "Mac"
            : /Linux/.test(userAgent) ? "Linux"
              : "other";
    return `browser:${engine}:${platform}`;
  }
  return token(userAgent.split(/[\s(]/)[0], 40) || "other";
}

// Keeps only characters that are safe inside a dimension key.
function token(value, maxLength) {
  return String(value).replace(/[^A-Za-z0-9._:/+-]/g, "").slice(0, maxLength);
}

// --- field helpers -----------------------------------------------------------

// Strict: the whole value must be an integer (the service itself is laxer and
// accepts "12abc" as 12). Returns null when it is not.
function parseStrictInteger(value) {
  if (typeof value === "number") {
    return Number.isSafeInteger(value) ? value : null;
  }
  if (typeof value !== "string" || !/^\s*-?\d{1,15}\s*$/.test(value)) {
    return null;
  }
  return Number(value);
}

// The game packs "name-country-score" into username. Works out how the trailing
// number relates to the score field (the game sends displayed value x 100) and
// reports lengths only.
function describeUsername(username, score) {
  const detail = { relation: "shape_mismatch", usernameLength: username.length, parts: username.split("-").length };
  const match = USERNAME_PATTERN.exec(username);
  if (!match) {
    return detail;
  }

  const tail = Number(match[3].replace(",", "."));
  detail.nameLength = match[1].length;
  detail.countryLength = match[2].length;
  detail.tail = match[3].slice(0, 20);
  if (score === null) {
    detail.relation = "score_not_integer";
    return detail;
  }

  detail.score = score;
  const hundredth = Math.round(tail * 100) === score;
  const raw = tail === score;
  if (hundredth && raw) {
    detail.relation = "both_zero";
  } else if (hundredth) {
    detail.relation = "score_div_100";
  } else if (raw) {
    detail.relation = "raw_score";
  } else if (tail === Math.trunc(score / 100)) {
    detail.relation = "score_div_100_truncated";
  } else if (tail === Math.round(score / 100)) {
    detail.relation = "score_div_100_rounded";
  } else {
    detail.relation = "mismatch";
  }
  return detail;
}

function clip(value, maxLength) {
  return String(value === undefined ? "" : value).slice(0, maxLength);
}

function describeKey(publicKey) {
  return { keyPrefix: publicKey.slice(0, 8), length: publicKey.length };
}

function encodeDetail(detail) {
  const text = JSON.stringify(detail);
  return text.length <= MAX_DETAIL_LENGTH ? text : JSON.stringify({ truncated: true });
}

function decodeDetail(text) {
  try {
    return JSON.parse(text);
  } catch (error) {
    return text;
  }
}

// `since` is unix seconds, or anything Date.parse understands.
function parseSince(value, fallback) {
  if (typeof value !== "string" || !value.trim()) {
    return fallback;
  }
  if (/^\d+$/.test(value.trim())) {
    return Number(value.trim());
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? Math.floor(parsed / 1000) : fallback;
}

function hourOf(unixSeconds) {
  return Math.floor(unixSeconds / HOUR_SECONDS) * HOUR_SECONDS;
}

function toBool(value) {
  return value === true || value === "1" || value === "true";
}

function delay(milliseconds) {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds).unref();
  });
}

module.exports = {
  SecurityObserver,
  LIVE_PUBLIC_KEY
};
