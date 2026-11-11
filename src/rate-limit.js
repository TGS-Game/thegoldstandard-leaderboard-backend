// Small in-memory fixed-window rate limiter (no dependency). One process, one
// replica: counters live in memory and reset on restart, which is fine for
// limits measured in minutes.
//
// Each limited route has a per-IP limit and a global limit (all callers
// together). Going over either answers 429 with Retry-After. One log line is
// printed when a window first goes over, never one per request.

const MAX_KEYS = 20000;

class RateLimiter {
  constructor({ now } = {}) {
    this.now = typeof now === "function" ? now : () => Date.now();
    this.windows = new Map(); // key -> { start, count }
  }

  // Returns 0 when allowed, else the seconds until the window resets.
  hit(key, limit) {
    const now = this.now();
    const windowMs = limit.windowSeconds * 1000;
    let entry = this.windows.get(key);
    if (!entry || now >= entry.start + windowMs) {
      this.windows.delete(key);
      this.makeRoom(now);
      entry = { start: now, count: 0, windowMs };
      this.windows.set(key, entry);
    }
    entry.count += 1;
    if (entry.count <= limit.max) {
      return 0;
    }
    entry.firstOver = entry.count === limit.max + 1;
    return Math.max(1, Math.ceil((entry.start + windowMs - now) / 1000));
  }

  wasFirstOver(key) {
    const entry = this.windows.get(key);
    return Boolean(entry && entry.firstOver);
  }

  makeRoom(now) {
    if (this.windows.size < MAX_KEYS) {
      return;
    }
    for (const [key, entry] of this.windows) {
      if (now >= entry.start + entry.windowMs) {
        this.windows.delete(key);
      }
    }
    while (this.windows.size >= MAX_KEYS) {
      this.windows.delete(this.windows.keys().next().value);
    }
  }
}

// Express middleware for one route. `limits` is { perIp, global }, each
// { max, windowSeconds } or null.
function rateLimitMiddleware(limiter, name, limits) {
  return (req, res, next) => {
    const ip = req.ip || (req.socket && req.socket.remoteAddress) || "unknown";
    // Per-IP first, so one noisy client does not eat the global budget with
    // requests that are rejected anyway.
    const checks = [];
    if (limits.perIp) {
      checks.push({ key: `${name}|ip|${ip}`, limit: limits.perIp, scope: "ip" });
    }
    if (limits.global) {
      checks.push({ key: `${name}|global`, limit: limits.global, scope: "global" });
    }
    for (const check of checks) {
      const retryAfter = limiter.hit(check.key, check.limit);
      if (retryAfter > 0) {
        if (limiter.wasFirstOver(check.key)) {
          console.warn(
            `[rate-limit] ${name} over the ${check.scope} limit ` +
            `(${check.limit.max} per ${check.limit.windowSeconds}s)` +
            (check.scope === "ip" ? ` for ip=${JSON.stringify(String(ip).slice(0, 64))}` : "") +
            `; answering 429 until the window resets.`
          );
        }
        res.setHeader("Retry-After", String(retryAfter));
        res.status(429).type("text/plain").send("Too many requests.");
        return;
      }
    }
    next();
  };
}

// "<max>/<window seconds>" -> { max, windowSeconds }; "off" or "0" -> null.
function parseLimit(value, fallback) {
  if (typeof value !== "string" || !value.trim()) {
    return fallback;
  }
  const text = value.trim().toLowerCase();
  if (["off", "0", "none"].includes(text)) {
    return null;
  }
  const match = /^(\d+)\s*\/\s*(\d+)$/.exec(text);
  if (!match || Number(match[1]) <= 0 || Number(match[2]) <= 0) {
    console.warn(`[rate-limit] ignoring malformed limit ${JSON.stringify(value)}; using the default.`);
    return fallback;
  }
  return { max: Number(match[1]), windowSeconds: Number(match[2]) };
}

// Defaults are roughly 20x what real players do (7 days of logs, Nov 2026:
// ~76 /authorize, ~37 /player-profile, ~28 /entry/upload in a week, with at
// most ~14 uploads in 10 minutes from one office IP).
const DEFAULT_LIMITS = {
  authorize: { perIp: { max: 60, windowSeconds: 600 }, global: { max: 600, windowSeconds: 60 } },
  upload: { perIp: { max: 60, windowSeconds: 600 }, global: { max: 300, windowSeconds: 60 } },
  profile: { perIp: { max: 20, windowSeconds: 3600 }, global: { max: 60, windowSeconds: 600 } },
  adminLogin: { perIp: { max: 10, windowSeconds: 900 }, global: { max: 50, windowSeconds: 900 } }
};

const ENV_NAMES = {
  authorize: "AUTHORIZE",
  upload: "UPLOAD",
  profile: "PROFILE",
  adminLogin: "ADMIN_LOGIN"
};

function resolveRateLimits(env) {
  const source = env || {};
  const enabled = !["off", "0", "false", "no"].includes(String(source.RATE_LIMITS || "").trim().toLowerCase());
  const limits = {};
  for (const [name, defaults] of Object.entries(DEFAULT_LIMITS)) {
    limits[name] = {
      perIp: parseLimit(source[`RATE_${ENV_NAMES[name]}_IP`], defaults.perIp),
      global: parseLimit(source[`RATE_${ENV_NAMES[name]}_GLOBAL`], defaults.global)
    };
  }
  return { enabled, limits };
}

function describeRateLimits(rateLimits) {
  if (!rateLimits || !rateLimits.enabled) {
    return "Rate limits: OFF (RATE_LIMITS=off).";
  }
  const parts = Object.entries(rateLimits.limits).map(([name, value]) => {
    const fmt = (limit) => (limit ? `${limit.max}/${limit.windowSeconds}s` : "off");
    return `${name} ip ${fmt(value.perIp)} global ${fmt(value.global)}`;
  });
  return `Rate limits: on (${parts.join("; ")}).`;
}

// TRUST_PROXY: "off"/"false"/"0" -> false, a number -> that many hops, any
// other text is passed to Express as is. Unset: 1 hop on Railway (its edge
// proxy appends the real client address as the LAST X-Forwarded-For entry),
// false elsewhere so a local client cannot fake its address.
function resolveTrustProxy(env) {
  const source = env || {};
  const raw = typeof source.TRUST_PROXY === "string" ? source.TRUST_PROXY.trim() : "";
  if (raw) {
    if (["off", "false", "0", "no"].includes(raw.toLowerCase())) {
      return false;
    }
    if (/^\d+$/.test(raw)) {
      return Number(raw);
    }
    return raw;
  }
  const onRailway = Boolean(source.RAILWAY_ENVIRONMENT_NAME || source.RAILWAY_ENVIRONMENT || source.RAILWAY_PROJECT_ID);
  return onRailway ? 1 : false;
}

module.exports = {
  RateLimiter,
  rateLimitMiddleware,
  resolveRateLimits,
  resolveTrustProxy,
  describeRateLimits,
  parseLimit,
  DEFAULT_LIMITS
};
