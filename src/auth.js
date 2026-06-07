const crypto = require("crypto");

// Session cookie name. Kept distinct so it never collides with anything else.
const SESSION_COOKIE_NAME = "tgs_admin_session";

// --- base64url helpers ------------------------------------------------------

function base64UrlEncode(buffer) {
  return Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64UrlDecodeToBuffer(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(normalized, "base64");
}

// Constant-time string comparison that never throws on length mismatch.
function timingSafeEqualStrings(a, b) {
  const bufferA = Buffer.from(String(a));
  const bufferB = Buffer.from(String(b));
  if (bufferA.length !== bufferB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufferA, bufferB);
}

// --- Session cookie (signed, our own format) --------------------------------
// Format: base64url(JSON payload) "." base64url(HMAC-SHA256 of the payload part).

function signSession(payload, secret) {
  const payloadPart = base64UrlEncode(JSON.stringify(payload));
  const signature = crypto
    .createHmac("sha256", secret)
    .update(payloadPart)
    .digest();
  return `${payloadPart}.${base64UrlEncode(signature)}`;
}

function verifySession(token, secret, nowSeconds) {
  if (!token || typeof token !== "string") {
    return null;
  }

  const parts = token.split(".");
  if (parts.length !== 2) {
    return null;
  }

  const [payloadPart, signaturePart] = parts;
  const expectedSignature = base64UrlEncode(
    crypto.createHmac("sha256", secret).update(payloadPart).digest()
  );

  if (!timingSafeEqualStrings(signaturePart, expectedSignature)) {
    return null;
  }

  let payload;
  try {
    payload = JSON.parse(base64UrlDecodeToBuffer(payloadPart).toString("utf8"));
  } catch (error) {
    return null;
  }

  if (typeof payload.exp !== "number" || payload.exp <= nowSeconds) {
    return null;
  }

  return payload;
}

// Build a session token + the matching Set-Cookie header value. The cookie is
// iframe-ready: SameSite=None requires Secure, and Partitioned (CHIPS) keeps it
// working in third-party iframe contexts, including mobile browsers.
function buildSessionCookie(secret, ttlSeconds, nowSeconds) {
  const payload = {
    sub: "admin",
    iat: nowSeconds,
    exp: nowSeconds + ttlSeconds
  };
  const value = signSession(payload, secret);
  const cookie = [
    `${SESSION_COOKIE_NAME}=${value}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=None",
    "Partitioned",
    `Max-Age=${ttlSeconds}`
  ].join("; ");
  return { value, cookie };
}

// Expiring (clearing) cookie keeps the same attributes so the browser matches
// and removes it.
function buildClearSessionCookie() {
  return [
    `${SESSION_COOKIE_NAME}=`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=None",
    "Partitioned",
    "Max-Age=0"
  ].join("; ");
}

// --- Cookie parsing ---------------------------------------------------------

function parseCookies(cookieHeader) {
  const result = {};
  if (!cookieHeader || typeof cookieHeader !== "string") {
    return result;
  }

  for (const part of cookieHeader.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) {
      continue;
    }
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (name) {
      result[name] = value;
    }
  }

  return result;
}

function readSessionFromRequest(req, secret, nowSeconds) {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies[SESSION_COOKIE_NAME];
  return verifySession(token, secret, nowSeconds);
}

// --- SSO JWT verification (HS256) -------------------------------------------
// Verifies a short-lived JWT minted by the hub. Throws on any failure; the
// caller maps that to a 401. The raw token is never included in error messages.

class SsoVerificationError extends Error {}

function verifySsoToken(token, secret, options) {
  const { audience, nowSeconds, clockSkewSeconds = 5 } = options;

  if (!token || typeof token !== "string") {
    throw new SsoVerificationError("Missing SSO token.");
  }

  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new SsoVerificationError("Malformed SSO token.");
  }

  const [headerPart, payloadPart, signaturePart] = parts;

  let header;
  try {
    header = JSON.parse(base64UrlDecodeToBuffer(headerPart).toString("utf8"));
  } catch (error) {
    throw new SsoVerificationError("Unreadable SSO token header.");
  }

  // Pin the algorithm. Explicitly reject "none" and anything that is not HS256.
  if (!header || header.alg !== "HS256") {
    throw new SsoVerificationError("Unsupported SSO token algorithm.");
  }

  const expectedSignature = base64UrlEncode(
    crypto
      .createHmac("sha256", secret)
      .update(`${headerPart}.${payloadPart}`)
      .digest()
  );

  if (!timingSafeEqualStrings(signaturePart, expectedSignature)) {
    throw new SsoVerificationError("Bad SSO token signature.");
  }

  let payload;
  try {
    payload = JSON.parse(base64UrlDecodeToBuffer(payloadPart).toString("utf8"));
  } catch (error) {
    throw new SsoVerificationError("Unreadable SSO token payload.");
  }

  if (typeof payload.exp !== "number") {
    throw new SsoVerificationError("SSO token has no expiry.");
  }

  if (payload.exp + clockSkewSeconds <= nowSeconds) {
    throw new SsoVerificationError("SSO token has expired.");
  }

  if (typeof payload.nbf === "number" && payload.nbf - clockSkewSeconds > nowSeconds) {
    throw new SsoVerificationError("SSO token not yet valid.");
  }

  // aud may be a string or an array per the JWT spec.
  const audMatches = Array.isArray(payload.aud)
    ? payload.aud.includes(audience)
    : payload.aud === audience;
  if (!audMatches) {
    throw new SsoVerificationError("SSO token audience mismatch.");
  }

  if (!payload.jti || typeof payload.jti !== "string") {
    throw new SsoVerificationError("SSO token missing jti.");
  }

  return payload;
}

// In-memory one-time-use tracker for jti values. Self-pruning so it cannot grow
// without bound: expired jtis are dropped on each use. Single-instance only,
// which is fine for ~60s one-time tokens on a single Railway service.
class SeenJtiStore {
  constructor() {
    this.map = new Map();
  }

  // Returns true if this jti is fresh (and records it); false if already used.
  useOnce(jti, expSeconds, nowSeconds) {
    this.prune(nowSeconds);
    if (this.map.has(jti)) {
      return false;
    }
    this.map.set(jti, expSeconds);
    return true;
  }

  prune(nowSeconds) {
    for (const [jti, exp] of this.map) {
      if (exp <= nowSeconds) {
        this.map.delete(jti);
      }
    }
  }
}

module.exports = {
  SESSION_COOKIE_NAME,
  signSession,
  verifySession,
  buildSessionCookie,
  buildClearSessionCookie,
  parseCookies,
  readSessionFromRequest,
  verifySsoToken,
  timingSafeEqualStrings,
  SsoVerificationError,
  SeenJtiStore
};
