// Server-to-server events to the support site's notifications endpoint
// (POST /api/notifications/events, Bearer NOTIFICATIONS_EVENT_SECRET).
//
// Fire-and-forget: send() never throws and is never awaited by a request.
// Each event is tried at most 3 times (5 s timeout each), with a pause between
// tries, and only network errors, timeouts and 5xx answers are retried. Every
// try carries the same idempotency_key, so the support site creates at most
// one notification per event. The secret is never logged.

const DEFAULT_URL = "https://support.thegoldstandard.com/api/notifications/events";
const DEFAULT_TIMEOUT_MS = 5000;
const MAX_TRIES = 3;
// Pause before try 2 and before try 3.
const DEFAULT_RETRY_DELAYS_MS = [2000, 8000];

class SupportNotifier {
  constructor({ url, secret, timeoutMs, retryDelaysMs, fetchImpl } = {}) {
    this.url = url || DEFAULT_URL;
    this.secret = secret || "";
    this.timeoutMs = Number.isInteger(timeoutMs) && timeoutMs > 0 ? timeoutMs : DEFAULT_TIMEOUT_MS;
    this.retryDelaysMs = Array.isArray(retryDelaysMs) ? retryDelaysMs : DEFAULT_RETRY_DELAYS_MS;
    this.fetchImpl = fetchImpl || ((...args) => fetch(...args));
    this.offLogged = false;
  }

  get configured() {
    return Boolean(this.secret);
  }

  // Startup line for server.js. Counts as the one "off" log line.
  describe() {
    if (!this.configured) {
      this.offLogged = true;
      return "notifications: off (no secret)";
    }
    return `notifications: on (events to ${safeOrigin(this.url)})`;
  }

  // Resolves to "sent" | "off" | "rejected" | "failed". Never rejects.
  send(type, idempotencyKey, data) {
    if (!this.configured) {
      if (!this.offLogged) {
        this.offLogged = true;
        console.log("notifications: off (no secret)");
      }
      return Promise.resolve("off");
    }
    const body = JSON.stringify({ type, idempotency_key: idempotencyKey, data });
    return this.attempt(type, body, 1).catch((error) => {
      console.error(`[notify] ${type}: unexpected error ${String(error && error.message).slice(0, 200)}`);
      return "failed";
    });
  }

  async attempt(type, body, tryNumber) {
    let problem;
    try {
      const response = await this.fetchImpl(this.url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.secret}`
        },
        body,
        signal: AbortSignal.timeout(this.timeoutMs)
      });
      // Drain the body so the connection is released.
      await response.text().catch(() => "");
      if (response.ok) {
        console.log(`[notify] ${type}: delivered (HTTP ${response.status}).`);
        return "sent";
      }
      if (response.status < 500) {
        console.error(`[notify] ${type}: refused with HTTP ${response.status}; not retried.`);
        return "rejected";
      }
      problem = `HTTP ${response.status}`;
    } catch (error) {
      problem = error && error.name === "TimeoutError"
        ? `timeout after ${this.timeoutMs} ms`
        : String((error && error.message) || error).slice(0, 200);
    }

    if (tryNumber >= MAX_TRIES) {
      console.error(`[notify] ${type}: gave up after ${tryNumber} tries (${problem}).`);
      return "failed";
    }
    console.warn(`[notify] ${type}: try ${tryNumber} failed (${problem}); retrying.`);
    const delay = this.retryDelaysMs[tryNumber - 1] || 0;
    await new Promise((resolve) => {
      const timer = setTimeout(resolve, delay);
      if (timer.unref) {
        timer.unref();
      }
    });
    return this.attempt(type, body, tryNumber + 1);
  }
}

function safeOrigin(url) {
  try {
    return new URL(url).origin;
  } catch (_error) {
    return "an invalid SUPPORT_NOTIFY_URL";
  }
}

module.exports = { SupportNotifier, DEFAULT_URL };
