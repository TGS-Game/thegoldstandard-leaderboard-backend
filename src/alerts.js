// Slack alerts that follow the alert rule:
// - only when the owner has to act, one message per problem, in plain English;
// - a condition must hold for `minSeconds` (default 5 min) before it alerts;
// - while it lasts, at most one reminder per 24 h;
// - exactly one "fixed" message, and only after a problem that was alerted.
//   A blip that clears before it alerted ends silently.
//
// State lives in the alert_state table when the storage has it (so restarts
// neither repeat nor lose an alert); otherwise in memory, which then repeats an
// open alert after a restart. SLACK_WEBHOOK_URL unset: messages are logged with
// an "[alert]" prefix instead of sent.

const DEFAULT_MIN_SECONDS = 5 * 60;
const REMINDER_SECONDS = 24 * 60 * 60;
const SEND_TIMEOUT_MS = 10000;
const IMMEDIATE_INTERVAL_SECONDS = 60 * 60;

class Alerter {
  constructor({ storage, webhookUrl, now } = {}) {
    this.storage = storage;
    this.webhookUrl = webhookUrl || "";
    this.now = typeof now === "function" ? now : () => Math.floor(Date.now() / 1000);
    this.persistent = Boolean(storage && typeof storage.getAlertState === "function");
    this.memory = new Map();
    this.lastImmediate = new Map();
  }

  describe() {
    const target = this.webhookUrl ? "Slack" : "the log only (SLACK_WEBHOOK_URL not set)";
    const state = this.persistent ? "kept in Postgres" : "kept in memory (repeats after a restart)";
    return `Alerts: sent to ${target}; alert state ${state}.`;
  }

  async getState(key) {
    if (this.persistent) {
      return this.storage.getAlertState(key);
    }
    return this.memory.get(key) || null;
  }

  async saveState(key, state) {
    if (this.persistent) {
      return state ? this.storage.saveAlertState(key, state) : this.storage.deleteAlertState(key);
    }
    if (state) {
      this.memory.set(key, { ...state });
    } else {
      this.memory.delete(key);
    }
    return undefined;
  }

  // Call regularly with the current truth of a condition.
  //   problem(): the alert text, built when it is needed (counts stay fresh)
  //   fixed: the recovery text
  async update(key, active, { problem, fixed, minSeconds = DEFAULT_MIN_SECONDS }) {
    const now = this.now();
    const state = await this.getState(key);

    if (active) {
      if (!state) {
        const fresh = { since: now, alertedAt: null };
        if (minSeconds > 0) {
          await this.saveState(key, fresh);
          return "pending";
        }
        return this.raise(key, fresh, problem(), now);
      }
      if (state.alertedAt === null || state.alertedAt === undefined) {
        if (now - state.since >= minSeconds) {
          return this.raise(key, state, problem(), now);
        }
        return "pending";
      }
      if (now - state.alertedAt >= REMINDER_SECONDS) {
        return this.raise(key, state, `Reminder, still not fixed: ${problem()}`, now);
      }
      return "open";
    }

    if (!state) {
      return "clear";
    }
    if (state.alertedAt === null || state.alertedAt === undefined) {
      // Cleared before it ever alerted: a blip, no message.
      await this.saveState(key, null);
      return "clear";
    }
    if (await this.send(fixed)) {
      await this.saveState(key, null);
      return "fixed";
    }
    return "open"; // the fixed message is retried next time
  }

  async raise(key, state, text, now) {
    if (await this.send(text)) {
      await this.saveState(key, { ...state, alertedAt: now });
      return "alerted";
    }
    // Not delivered: keep the state so the next call tries again.
    await this.saveState(key, { ...state, alertedAt: null });
    return "pending";
  }

  // For problems that lose data right now (no 5-minute wait). At most one per
  // `key` per hour per process, so a burst cannot flood the channel.
  async immediate(key, text) {
    const now = this.now();
    const last = this.lastImmediate.get(key);
    if (last !== undefined && now - last < IMMEDIATE_INTERVAL_SECONDS) {
      return false;
    }
    this.lastImmediate.set(key, now);
    return this.send(text);
  }

  async send(text) {
    if (!this.webhookUrl) {
      console.log(`[alert] (SLACK_WEBHOOK_URL not set, not sent) ${text}`);
      return true;
    }
    try {
      const response = await fetch(this.webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
        signal: AbortSignal.timeout(SEND_TIMEOUT_MS)
      });
      if (!response.ok) {
        console.error(`[alert] Slack answered HTTP ${response.status}; will retry.`);
        return false;
      }
      return true;
    } catch (error) {
      console.error(`[alert] Slack send failed (${error.name}); will retry.`);
      return false;
    }
  }
}

module.exports = {
  Alerter,
  DEFAULT_MIN_SECONDS,
  REMINDER_SECONDS
};
