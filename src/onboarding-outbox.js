// Durable delivery of new player registrations to onboarding-bridge, which
// creates the Pipedrive person.
//
// Contract: a 2xx answer from onboarding-bridge means the lead is safe there.
// Anything else (4xx, 5xx, 429, timeout, network error) means we keep it and
// try again with backoff, for ONBOARD_RETRY_HOURS (default 24). Every attempt
// for one lead carries the same Idempotency-Key header, so a bridge that
// honours it creates the person once even if an earlier attempt timed out
// after it had succeeded.
//
// One row per email (UNIQUE): a player is sent to Pipedrive at most once.
// Rows are claimed with a short lease (FOR UPDATE SKIP LOCKED), so two
// replicas would not send the same row at the same time.

const crypto = require("crypto");
const { nowUnixSeconds } = require("./time");

const BACKOFF_SECONDS = [60, 120, 300, 600, 1800, 3600, 7200];
const LEASE_SECONDS = 120;
const BATCH_SIZE = 10;
const BACKLOG_ALERT_KEY = "onboarding_backlog";
const CAP_ALERT_KEY = "onboarding_daily_cap";

class OnboardingOutbox {
  constructor({ storage, config, alerter }) {
    this.storage = storage;
    this.alerter = alerter;
    this.url = config.onboardUrl || "";
    this.secret = config.onboardSharedSecret || "";
    this.timeoutMs = config.onboardTimeoutMs || 5000;
    this.retrySeconds = (config.onboardRetryHours || 24) * 60 * 60;
    this.alertAfterSeconds = (config.onboardAlertAfterMinutes || 30) * 60;
    this.tickMs = config.onboardTickMs || 30000;
    this.dailyCap = Number.isInteger(config.onboardDailyCap) && config.onboardDailyCap >= 0 ? config.onboardDailyCap : 100;
    this.configured = Boolean(this.url && this.secret);
    this.timer = null;
    this.running = false;
    this.again = false;
    this.idle = Promise.resolve();
  }

  describe() {
    if (!this.configured) {
      return "Onboarding mirror: OFF (ONBOARD_URL or ONBOARD_SHARED_SECRET not set). " +
        "New sign-ups are kept in onboarding_outbox and sent once it is set.";
    }
    return `Onboarding mirror: outbox on (retries for ${this.retrySeconds / 3600} h, ` +
      `alert when a sign-up has waited ${this.alertAfterSeconds / 60} min, ` +
      `daily cap ${this.dailyCap || "off"}).`;
  }

  start() {
    if (this.timer) {
      return;
    }
    this.timer = setInterval(() => this.kick(), this.tickMs);
    this.timer.unref();
    this.kick();
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    return this.idle;
  }

  // Stores the lead. Resolves "queued" (new row) or "duplicate" (this email
  // was already queued or sent: nothing more goes to Pipedrive). Throws if the
  // row could not be written.
  async enqueue(lead) {
    const now = nowUnixSeconds();
    // Daily cap: over it, the row is kept as "held" (never sent until the
    // owner releases it) instead of going to Pipedrive. Count and insert are
    // two statements, so a burst can overshoot by a few; that is fine.
    let status = "pending";
    if (this.dailyCap > 0) {
      const admitted = await this.storage.countOnboardingAdmittedSince(startOfUtcDay(now));
      if (admitted >= this.dailyCap) {
        status = "held";
      }
    }
    const result = await this.storage.enqueueOnboarding({
      email: lead.email,
      idempotencyKey: crypto.randomUUID(),
      payload: JSON.stringify({ name: lead.name, email: lead.email, country: lead.country, consent: lead.consent }),
      status,
      createdAt: now,
      deadlineAt: now + this.retrySeconds
    });
    if (result === "queued" && status === "pending") {
      this.kick();
    } else if (result === "queued") {
      console.warn(`[onboarding] daily cap of ${this.dailyCap} reached: new sign-up held, not sent to Pipedrive.`);
      this.kick(); // runs the alert check
    }
    return result === "queued" ? status : result;
  }

  // Runs one pass soon, never two at once. Not awaited by callers.
  kick() {
    if (this.running) {
      this.again = true;
      return this.idle;
    }
    this.running = true;
    this.idle = this.pass()
      .catch((error) => console.error(`[onboarding] outbox pass failed: ${String(error && error.message).slice(0, 200)}`))
      .finally(() => {
        this.running = false;
        if (this.again) {
          this.again = false;
          this.kick();
        }
      });
    return this.idle;
  }

  async pass() {
    if (this.configured) {
      for (;;) {
        const rows = await this.storage.claimDueOnboarding(nowUnixSeconds(), BATCH_SIZE, LEASE_SECONDS);
        if (rows.length === 0) {
          break;
        }
        for (const row of rows) {
          await this.deliver(row);
        }
      }
    }
    await this.checkAlerts();
  }

  async deliver(row) {
    let error = "";
    try {
      const response = await fetch(this.url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-shared-secret": this.secret,
          "Idempotency-Key": row.idempotencyKey
        },
        body: row.payload,
        signal: AbortSignal.timeout(this.timeoutMs)
      });
      // Drain the body so the connection can be reused.
      await response.arrayBuffer().catch(() => null);
      if (response.ok) {
        await this.storage.markOnboardingSent(row.id, nowUnixSeconds());
        if (row.attempts > 0) {
          console.log(`[onboarding] sign-up #${row.id} delivered after ${row.attempts + 1} attempts.`);
        }
        return;
      }
      error = `HTTP ${response.status}`;
    } catch (caught) {
      error = caught && caught.name === "TimeoutError"
        ? `timeout after ${this.timeoutMs} ms`
        : String((caught && caught.message) || caught).slice(0, 120);
    }

    const now = nowUnixSeconds();
    const attempts = row.attempts + 1;
    const giveUp = now >= row.deadlineAt;
    const delay = BACKOFF_SECONDS[Math.min(attempts - 1, BACKOFF_SECONDS.length - 1)];
    await this.storage.markOnboardingRetry(row.id, {
      attempts,
      lastError: error,
      failed: giveUp,
      nextAttemptAt: now + delay
    });
    console.error(
      `[onboarding] sign-up #${row.id} not accepted by onboarding-bridge (${error}); ` +
      (giveUp ? "retry window over, stopped (needs a manual retry)." : `attempt ${attempts}, next try in ${delay} s.`)
    );
  }

  async checkAlerts() {
    const now = nowUnixSeconds();
    // Daily cap: alert once held sign-ups have existed for 5 minutes.
    const held = await this.storage.heldOnboarding(startOfUtcDay(now));
    await this.alerter.update(CAP_ALERT_KEY, held.total > 0, {
      problem: () => capMessage(held, this.dailyCap),
      fixed: "Leaderboard: fixed. No Switch Max sign-ups are held by the daily Pipedrive cap any more."
    });

    if (!this.configured) {
      return;
    }
    const backlog = await this.storage.onboardingBacklog(now - this.alertAfterSeconds);
    await this.alerter.update(BACKLOG_ALERT_KEY, backlog.waiting > 0, {
      minSeconds: 0, // the 30-minute wait is already part of the condition
      problem: () => backlogMessage(backlog, this.alertAfterSeconds, this.retrySeconds),
      fixed: "Leaderboard: fixed. All waiting Switch Max sign-ups have now reached Pipedrive (onboarding-bridge accepted them)."
    });
  }
}

function capMessage(held, cap) {
  return `Leaderboard blocked ${held.today} Pipedrive sign-up${held.today === 1 ? "" : "s"} today — possible abuse. ` +
    `More than ${cap} new Switch Max players registered today (the daily cap, ONBOARD_DAILY_CAP), so the rest are ` +
    `held instead of being sent to Pipedrive (${held.total} held in total). Nothing is lost. What to do: look at the ` +
    "newest Player Profiles in the leaderboard admin. If they are real players, release them with " +
    "POST /admin/api/onboarding-outbox/retry {\"status\":\"held\"} (admin token), or raise ONBOARD_DAILY_CAP. " +
    "If they are spam, drop them with POST /admin/api/onboarding-outbox/discard {\"status\":\"held\"}.";
}

function startOfUtcDay(unixSeconds) {
  return unixSeconds - (unixSeconds % 86400);
}

function backlogMessage(backlog, alertAfterSeconds, retrySeconds) {
  const n = backlog.waiting;
  const stopped = backlog.failed > 0
    ? ` ${backlog.failed} of them passed the ${retrySeconds / 3600} h retry window and stopped retrying.`
    : "";
  return `Leaderboard: ${n} Switch Max sign-up${n === 1 ? " has" : "s have"} been waiting more than ` +
    `${alertAfterSeconds / 60} minutes to reach Pipedrive, because onboarding-bridge is not accepting them ` +
    `(last error: ${backlog.lastError || "unknown"}). They are saved in the leaderboard database and retried ` +
    `automatically for ${retrySeconds / 3600} hours.${stopped} What to do: check that onboarding-bridge is up, and that ` +
    "ONBOARD_URL and ONBOARD_SHARED_SECRET on the leaderboard service are right. Stopped ones can be retried with " +
    "POST /admin/api/onboarding-outbox/retry (admin token).";
}

module.exports = {
  OnboardingOutbox,
  BACKOFF_SECONDS,
  BACKLOG_ALERT_KEY,
  CAP_ALERT_KEY
};
