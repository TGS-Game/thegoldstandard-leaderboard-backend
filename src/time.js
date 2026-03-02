function nowUnixSeconds() {
  return Math.floor(Date.now() / 1000);
}

function startOfUtcDayUnixSeconds() {
  const now = new Date();
  return Math.floor(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()) / 1000);
}

function resolveMinTimestamp(timePeriod) {
  const days = Number.parseInt(timePeriod, 10);
  if (!Number.isFinite(days) || days <= 0) {
    return 0;
  }

  if (days === 1) {
    return startOfUtcDayUnixSeconds();
  }

  return nowUnixSeconds() - (days * 24 * 60 * 60);
}

module.exports = {
  nowUnixSeconds,
  resolveMinTimestamp
};
