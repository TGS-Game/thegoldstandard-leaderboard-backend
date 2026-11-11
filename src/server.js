const config = require("./config");
const { createStorage } = require("./storage");
const { LeaderboardService } = require("./service");
const { createApp } = require("./app");
const { describeRateLimits } = require("./rate-limit");

async function main() {
  const storage = createStorage(config);
  await storage.initialize();

  const service = new LeaderboardService(storage, config);
  const app = createApp(service, config);
  service.observer.start();
  service.start();

  const server = app.listen(config.port, () => {
    const storageLabel = config.databaseUrl ? "postgres" : "sqlite";
    console.log(`Leaderboard backend listening on port ${config.port} using ${storageLabel}.`);
    console.log(describeRateLimits(config.rateLimits));
    console.log(service.describeUploadSession());
    console.log(service.describeOnboarding());
    console.log(`trust proxy: ${JSON.stringify(config.trustProxy)} (client IP for rate limits ${config.trustProxy === false ? "is the socket address" : "comes from X-Forwarded-For"}).`);
  });

  async function shutdown(signal) {
    console.log(`Received ${signal}, shutting down leaderboard backend...`);
    server.close(async () => {
      await Promise.race([
        service.stop(),
        new Promise((resolve) => setTimeout(resolve, 3000))
      ]).catch(() => {});
      // Last flush of the observe-mode traffic counts; never waits long.
      await Promise.race([
        service.observer.stop(),
        new Promise((resolve) => setTimeout(resolve, 2000))
      ]).catch(() => {});
      await storage.close();
      process.exit(0);
    });
  }

  process.on("SIGINT", () => {
    shutdown("SIGINT").catch((error) => {
      console.error(error);
      process.exit(1);
    });
  });

  process.on("SIGTERM", () => {
    shutdown("SIGTERM").catch((error) => {
      console.error(error);
      process.exit(1);
    });
  });
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
