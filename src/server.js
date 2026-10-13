const config = require("./config");
const { createStorage } = require("./storage");
const { LeaderboardService } = require("./service");
const { createApp } = require("./app");

async function main() {
  const storage = createStorage(config);
  await storage.initialize();

  const service = new LeaderboardService(storage, config);
  const app = createApp(service, config);
  service.observer.start();

  const server = app.listen(config.port, () => {
    const storageLabel = config.databaseUrl ? "postgres" : "sqlite";
    console.log(`Leaderboard backend listening on port ${config.port} using ${storageLabel}.`);
  });

  async function shutdown(signal) {
    console.log(`Received ${signal}, shutting down leaderboard backend...`);
    server.close(async () => {
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
