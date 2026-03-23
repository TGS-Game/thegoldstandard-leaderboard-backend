const express = require("express");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const { createHttpError } = require("./service");

function createApp(service, config) {
  const app = express();
  const formParser = multer();

  app.disable("x-powered-by");
  app.use(cors({ origin: config.corsOrigin }));
  app.use(express.json());

  app.get("/", (_req, res) => {
    res.status(200).send("OK");
  });

  app.get("/authorize", async (_req, res, next) => {
    try {
      const guid = await service.authorize();
      res.status(200).type("text/plain").send(guid);
    } catch (error) {
      next(error);
    }
  });

  app.get("/get", async (req, res, next) => {
    try {
      const entries = await service.getLeaderboard(req.query);
      res.status(200).json(entries);
    } catch (error) {
      next(error);
    }
  });

  app.post("/entry/upload", formParser.none(), async (req, res, next) => {
    try {
      await service.uploadEntry(req.body);
      res.status(200).type("text/plain").send("OK");
    } catch (error) {
      next(error);
    }
  });

  app.post("/entry/update-username", formParser.none(), async (req, res, next) => {
    try {
      await service.updateUsername(req.body);
      res.status(200).type("text/plain").send("OK");
    } catch (error) {
      next(error);
    }
  });

  app.post("/entry/delete", formParser.none(), async (req, res, next) => {
    try {
      await service.deleteEntry(req.body);
      res.status(200).type("text/plain").send("OK");
    } catch (error) {
      next(error);
    }
  });

  app.get("/entry/get", async (req, res, next) => {
    try {
      const entry = await service.getPersonalEntry(req.query);
      res.status(200).json(entry);
    } catch (error) {
      next(error);
    }
  });

  app.get("/entry/count", async (req, res, next) => {
    try {
      const count = await service.getEntryCount(req.query);
      res.status(200).type("text/plain").send(String(count));
    } catch (error) {
      next(error);
    }
  });

  app.post("/player-profile", formParser.none(), async (req, res, next) => {
    try {
      await service.uploadPlayerProfile(req.body);
      res.status(200).json({ ok: true });
    } catch (error) {
      next(error);
    }
  });

  if (config.adminToken) {
    const publicDir = path.join(__dirname, "..", "public");

    app.get("/admin", (_req, res) => {
      res.sendFile(path.join(publicDir, "admin.html"));
    });

    app.use("/admin/assets", express.static(publicDir));

    app.use("/admin/api", (req, _res, next) => {
      const authHeader = req.headers.authorization || "";
      const bearerToken = authHeader.startsWith("Bearer ")
        ? authHeader.slice("Bearer ".length).trim()
        : "";
      const headerToken = typeof req.headers["x-admin-token"] === "string"
        ? req.headers["x-admin-token"].trim()
        : "";
      const supplied = bearerToken || headerToken;

      if (!supplied || supplied !== config.adminToken) {
        next(createHttpError(401, "Unauthorized."));
        return;
      }

      next();
    });

    app.get("/admin/api/public-keys", async (_req, res, next) => {
      try {
        const publicKeys = await service.getAdminPublicKeys();
        res.status(200).json(publicKeys);
      } catch (error) {
        next(error);
      }
    });

    app.get("/admin/api/entries", async (req, res, next) => {
      try {
        const entries = await service.getAdminEntries(req.query);
        res.status(200).json(entries);
      } catch (error) {
        next(error);
      }
    });

    app.get("/admin/api/player-profiles", async (_req, res, next) => {
      try {
        const profiles = await service.getAdminPlayerProfiles();
        res.status(200).json(profiles);
      } catch (error) {
        next(error);
      }
    });

    app.post("/admin/api/entries", async (req, res, next) => {
      try {
        await service.adminUpsertEntry(req.body);
        res.status(200).json({ ok: true });
      } catch (error) {
        next(error);
      }
    });

    app.put("/admin/api/entries/:publicKey/:userGuid", async (req, res, next) => {
      try {
        await service.adminUpsertEntry({
          ...req.body,
          publicKey: req.params.publicKey,
          userGuid: req.params.userGuid
        });
        res.status(200).json({ ok: true });
      } catch (error) {
        next(error);
      }
    });

    app.delete("/admin/api/entries/:publicKey/:userGuid", async (req, res, next) => {
      try {
        await service.adminDeleteEntry(req.params);
        res.status(200).json({ ok: true });
      } catch (error) {
        next(error);
      }
    });
  }

  app.use((req, _res, next) => {
    next(createHttpError(404, `Route not found: ${req.method} ${req.path}`));
  });

  app.use((error, _req, res, _next) => {
    const status = error.status || 500;
    const message = error.message || "Internal server error.";
    if (status >= 500) {
      console.error(error);
    }
    res.status(status).type("text/plain").send(message);
  });

  return app;
}

module.exports = {
  createApp
};
