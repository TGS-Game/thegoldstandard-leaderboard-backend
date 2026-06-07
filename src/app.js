const express = require("express");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const { createHttpError } = require("./service");
const { nowUnixSeconds } = require("./time");
const auth = require("./auth");

function createApp(service, config) {
  const app = express();
  const formParser = multer();

  app.disable("x-powered-by");
  app.use(cors({ origin: config.corsOrigin }));
  app.use(express.json());

  app.get("/", (_req, res) => {
    res.status(200).send("OK");
  });

  // Health check: no auth, actually exercises the data store. Returns 200 when
  // the store responds, 503 when it does not. Never gated or framed.
  app.get("/health", async (_req, res) => {
    try {
      await service.checkHealth();
      res.status(200).json({ status: "ok" });
    } catch (error) {
      res.status(503).json({ status: "degraded" });
    }
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

  // --- Admin auth capabilities (each independently optional) -----------------
  const sessionEnabled = Boolean(config.adminPassword && config.sessionSecret);
  const ssoEnabled = Boolean(config.ssoSecret && config.sessionSecret);
  const tokenEnabled = Boolean(config.adminToken);
  const adminEnabled = sessionEnabled || ssoEnabled || tokenEnabled;

  // In-memory one-time-use tracker for SSO jti values (self-pruning).
  const seenJti = new auth.SeenJtiStore();

  // True when the request carries a valid signed session cookie.
  function hasValidSession(req) {
    if (!sessionEnabled && !ssoEnabled) {
      return false;
    }
    const session = auth.readSessionFromRequest(
      req,
      config.sessionSecret,
      nowUnixSeconds()
    );
    return Boolean(session);
  }

  // True when the request carries the admin token via Bearer or X-Admin-Token.
  function hasValidToken(req) {
    if (!tokenEnabled) {
      return false;
    }
    const authHeader = req.headers.authorization || "";
    const bearerToken = authHeader.startsWith("Bearer ")
      ? authHeader.slice("Bearer ".length).trim()
      : "";
    const headerToken = typeof req.headers["x-admin-token"] === "string"
      ? req.headers["x-admin-token"].trim()
      : "";
    const supplied = bearerToken || headerToken;
    return Boolean(supplied) && auth.timingSafeEqualStrings(supplied, config.adminToken);
  }

  function isAdminAuthorized(req) {
    return hasValidSession(req) || hasValidToken(req);
  }

  // Admin pages (and only admin pages) may be embedded by the hub. Game-facing
  // endpoints never get this header.
  function setAdminPageHeaders(res) {
    const frameAncestors = config.hubOrigin ? config.hubOrigin : "'none'";
    res.setHeader("Content-Security-Policy", `frame-ancestors ${frameAncestors}`);
  }

  function setSessionCookie(res) {
    const { cookie } = auth.buildSessionCookie(
      config.sessionSecret,
      config.sessionTtlSeconds,
      nowUnixSeconds()
    );
    res.append("Set-Cookie", cookie);
  }

  if (adminEnabled) {
    const publicDir = path.join(__dirname, "..", "public");
    const loginFormParser = express.urlencoded({ extended: false });

    // --- Session login (the only open admin route) -------------------------
    if (sessionEnabled) {
      app.get("/admin/login", (req, res) => {
        // Already signed in? Skip straight to the panel.
        if (hasValidSession(req)) {
          res.redirect(302, "/admin");
          return;
        }
        setAdminPageHeaders(res);
        res.sendFile(path.join(publicDir, "login.html"));
      });

      app.post("/admin/login", loginFormParser, (req, res) => {
        const supplied = typeof req.body.password === "string" ? req.body.password : "";
        const ok = supplied && auth.timingSafeEqualStrings(supplied, config.adminPassword);
        if (!ok) {
          res.redirect(302, "/admin/login?error=1");
          return;
        }
        setSessionCookie(res);
        res.redirect(302, "/admin");
      });

      app.post("/admin/logout", (_req, res) => {
        res.append("Set-Cookie", auth.buildClearSessionCookie());
        res.redirect(302, "/admin/login");
      });
    }

    // --- Hub single sign-on -------------------------------------------------
    // Verifies a short-lived HS256 JWT (aud "leaderboard", ~60s, one-time jti).
    // The token itself is never logged. Success sets a session and redirects to
    // /admin; any failure is a flat 401.
    if (ssoEnabled) {
      app.get("/sso", (req, res) => {
        setAdminPageHeaders(res);

        const headerAuth = req.headers.authorization || "";
        const bearer = headerAuth.startsWith("Bearer ")
          ? headerAuth.slice("Bearer ".length).trim()
          : "";
        const token = (typeof req.query.token === "string" && req.query.token)
          || (typeof req.query.jwt === "string" && req.query.jwt)
          || bearer;

        const now = nowUnixSeconds();
        try {
          const payload = auth.verifySsoToken(token, config.ssoSecret, {
            audience: config.ssoAudience,
            nowSeconds: now
          });

          // One-time use: reject replays of an already-seen jti.
          if (!seenJti.useOnce(payload.jti, payload.exp, now)) {
            res.status(401).type("text/plain").send("Unauthorized.");
            return;
          }

          setSessionCookie(res);
          res.redirect(302, "/admin");
        } catch (error) {
          // Do not surface or log token contents.
          res.status(401).type("text/plain").send("Unauthorized.");
        }
      });
    }

    // --- Admin panel page (requires session or token) ----------------------
    app.get("/admin", (req, res) => {
      setAdminPageHeaders(res);
      if (!isAdminAuthorized(req)) {
        if (sessionEnabled) {
          res.redirect(302, "/admin/login");
        } else {
          res.status(401).type("text/plain").send("Unauthorized.");
        }
        return;
      }
      res.sendFile(path.join(publicDir, "admin.html"));
    });

    // --- Admin API (requires session or token) -----------------------------
    app.use("/admin/api", (req, _res, next) => {
      if (!isAdminAuthorized(req)) {
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
