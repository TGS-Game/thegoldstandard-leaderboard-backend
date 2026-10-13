const express = require("express");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const { createHttpError } = require("./service");
const { nowUnixSeconds } = require("./time");
const auth = require("./auth");

const MAX_META_IP_LENGTH = 200;
const MAX_META_USER_AGENT_LENGTH = 300;

// Request metadata for the entry history and the denial log. Read from the raw
// headers/socket so `trust proxy` stays untouched. The x-forwarded-for value is
// client-controlled except for its tail (appended by the platform proxy), so
// when it is too long the START is cut and the tail plus socket address stay.
function getRequestMeta(req) {
  const remoteAddress = (req.socket && req.socket.remoteAddress) || "";
  const forwardedFor = typeof req.headers["x-forwarded-for"] === "string"
    ? req.headers["x-forwarded-for"].trim()
    : "";
  const userAgent = typeof req.headers["user-agent"] === "string"
    ? req.headers["user-agent"]
    : "";

  let ip = remoteAddress;
  if (forwardedFor) {
    const suffix = ` via ${remoteAddress}`;
    const room = Math.max(0, MAX_META_IP_LENGTH - suffix.length);
    ip = `${forwardedFor.slice(-room)}${suffix}`;
  }

  return {
    ip: ip.slice(0, MAX_META_IP_LENGTH),
    userAgent: userAgent.slice(0, MAX_META_USER_AGENT_LENGTH)
  };
}

function createApp(service, config) {
  const app = express();
  const formParser = multer();
  const observer = service.observer;

  app.disable("x-powered-by");
  // Observe mode: only attaches a listener that runs after the response has
  // been sent. It cannot reject, delay or change any request.
  app.use(observer.middleware());
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
      observer.guidIssued(res, guid);
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
      const stored = await service.uploadEntry(req.body, getRequestMeta(req));
      observer.uploadStored(res, stored);
      res.status(200).type("text/plain").send("OK");
    } catch (error) {
      next(error);
    }
  });

  // Admin-only: the shipped game never calls these two routes, and leaving them
  // open let anyone holding a GUID rename or delete that entry. Without valid
  // admin auth they answer 403 and do nothing.
  app.post(
    "/entry/update-username",
    formParser.none(),
    requireAdminForEntryWrite,
    async (req, res, next) => {
      try {
        await service.updateUsername(req.body, { ...getRequestMeta(req), source: "admin" });
        res.status(200).type("text/plain").send("OK");
      } catch (error) {
        next(error);
      }
    }
  );

  app.post(
    "/entry/delete",
    formParser.none(),
    requireAdminForEntryWrite,
    async (req, res, next) => {
      try {
        await service.deleteEntry(req.body, { ...getRequestMeta(req), source: "admin" });
        res.status(200).type("text/plain").send("OK");
      } catch (error) {
        next(error);
      }
    }
  );

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

  // Gate for the two /entry/* routes that are admin-only. Token auth only
  // (Bearer / X-Admin-Token): these routes accept plain form posts, so honouring
  // the SameSite=None session cookie would let another site trigger them from a
  // logged-in admin's browser. With no ADMIN_TOKEN configured it denies everyone.
  // Logs one line per denial: never the GUID, and only a prefix of the key.
  function requireAdminForEntryWrite(req, _res, next) {
    if (hasValidToken(req)) {
      next();
      return;
    }

    const meta = getRequestMeta(req);
    const publicKey = req.body && typeof req.body.publicKey === "string"
      ? req.body.publicKey.trim().slice(0, 8)
      : "";
    console.warn(
      `Denied ${req.method} ${req.path} (admin auth required): ` +
      `ip=${JSON.stringify(meta.ip)} ua=${JSON.stringify(meta.userAgent)} ` +
      `publicKey=${JSON.stringify(publicKey)}`
    );
    next(createHttpError(403, "Forbidden."));
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

    // Read-only audit trail of entry changes (newest first).
    app.get("/admin/api/entry-history", async (req, res, next) => {
      try {
        const history = await service.getAdminEntryHistory(req.query);
        res.status(200).json(history);
      } catch (error) {
        next(error);
      }
    });

    // Read-only observe-mode rows (newest first).
    app.get("/admin/api/observations", async (req, res, next) => {
      try {
        const observations = await service.getAdminObservations(req.query);
        res.status(200).json(observations);
      } catch (error) {
        next(error);
      }
    });

    // Read-only observe-mode report for a period.
    app.get("/admin/api/observation-summary", async (req, res, next) => {
      try {
        const summary = await service.getAdminObservationSummary(req.query);
        res.status(200).json(summary);
      } catch (error) {
        next(error);
      }
    });

    app.post("/admin/api/entries", async (req, res, next) => {
      try {
        await service.adminUpsertEntry(req.body, getRequestMeta(req));
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
        }, getRequestMeta(req));
        res.status(200).json({ ok: true });
      } catch (error) {
        next(error);
      }
    });

    app.delete("/admin/api/entries/:publicKey/:userGuid", async (req, res, next) => {
      try {
        await service.adminDeleteEntry(req.params, getRequestMeta(req));
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
