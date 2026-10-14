# Self-Hosted Leaderboard Backend

This service is a drop-in backend replacement for the Unity `Leaderboard Creator` package already used by this project.

It exposes the routes your current Unity code expects:

- `GET /`
- `GET /authorize`
- `GET /get`
- `POST /entry/upload`
- `POST /entry/update-username` (admin-only, see below)
- `POST /entry/delete` (admin-only, see below)
- `GET /entry/get`
- `GET /entry/count`

It now also supports first-launch player profile capture:

- `POST /player-profile`

It also exposes an admin panel and admin API for managing entries yourself.

## Why this works

Your Unity gameplay/UI scripts do not need leaderboard logic changes. The only Unity-side change in this project is that the imported package now reads the backend base URL from `LeaderboardCreatorConfig` instead of a hardcoded vendor domain.

## Storage

- Default local storage: SQLite file
- Production-ready option: Postgres via `DATABASE_URL`
- Additional player onboarding storage: `player_profiles` table in the same database
- Audit trail: `entry_history` table in the same database (created automatically
  on start; one row per entry change, see "Entry History")
- Observe mode: `issued_guids`, `security_observations` and `traffic_hourly`
  tables in the same database (created automatically, see "Observe Mode")

If `DATABASE_URL` is set, the service uses Postgres. Otherwise it uses SQLite.

## Quick Start

1. Copy `.env.example` to `.env`.
2. Run `npm install`.
3. Run `npm start`.
4. Set the Unity leaderboard package server URL to your backend URL.

Local default:

```bash
http://localhost:8787
```

## Environment Variables

- `PORT`: HTTP port. Default `8787`.
- `CORS_ORIGIN`: Allowed CORS origin. Default `*`.
- `DATABASE_URL`: Postgres connection string. If blank, SQLite is used.
- `SQLITE_PATH`: SQLite database path when Postgres is not used.
- `ALLOWED_PUBLIC_KEYS`: Optional comma-separated whitelist of leaderboard public keys.
- `ADMIN_TOKEN`: Enables the admin panel/API via Bearer / `X-Admin-Token` header auth.
- `ADMIN_PASSWORD`: Enables password session login for `/admin`.
- `SESSION_SECRET`: Secret used to sign the admin session cookie. Required for session login and SSO.
- `SESSION_TTL_SECONDS`: Session lifetime. Default `43200` (12h).
- `DIRECT_ADMIN_LOGIN`: Optional. Default on; `off` (or `false`/`0`/`no`) switches
  off the password login so the hub's `/sso` is the only way in for a person.
- `LEADERBOARD_SSO_SECRET`: Shared secret for hub single sign-on (HS256 JWT).
- `LEADERBOARD_SSO_AUDIENCE`: Expected JWT `aud`. Default `leaderboard`.
- `HUB_ORIGIN`: Origin allowed to embed `/admin` in an iframe (CSP `frame-ancestors`).
- `GUID_MASK_SECRET`: Optional. Key used to mask other players' GUIDs in `GET /get`.
  If blank, a key derived from `SESSION_SECRET` is used; if that is blank too, a
  random per-process key (masks then change on every restart).
- `MAX_USERNAME_LENGTH`: Default `127`.
- `MAX_EXTRA_LENGTH`: Default `100`.
- `SECURITY_OBSERVE`: Optional. Default on; `off` stops all observe-mode writes.
- `OBSERVE_EXPECTED_PUBLIC_KEYS`: Optional comma-separated keys treated as
  expected. Default: the shipped game's key. Other keys are recorded, not blocked.
- `OBSERVE_MAX_SCORE`: Default `100000000`. `OBSERVE_MAX_USERNAME_LENGTH`: Default `60`.
- `OBSERVE_RATE_AUTHORIZE` (`30/600`), `OBSERVE_RATE_UPLOAD` (`20/600`),
  `OBSERVE_RATE_UPLOAD_GUID` (`5/600`), `OBSERVE_RATE_PROFILE` (`10/3600`):
  proposed limits as `<requests>/<window seconds>`. Recorded, never enforced.
- `OBSERVE_MAX_ROWS_PER_HOUR`: Default `500` observation rows per reason per hour.
- `OBSERVE_MAX_ISSUED_PER_HOUR`: Default `2000` issued GUID rows per hour.

## Health Check

- `GET /health`: no auth. Returns `200 {"status":"ok"}` when the data store
  responds, or `503 {"status":"degraded"}` if it does not.

## Admin Authentication

The admin panel and API accept **either** of these, in parallel:

- A signed session cookie, obtained by logging in at `GET /admin/login` with
  `ADMIN_PASSWORD`, or via hub SSO at `GET /sso`.
- The `ADMIN_TOKEN` via `Authorization: Bearer <token>` or `X-Admin-Token`
  (unchanged; used by programmatic callers).

The session cookie is `HttpOnly; Secure; SameSite=None; Partitioned` so the panel
works embedded in the hub iframe (including mobile). `GET /admin/login` is the
only open admin route; everything else under `/admin` requires auth.

Setting `DIRECT_ADMIN_LOGIN=off` switches the password login off: `GET` and
`POST /admin/login` answer `403` with a "sign in through the admin hub" page (the
POST never reads the password), and only sessions created by `/sso` are accepted.
Password sessions, and any session issued before this switch existed, stop
working until the admin signs in again through the hub. `ADMIN_TOKEN` header
auth, `/sso`, `/health` and the game endpoints are unaffected.

### Hub single sign-on (`GET /sso`)

Verifies a short-lived JWT minted by the hub:

- `alg`: `HS256`, signed with `LEADERBOARD_SSO_SECRET`
- `aud`: `leaderboard`
- `exp`: short-lived (~60s)
- `jti`: unique, one-time-use (replays are rejected)

On success the service sets the session cookie and `302`s to `/admin`. Any
failure returns `401`. The token is never logged. Admin pages
(`/admin`, `/admin/login`, `/sso`) send `Content-Security-Policy: frame-ancestors
<HUB_ORIGIN>`; game-facing endpoints are never framed or gated.

## Railway Deployment

Recommended production setup:

1. Create a new Railway project.
2. Add a Postgres service.
3. Add a service from this `leaderboard-backend` folder.
4. Set `DATABASE_URL` from Railway Postgres.
5. Set `ADMIN_TOKEN` to a long random secret.
6. Set `CORS_ORIGIN` to your expected origin if you want to restrict it.
7. Deploy.

Then set the Unity package server URL to your Railway domain, for example:

```text
https://your-service.up.railway.app
```

## Unity Setup

In this project, update `Assets/Imported Assets/LeaderboardCreator/Resources/LeaderboardCreatorConfig.asset` and set:

- `serverUrl`: your backend base URL

Example:

```text
https://leaderboard.yourdomain.com
```

No leaderboard scene/gameplay script changes are required.

## Admin Panel

If `ADMIN_TOKEN` is set, the backend exposes:

- `GET /admin` for the built-in management page
- `GET /admin/api/public-keys`
- `GET /admin/api/entries?publicKey=...`
- `GET /admin/api/player-profiles`
- `POST /admin/api/entries`
- `PUT /admin/api/entries/:publicKey/:userGuid`
- `DELETE /admin/api/entries/:publicKey/:userGuid`
- `GET /admin/api/entry-history?publicKey=...&userGuid=...&limit=...`
- `GET /admin/api/observations?reason=...&route=...&since=...&limit=...`
- `GET /admin/api/observation-summary?since=...`

Authenticate with either:

- `Authorization: Bearer <ADMIN_TOKEN>`
- `X-Admin-Token: <ADMIN_TOKEN>`

The built-in admin page prompts for the token and lets you load public keys, inspect entries, edit rows, create rows, and delete rows.

## Step-By-Step Railway Deployment

1. Create a Railway account and a new empty project.
2. Inside Railway, add a `Postgres` service.
3. From this folder, commit or upload the contents of [leaderboard-backend](/d:/Projects/Switch Max The Game Mobile/leaderboard-backend).
4. Add a new Railway service from that repo or folder.
5. In the backend service variables, set:
   - `DATABASE_URL`: use the value from the Railway Postgres service.
   - `ADMIN_TOKEN`: generate a long secret, at least 32 random characters.
   - `CORS_ORIGIN`: set `*` or restrict it to your site if needed.
   - `ALLOWED_PUBLIC_KEYS`: optional, but recommended once you know your production key.
6. Deploy the service.
7. Open the service domain that Railway gives you and verify:
   - `/` returns `OK`
   - `/authorize` returns a GUID string
   - `/admin` loads the admin page
8. In Unity, open [LeaderboardCreatorConfig.asset](/d:/Projects/Switch Max The Game Mobile/Assets/Imported%20Assets/LeaderboardCreator/Resources/LeaderboardCreatorConfig.asset) and set `serverUrl` to your Railway domain.
9. Build and test leaderboard submission from the game.
10. Open `/admin`, enter your `ADMIN_TOKEN`, choose the leaderboard public key, and manage entries there.

## API Notes

- `GET /authorize` returns a plain text GUID.
- `GET /get` returns a JSON array of entries. The real `UserGuid` is returned only
  on the row whose GUID equals the caller's `userGuid` query parameter; every
  other row carries a stable opaque 32-character token in `UserGuid` instead.
- `GET /entry/get` returns a JSON object for one entry (the caller's own, looked
  up by the `userGuid` they supply).
- `POST /entry/update-username` and `POST /entry/delete` are admin-only: they
  need the admin token (`Authorization: Bearer <ADMIN_TOKEN>` or
  `X-Admin-Token`; the session cookie is deliberately not accepted here).
  Anything else gets `403 Forbidden.` and nothing is changed. If `ADMIN_TOKEN`
  is not set they deny everyone.
- `GET /entry/count` returns a plain text integer.
- Write routes return HTTP `200` on success. The body is not significant to the Unity package.
- `POST /player-profile` accepts `name`, `email`, `country`, `consentAccepted`, and optional `userGuid`.

## Entry History

Every entry change (game upload insert/overwrite, rename, delete, admin
create/edit/delete) appends a row to `entry_history` holding the row as it was
before and after, plus the caller's IP string and user agent, so unwanted
changes can be reviewed and put back by hand. Read it with
`GET /admin/api/entry-history` (admin auth; newest first; optional `publicKey`
and `userGuid` filters; `limit` default `100`, max `500`). History is
best-effort: a failed history write is logged and never fails the request.

## Observe Mode

Log-only security telemetry for the game-facing routes. It never rejects,
delays or changes a request: everything runs after the response has been sent,
and a failed or slow write is dropped. `SECURITY_OBSERVE=off` turns it off.

- `issued_guids`: every GUID handed out by `GET /authorize` (kept 90 days).
- `security_observations`: one row per finding, also printed as an
  `[observe]` log line. Reasons: `unexpected_public_key`, `guid_not_issued`,
  `guid_shape`, `score_out_of_bounds`, `username_shape`, `username_too_long`,
  `extra_unexpected`, `profile_fields`, `would_rate_limit` (one per client per
  window) and `observations_suppressed` (the hourly cap for a reason was hit).
  Rows never hold a full GUID or public key: `guid_ref` is the same masked
  token `GET /get` returns, `key_prefix` is the first 8 characters.
- `traffic_hourly`: hourly counts of what clients send (content type, origin,
  Unity version, user agent family, `userGuid` presence, status, client address
  source), flushed every 5 minutes and on shutdown.

Read them with `GET /admin/api/observations` (admin auth; newest first;
optional `reason`, `route`, `since` filters; `limit` default `100`, max `1000`)
and `GET /admin/api/observation-summary` (default period: the last 7 days;
`since` is unix seconds or an ISO date; add `hourly=1` for the raw hourly rows).

## Public Key Behavior

This backend accepts any `publicKey` by default, which keeps it compatible with your existing Unity configuration. If you want to lock it down, set `ALLOWED_PUBLIC_KEYS`.
