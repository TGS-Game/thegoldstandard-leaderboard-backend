# Self-Hosted Leaderboard Backend

This service is a drop-in backend replacement for the Unity `Leaderboard Creator` package already used by this project.

It exposes the routes your current Unity code expects:

- `GET /`
- `GET /authorize`
- `GET /get`
- `POST /entry/upload`
- `POST /entry/update-username`
- `POST /entry/delete`
- `GET /entry/get`
- `GET /entry/count`

It also exposes an admin panel and admin API for managing entries yourself.

## Why this works

Your Unity gameplay/UI scripts do not need leaderboard logic changes. The only Unity-side change in this project is that the imported package now reads the backend base URL from `LeaderboardCreatorConfig` instead of a hardcoded vendor domain.

## Storage

- Default local storage: SQLite file
- Production-ready option: Postgres via `DATABASE_URL`

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
- `ADMIN_TOKEN`: Required to enable the admin panel and admin API.
- `MAX_USERNAME_LENGTH`: Default `127`.
- `MAX_EXTRA_LENGTH`: Default `100`.

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
- `GET /admin/api/entries?publicKey=...&sortBy=rank|score|time&sortDirection=asc|desc`
- `POST /admin/api/entries`
- `PUT /admin/api/entries/:publicKey/:userGuid`
- `DELETE /admin/api/entries/:publicKey/:userGuid`

Authenticate with either:

- `Authorization: Bearer <ADMIN_TOKEN>`
- `X-Admin-Token: <ADMIN_TOKEN>`

The built-in admin page prompts for the token and lets you load public keys, inspect entries, edit rows, create rows, and delete rows.
It also lets you sort the shown entries by rank, score, or updated time in ascending or descending order.

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
- `GET /get` returns a JSON array of entries.
- `GET /entry/get` returns a JSON object for one entry.
- `GET /entry/count` returns a plain text integer.
- Write routes return HTTP `200` on success. The body is not significant to the Unity package.

## Public Key Behavior

This backend accepts any `publicKey` by default, which keeps it compatible with your existing Unity configuration. If you want to lock it down, set `ALLOWED_PUBLIC_KEYS`.
