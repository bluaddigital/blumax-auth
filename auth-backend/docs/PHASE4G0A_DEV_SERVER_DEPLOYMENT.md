# PHASE 4G-0A — Workstream A: Blumax Auth DEV Server Deployment

## Scope

Deploy Blumax Auth into the real DEV server topology (`dev-infra`), using
the existing per-service conventions already established there (not a new
pattern). "DEV server" means the actual shared development host this
session operates on — `dev-*` prefixed containers on `blumax-dev-net` /
`blumax-platform_blumax-net` — never the separate production environment.

## Prerequisite: GitHub `dev` branch had no `auth-backend` at all

`dev-infra`'s deployment mechanism (`apps/export_dev`/`apps/deploy.py`)
builds images from a `git archive` export of each repo's GitHub `dev`
branch tip — never from a local working copy. `blumax-auth/auth-backend`
had never been committed anywhere. With explicit user confirmation
(asked before acting, since this is a first-ever, team-visible push), it
was committed (66 files, `.gitignore` already correctly excluding
`.dev-keys/`, `.venv/`, caches, `.env` — confirmed via `git add --dry-run`
before staging) and pushed to `blumax-auth`'s `dev` branch:
`a0354ae..73de50f`.

## DEV components created

| Component | Detail |
|---|---|
| Postgres database | `blumax_auth`, dedicated least-privilege role `blumax_auth`, on the existing shared Postgres server (`blumax-platform-postgres-1`) — the same per-service-database convention every other dev service already uses (not a new pattern). `CONNECT` is granted to `PUBLIC` by Postgres default platform-wide (unchanged, pre-existing convention, not introduced here); table-level privilege is what actually isolates data — confirmed live: `blumax_auth` role gets `permission denied for table lab_user` querying Labs' database, zero data access despite being able to connect. |
| Redis | The existing shared `dev-redis` container, logical DB index **5** (0-4 already taken by core/superadmin, appointments, opd, ipd, labs respectively — confirmed by inspecting each service's `REDIS_URL` before picking an unused index) — mirrors every other service's own "shared container, dedicated index" pattern exactly. |
| Signing-key storage | A dedicated named Docker volume (`blumax-dev-auth_auth_devkeys`) mounted at `/app/.dev-keys`, letting the service's own existing dev-key fallback (`app/core/keys.py::_load_or_create_dev_key`) generate once and persist — identical mechanism to the app's own `docker-compose.yml`. |
| Compose definition | `dev-infra/apps/auth/docker-compose.yml`, modeled directly on `apps/labs/docker-compose.yml`'s shape (image/build/env_file/networks/restart-policy). **Not** added to `dev-infra/apps/deploy.py`'s automation — that driver's `--run` path is explicitly reserved for its own planned rehearsal sequence (starting with `notifications`, per its own docstring) and extending it to a brand-new service type was out of this phase's scope; this compose file was built and run manually, following the same conventions. |
| Migration mechanism | `auth-migrate` service (profile-gated, `alembic upgrade head`), same pattern as `labs-migrate`. |
| Networking | `dev-net` (`blumax-dev-net`, for other dev services to reach it) + `legacy-net` (`blumax-platform_blumax-net`, to reach the shared Postgres). |
| nginx / reverse proxy | **None added, deliberately.** Phase 4G-0's audit found Labs' own password-delegation and SSO calls are all server-to-server (Labs' backend calls Blumax Auth's API directly over the internal network); no browser ever needs to reach Blumax Auth directly under the current design. If that design changes, an nginx route becomes a required follow-up — flagged, not built speculatively. |
| Health check | The image's own built-in `HEALTHCHECK` (`GET /health` on port 8040). |

Internal service address: **`http://auth:8040`** (reachable from any
container on `blumax-dev-net`, e.g. Labs/Superadmin). No public DNS name
exists or was created.

## Verification (all performed live against the real deployed container)

| Check | Result |
|---|---|
| `GET /health` | `{"status":"ok","database":"ok","redis":"ok","signing_key":"ok"}` |
| `GET /.well-known/jwks.json` | Real RS256 public key returned, `kid` present |
| `POST /auth/login` | 200, real access+refresh token pair, for a disposable dev user created via `scripts/create_dev_user.py` |
| `POST /auth/refresh` | 200, rotated token pair |
| Refresh-token reuse detection | Reusing the already-rotated refresh token → `401 "Refresh token reuse detected -- all sessions revoked"`; confirmed the **blast radius is real**: the second (still-fresh) refresh token from the same session was also invalidated, not just the reused one |
| `POST /auth/logout` | 204, and the refresh token was dead immediately afterward |
| Wrong password | 401, correctly rejected |

## Database isolation, confirmed live

- `blumax_auth` role querying Labs' own `lab_user` table: `ERROR: permission denied for table lab_user`.
- No Core or Labs DSN exists anywhere in `blumax-auth`'s code (reconfirmed, Phase 4G-0).

## What was NOT done

- `dev-infra/apps/deploy.py` was not modified (no new `REPO`/`ORDER`/`DBS` entries for `auth`).
- No nginx/ingress route was added.
- No production system, database, Redis, or DNS was touched.
- No key rotation was performed or needed (fresh dev key generated once, as designed).

## Cleanup performed at phase end

Five disposable dev-auth test identities created during this phase's
verification work were deleted after use; the real, migrated identities
(Workstream D) were left intact. A test-named service account
(`blumax-labs-dev-sso`) was replaced with a permanently-named one
(`blumax-labs-sso`) actually wired into `dev-labs`'s real environment file.
