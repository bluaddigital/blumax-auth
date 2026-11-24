# Role-map permission checks: rollout (blumax-auth 0.6.0 + Core PERMISSION_VERSION_CLAIMS_ENABLED)

Goal: services stop asking Core `GET /api/v1/me/permissions` per caller, without weakening revocation (a revoked role, permission,
membership or user must stop within ~30 s). Both sides ship with their switch **OFF**; nothing changes until the steps below.

## How it works (one paragraph)

Core's database bumps a per-tenant version on every write that changes who holds which role or whether they may act (triggers,
migration 231: memberships, additional roles, user active / deleted / must-change-password / platform-admin, tenant status) and a
global grants version on every role-permission write. New access tokens carry `rid` (role ids) and `pv` (the tenant version, read before
the roles). Core copies the versions to Redis (`role:perms:ver`, ZADD GT) every second. A service with the role map on checks the session
against the revocation markers, reads the versions (<= 5 s old), and if the token's `pv` is current resolves `rid` through a role -> codes
map it fetched once per grants version (`GET /api/v1/identity/role-permissions`). Otherwise, or on any doubt, it asks Core exactly as
in 0.5.2. Revocation bound: Core publish (~1 s) + version cache (<= 5 s), for tokens minted before the change too.

## Order

1. **Core first** (blumax-backend): deploy the release with migration 231 (triggers + table; harmless while the switch is off), then set
   `PERMISSION_VERSION_CLAIMS_ENABLED=true` on Core. Tokens minted from then on carry `rid` / `pv`; old tokens and services are unaffected.
   Check: `ZRANGE role:perms:ver 0 -1 WITHSCORES` on Core's Redis shows every tenant + `grants`.
   *If the redis-sec instance is in use:* add `+zadd` (pattern `role:perms:*` is already allowed) to `core-sec` and
   `+zmscore %R~role:perms:ver` to `rv-reader` in `blumax-platform/deploy/redis-sec/entrypoint.sh`; without that Core's publish is
   refused (logged) and every service simply falls back.
2. **Tag the library** (owner): `v0.6.0` on blumax-auth main.
3. **Repin ONE service** to `v0.6.0` (suggest OPD or Labs: highest `/me/permissions` rate). It must already call
   `configure_session_revocation()` (that Redis is where the versions are read). Deploy with the switch off: behaviour identical.
4. **Enable on that service**: `BLUMAX_PERMISSION_ROLE_MAP=true` (or `configure_permissions(role_map=True)`).
5. **Measure** for a day: Core's `/me/permissions` request count from that service (Core access log / request timing), and the service's
   `blumax_core_permission_calls_total{outcome}`: `role_map_hit` should dominate, `role_map_fetch` should be a handful per grant edit,
   `ok` (= real `/me/permissions` calls) should fall. A high `role_map_fallback` means tokens older than their tenant's last membership
   change (they are re-minted at refresh / the daily 02:00 reset) or a Redis / ACL problem (`permission_role_map_versions_unavailable`
   warnings).
6. Repeat 3-5 per service.

## Revocation check (do once on the first service)

With a test user: hold a token, remove the user's role (or the code from the role) in the admin console, and call a route guarded by that
code from the enabled service: refused within ~6 s. Then deactivate the user: refused (401) within ~6 s. Then stop Core's Redis briefly:
requests keep working through `/me/permissions` (fallback), never from the map.

## Turning it off

Service: unset `BLUMAX_PERMISSION_ROLE_MAP` and restart (back to 0.5.2 behaviour at once). Core: `PERMISSION_VERSION_CLAIMS_ENABLED=false`
stops new claims, the publisher and the endpoint (404); services then fall back for every request. The triggers stay (cheap).

## After a database restore

Raise every version past what Redis and services saw before re-enabling:
`UPDATE permission_versions SET version = version + 1000000;`
