"""Optional Prometheus counters for the library's calls to Core (O9).

    blumax_core_permission_calls_total{outcome}
    blumax_session_revocation_total{outcome}
    blumax_permission_local_total{outcome}            (0.6.0: local evaluator, shadow/local modes)
    blumax_token_service_audience_missing_total       (0.6.0: v2 token without this service's audience)

One increment per outcome of the permission client (see OUTCOMES). The counter is
registered in prometheus_client's default registry, so a service that already
serves /metrics from that registry exposes it with no further code.

Off unless the process environment has BLUMAX_METRICS_ENABLED=true (read once, on
first use). prometheus_client is NOT a dependency of this package: install the
`metrics` extra (`pip install blumax-auth[metrics]`) or have it in the service
already. Enabled but not installed -> one warning, then nothing (a missing metrics
library never breaks a permission check).

`snapshot()` returns this process's counts whether or not Prometheus is enabled
(plain dict, used by tests and for debugging); it costs one dict increment.
"""
from __future__ import annotations

import logging
import os
import threading
from collections import Counter as _Tally
from typing import Any

_log = logging.getLogger("blumax_auth.metrics")

ENV_FLAG = "BLUMAX_METRICS_ENABLED"
PERMISSION_CALLS = "blumax_core_permission_calls_total"

#: Every `outcome` label value the permission client emits. Fixed and small (no
#: tenant, user, route or status code in a label), so the series count is bounded.
OUTCOMES = frozenset({
    "ok",            # Core answered 200 with a well-formed permission list
    "unauthorized",  # Core answered 401 (token refused)
    "forbidden",     # Core answered 403/404 (no access to the tenant)
    "server_error",  # Core answered another non-200 status
    "malformed",     # 200 with a body that is not the documented shape
    "timeout",       # no answer: httpx timeout
    "unreachable",   # no answer: connection error / other transport error
    "breaker_open",  # refused locally, Core not asked (circuit breaker open)
    "retried",       # a no-answer attempt is being asked once more (C3)
    "stale_served",  # an expired answer was served during an outage (C4)
})
# Any other value passed in is counted as "unknown" so the label set stays closed.

SESSION_REVOCATION = "blumax_session_revocation_total"

#: Every `outcome` label value of the session-revocation check (fixed and small, like OUTCOMES).
SESSION_OUTCOMES = frozenset({
    "cache_hit",             # answered from this process's session-status cache; the store was not asked
    "cache_miss",            # cache on, no usable entry: a store read follows (shared by concurrent callers)
    "store_reads",           # one real round trip to the revocation store
    "store_unavailable",     # revocation_store_unavailable: the store did not answer (timeout/error/breaker open)
    "stale_read_served",     # split mode: a safe read passed on the last known status inside the stale window
    "rejected_unavailable",  # split mode: refused with 503 because the store is unavailable
    "revoked",               # a revoked session was refused
})

_lock = threading.Lock()
_tally: _Tally[str] = _Tally()
_prom: Any = None          # the prometheus Counter, once resolved
_resolved = False
_session_tally: _Tally[str] = _Tally()
_session_prom: Any = None
_session_resolved = False


def _enabled() -> bool:
    return os.environ.get(ENV_FLAG, "").strip().lower() in ("1", "true", "yes", "on")


def _prometheus_counter() -> Any:
    global _prom, _resolved
    if _resolved:
        return _prom
    with _lock:
        if _resolved:
            return _prom
        if _enabled():
            try:
                from prometheus_client import Counter  # noqa: PLC0415 - optional dependency
            except ImportError:
                _log.warning("metrics_unavailable", extra={"reason": "prometheus_client not installed", "flag": ENV_FLAG})
            else:
                try:
                    _prom = Counter(PERMISSION_CALLS, "Outcomes of blumax-auth permission lookups against Core", ["outcome"])
                except ValueError:  # already registered (module reloaded in the same process)
                    from prometheus_client import REGISTRY  # noqa: PLC0415

                    _prom = REGISTRY._names_to_collectors.get(PERMISSION_CALLS)  # type: ignore[attr-defined]
        _resolved = True
    return _prom


def core_permission_call(outcome: str) -> None:
    """Count one permission-client outcome. Never raises."""
    if outcome not in OUTCOMES:  # programming error; keep the label set closed
        outcome = "unknown"
    try:
        _tally[outcome] += 1
        counter = _prometheus_counter()
        if counter is not None:
            counter.labels(outcome=outcome).inc()
    except Exception:  # pragma: no cover - metrics must never break a check
        _log.exception("metrics_increment_failed")


def _prometheus_session_counter() -> Any:
    global _session_prom, _session_resolved
    if _session_resolved:
        return _session_prom
    with _lock:
        if _session_resolved:
            return _session_prom
        if _enabled():
            try:
                from prometheus_client import Counter  # noqa: PLC0415 - optional dependency
            except ImportError:
                _log.warning("metrics_unavailable", extra={"reason": "prometheus_client not installed", "flag": ENV_FLAG})
            else:
                try:
                    _session_prom = Counter(SESSION_REVOCATION, "Outcomes of blumax-auth session-revocation checks", ["outcome"])
                except ValueError:  # already registered (module reloaded in the same process)
                    from prometheus_client import REGISTRY  # noqa: PLC0415

                    _session_prom = REGISTRY._names_to_collectors.get(SESSION_REVOCATION)  # type: ignore[attr-defined]
        _session_resolved = True
    return _session_prom


def session_revocation_event(outcome: str) -> None:
    """Count one session-revocation outcome (see SESSION_OUTCOMES). Never raises."""
    if outcome not in SESSION_OUTCOMES:
        outcome = "unknown"
    try:
        _session_tally[outcome] += 1
        counter = _prometheus_session_counter()
        if counter is not None:
            counter.labels(outcome=outcome).inc()
    except Exception:  # pragma: no cover - metrics must never break a check
        _log.exception("metrics_increment_failed")


def session_snapshot() -> dict[str, int]:
    """This process's session-revocation counts per outcome (independent of the Prometheus flag)."""
    return dict(_session_tally)


class _Family:
    """One optional Prometheus counter with a closed label set plus an always-on per-process tally (0.6.0)."""

    def __init__(self, name: str, doc: str, outcomes: frozenset[str] | None) -> None:
        self.name, self.doc, self.outcomes = name, doc, outcomes
        self.tally: _Tally[str] = _Tally()
        self.prom: Any = None
        self.resolved = False

    def _counter(self) -> Any:
        if self.resolved:
            return self.prom
        with _lock:
            if self.resolved:
                return self.prom
            if _enabled():
                try:
                    from prometheus_client import Counter  # noqa: PLC0415 - optional dependency
                except ImportError:
                    _log.warning("metrics_unavailable", extra={"reason": "prometheus_client not installed", "flag": ENV_FLAG})
                else:
                    labels = ["outcome"] if self.outcomes is not None else []
                    try:
                        self.prom = Counter(self.name, self.doc, labels)
                    except ValueError:  # already registered (module reloaded in the same process)
                        from prometheus_client import REGISTRY  # noqa: PLC0415

                        self.prom = REGISTRY._names_to_collectors.get(self.name)  # type: ignore[attr-defined]
            self.resolved = True
        return self.prom

    def inc(self, outcome: str = "") -> None:
        if self.outcomes is not None and outcome not in self.outcomes:
            outcome = "unknown"
        try:
            self.tally[outcome] += 1
            counter = self._counter()
            if counter is not None:
                (counter.labels(outcome=outcome) if self.outcomes is not None else counter).inc()
        except Exception:  # pragma: no cover - metrics must never break a check
            _log.exception("metrics_increment_failed")

    def reset(self) -> None:
        self.tally.clear()
        self.prom = None
        self.resolved = False


PERMISSION_LOCAL = "blumax_permission_local_total"

#: Fallback reasons of the local permission evaluator (local_permissions.py). Fixed and small.
LOCAL_FALLBACK_REASONS = frozenset({
    "v1_token",                  # the token is not access token v2
    "service_token",             # service tokens keep the Core path (v2 service tokens: G8)
    "admin_route",               # local mode: require_permission/check_permission(admin=True) always asks Core
    "token_unreadable",          # the claims could not be re-read or do not match the verified context
    "no_perm",                   # v2 token without a (well-formed) perm claim: Core could not build it
    "no_authz_ver",              # v2 token without authz_ver: Redis was down when Core minted it
    "authz_ver_not_configured",  # no Redis to read the current authz_ver from
    "authz_ver_unavailable",     # Redis did not answer (timeout, error, NOPERM ACL)
    "authz_ver_unset",           # authctx:authz_ver is not in Redis (flushed, or the wrong Redis/db)
    "authz_ver_stale",           # token authz_ver != current: an authorization write happened since mint
    "catalogue_loading",         # no catalogue yet: the background preload is in flight (0.6.1)
    "catalogue_unavailable",     # no catalogue: the last fetch from Core failed (backing off)
    "catalogue_behind",          # Core's catalogue is older than the token's cv even after a refetch
    "invalid_bitset",            # bitset not base64url, or names an index the catalogue does not have
    "unknown_code",              # the code being checked is not in the catalogue
    "error",                     # anything unexpected (logged with a traceback)
})

#: Every `outcome` label of blumax_permission_local_total.
LOCAL_OUTCOMES = frozenset(
    {"match", "mismatch", "local_allow", "local_deny"} | {f"fallback:{r}" for r in LOCAL_FALLBACK_REASONS}
)

_local = _Family(PERMISSION_LOCAL, "Local (token) permission evaluation outcomes: shadow comparison and local decisions", LOCAL_OUTCOMES)
_audience = _Family(
    "blumax_token_service_audience_missing_total",
    "v2 access tokens accepted although their aud list lacks this service's audience (enforced from G6)",
    None,
)


def permission_local_event(outcome: str) -> None:
    """Count one local-evaluator outcome (see LOCAL_OUTCOMES). Never raises."""
    _local.inc(outcome)


def local_snapshot() -> dict[str, int]:
    """This process's local-evaluator counts per outcome (independent of the Prometheus flag)."""
    return dict(_local.tally)


def service_audience_missing() -> None:
    """Count one v2 token that lacks the configured service audience. Never raises."""
    _audience.inc("")


def audience_snapshot() -> int:
    return sum(_audience.tally.values())


def snapshot() -> dict[str, int]:
    """This process's counts per outcome (independent of the Prometheus flag)."""
    return dict(_tally)


def reset_metrics() -> None:
    """Forget counts and re-read the flag on next use. Tests only."""
    global _prom, _resolved, _session_prom, _session_resolved
    with _lock:
        _tally.clear()
        _session_tally.clear()
        _prom = None
        _resolved = False
        _session_prom = None
        _session_resolved = False
    _local.reset()
    _audience.reset()
