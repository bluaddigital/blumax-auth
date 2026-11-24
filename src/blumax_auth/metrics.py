"""Optional Prometheus counters for the library's calls to Core (O9).

    blumax_core_permission_calls_total{outcome}

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
    "role_map_hit",       # 0.6.0: answered from the role -> codes map (token pv current); Core not asked
    "role_map_fallback",  # 0.6.0: role map on but not usable for this request (old pv, no claims, Redis doubt...): asked the old way
    "role_map_fetch",     # 0.6.0: one GET /identity/role-permissions (new grant version or new role set)
})
# Any other value passed in is counted as "unknown" so the label set stays closed.

_lock = threading.Lock()
_tally: _Tally[str] = _Tally()
_prom: Any = None          # the prometheus Counter, once resolved
_resolved = False


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


def snapshot() -> dict[str, int]:
    """This process's counts per outcome (independent of the Prometheus flag)."""
    return dict(_tally)


def reset_metrics() -> None:
    """Forget counts and re-read the flag on next use. Tests only."""
    global _prom, _resolved
    with _lock:
        _tally.clear()
        _prom = None
        _resolved = False
