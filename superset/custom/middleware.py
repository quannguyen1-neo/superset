"""
QueryOnlyMiddleware
-------------------
WSGI middleware that blocks all mutating HTTP methods on Chart and
Dashboard REST endpoints at the transport layer — before any Flask
routing or FAB permission checks occur.

This is the last line of defence: even if a permission somehow
slips through (role sync race, future Superset upgrade re-adding a
perm), write operations are still rejected with 403.

Wire up in superset_config.py:
    from superset.custom.middleware import QueryOnlyMiddleware
    ADDITIONAL_MIDDLEWARE = [QueryOnlyMiddleware]
"""

import json
import logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

BLOCKED_PREFIXES: tuple[str, ...] = (
    "/api/v1/chart",
    "/api/v1/dashboard",
    "/api/v1/explore",
    "/chart/add",
    "/chart/edit",
    "/chartmodelview/add",
    "/chartmodelview/edit",
    "/dashboard/add",
    "/dashboard/edit",
    "/dashboardmodelview/add",
    "/dashboardmodelview/edit",
    "/explore/",
)

BLOCKED_METHODS: frozenset[str] = frozenset({"POST", "PUT", "DELETE", "PATCH"})

_BLOCKED_RESPONSE_BODY: bytes = json.dumps(
    {
        "message": "Chart and Dashboard mutations are disabled on this instance. "
                   "Use SQL Lab for all query operations.",
        "severity": "warning",
    }
).encode("utf-8")


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class QueryOnlyMiddleware:
    """
    PEP-3333 compliant WSGI middleware.

    Intercepts:
        - Any mutating method (POST/PUT/DELETE/PATCH) on chart/dashboard
          REST API paths.
        - Direct URL access to chart/dashboard add/edit views.

    Passes through:
        - GET requests (read-only browsing, if you still expose the views).
        - All SQL Lab / query execution paths (/api/v1/sqllab, /superset/sql_json).
        - Everything else.
    """

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        path: str   = environ.get("PATH_INFO", "")
        method: str = environ.get("REQUEST_METHOD", "GET")

        if self._is_blocked(path, method):
            logger.warning(
                "[QueryOnlyMiddleware] Blocked %s %s from %s",
                method,
                path,
                environ.get("REMOTE_ADDR", "unknown"),
            )
            return self._forbidden_response(environ, start_response)

        return self.app(environ, start_response)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_blocked(path: str, method: str) -> bool:
        if method not in BLOCKED_METHODS:
            return False
        return any(path.startswith(prefix) for prefix in BLOCKED_PREFIXES)

    @staticmethod
    def _forbidden_response(environ, start_response):
        status = "403 Forbidden"
        headers = [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(_BLOCKED_RESPONSE_BODY))),
            ("X-Query-Only-Block", "true"),
        ]
        start_response(status, headers)
        return [_BLOCKED_RESPONSE_BODY]
