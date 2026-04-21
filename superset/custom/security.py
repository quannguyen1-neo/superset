"""
superset/custom/security.py
---------------------------
QueryOnlyMixin — strips chart, dashboard, and explore permissions.
Compose into whatever SecurityManager your overlay defines.

Usage in enable_oauth.yaml:
    from superset.custom.security import QueryOnlyMixin
    from superset.security import SupersetSecurityManager

    class CustomSecurityManager(QueryOnlyMixin, SupersetSecurityManager):
        ...
"""

import logging
from superset.security import SupersetSecurityManager

logger = logging.getLogger("superset.custom.security")


# ---------------------------------------------------------------------------
# Stripped from ALL roles including Admin
# ---------------------------------------------------------------------------
BLOCKED_PERMISSIONS: set[tuple[str, str]] = {
    # Chart — full CRUD
    ("can_write",                   "Chart"),
    ("can_add",                     "Chart"),
    ("can_edit",                    "Chart"),
    ("can_delete",                  "Chart"),
    ("can_import",                  "Chart"),
    ("can_export",                  "Chart"),

    # Dashboard — full CRUD
    ("can_write",                   "Dashboard"),
    ("can_add",                     "Dashboard"),
    ("can_edit",                    "Dashboard"),
    ("can_delete",                  "Dashboard"),
    ("can_import",                  "Dashboard"),
    ("can_export",                  "Dashboard"),

    # Explore / chart builder — all access
    ("can_explore",                 "Superset"),
    ("can_explore_json",            "Superset"),
    ("can_add_slices",              "Superset"),
    ("can_save_dash",               "Superset"),
    ("can_copy_dash",               "Superset"),
    ("can_edit_charttype",          "Superset"),
    ("can_read",                    "Explore"),
    ("can_write",                   "ExploreFormDataRestApi"),
    ("can_read",                    "ExploreFormDataRestApi"),
    ("can_write",                   "ExplorePermalinkRestApi"),
    ("can_read",                    "ExplorePermalinkRestApi"),
}


# ---------------------------------------------------------------------------
# Stripped from non-Admin roles only
# ---------------------------------------------------------------------------
NON_ADMIN_BLOCKED_PERMISSIONS: set[tuple[str, str]] = {
    # Database connection management
    ("can_write",       "Database"),
    ("can_upload",      "Database"),
    ("menu_access",     "Databases"),

    # File uploads
    ("can_csv",         "Superset"),
    ("can_upload_csv",  "Superset"),
}

ADMIN_ROLES: frozenset[str] = frozenset({"Admin"})


# ---------------------------------------------------------------------------
# Mixin
# ---------------------------------------------------------------------------
class QueryOnlyMixin:
    """
    Mixin — handles permission stripping only.
    No OAuth logic, no role mappings — those stay in the yaml overlay.

    MRO when composed:
        CustomSecurityManager
            -> QueryOnlyMixin.sync_role_definitions()
                -> super() -> SupersetSecurityManager.sync_role_definitions()
    """

    def sync_role_definitions(self) -> None:
        super().sync_role_definitions()
        self._strip_blocked_permissions()

    def _strip_blocked_permissions(self) -> None:
        roles = self.get_all_roles()
        logger.info(
            "[QueryOnly] Scanning %d role(s) for blocked permissions.", len(roles)
        )
        for role in roles:
            is_admin = role.name in ADMIN_ROLES
            to_remove = [
                pv for pv in role.permissions
                if self._is_blocked(pv, is_admin)
            ]
            for pv in to_remove:
                self.del_permission_role(role, pv)
                logger.debug(
                    "[QueryOnly] Removed (%s, %s) from role '%s'.",
                    pv.permission.name, pv.view_menu.name, role.name,
                )
            if to_remove:
                logger.info(
                    "[QueryOnly] Role '%s': removed %d permission(s).",
                    role.name, len(to_remove),
                )

    @staticmethod
    def _is_blocked(pv, is_admin: bool) -> bool:
        try:
            pair = (pv.permission.name, pv.view_menu.name)
            if pair in BLOCKED_PERMISSIONS:
                return True
            if not is_admin and pair in NON_ADMIN_BLOCKED_PERMISSIONS:
                return True
            return False
        except AttributeError:
            return False