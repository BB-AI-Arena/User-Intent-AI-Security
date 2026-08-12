from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class PrivilegeContext:
    is_root: bool
    is_admin: bool
    level: str


def detect_privilege() -> PrivilegeContext:
    if os.name == "nt":
        try:
            elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            elevated = False
        return PrivilegeContext(False, elevated, "administrator" if elevated else "standard")
    try:
        root = os.geteuid() == 0
    except AttributeError:
        root = False
    if root:
        return PrivilegeContext(True, True, "root")
    try:
        import grp
        admin_groups = {"sudo", "wheel", "admin"}
        group_names = {grp.getgrgid(group_id).gr_name for group_id in os.getgroups()}
        admin = bool(group_names & admin_groups)
    except (KeyError, OSError):
        admin = False
    return PrivilegeContext(False, admin, "administrator-capable" if admin else "standard")
