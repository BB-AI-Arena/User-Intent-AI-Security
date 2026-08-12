from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class DestructivePattern:
    identifier: str
    platforms: tuple[str, ...]
    category: str
    score: int
    pattern: re.Pattern[str]
    description: str


def _rx(value: str) -> re.Pattern[str]:
    return re.compile(value, re.IGNORECASE)


DESTRUCTIVE_ACTIONS = (
    DestructivePattern("recursive-delete-unix", ("linux", "macos"), "filesystem", 55, _rx(r"(?:^|[;&|]\s*)rm\s+[^\n]*(?:-[a-z]*r[a-z]*|--recursive)\b"), "Recursively deletes files or directories."),
    DestructivePattern("recursive-delete-windows", ("windows",), "filesystem", 55, _rx(r"(?:remove-item\b[^\n]*(?:-recurse|-force)|rmdir\s+/s\b|rd\s+/s\b|del\s+/[sqf])"), "Recursively or forcibly deletes Windows filesystem content."),
    DestructivePattern("filesystem-format", ("all",), "storage", 90, _rx(r"(?:\bmkfs(?:\.[a-z0-9]+)?\b|\bformat(?:\.com)?\s+[a-z]:|format-volume\b)"), "Formats a filesystem or volume."),
    DestructivePattern("raw-disk-write", ("all",), "storage", 90, _rx(r"(?:\bdd\b[^\n]*\bof=/dev/|clear-disk\b|initialize-disk\b|diskpart\b)"), "Writes to or reinitializes raw storage."),
    DestructivePattern("partition-change", ("all",), "storage", 75, _rx(r"(?:\bfdisk\b|\bparted\b|remove-partition\b|resize-partition\b)"), "Changes disk partitions."),
    DestructivePattern("boot-change", ("all",), "system", 80, _rx(r"(?:\bgrub-install\b|\bupdate-grub\b|\bbcdedit\b|\bbootrec\b)"), "Changes boot configuration."),
    DestructivePattern("shutdown-reboot", ("all",), "availability", 40, _rx(r"(?:\bshutdown\b|\breboot\b|\bpoweroff\b|restart-computer\b|stop-computer\b)"), "Stops or restarts a machine."),
    DestructivePattern("service-disable", ("all",), "availability", 45, _rx(r"(?:systemctl\s+(?:disable|mask|stop)\b|service\s+\S+\s+stop\b|stop-service\b|set-service\b[^\n]*disabled|sc(?:\.exe)?\s+(?:delete|stop|config)\b)"), "Stops, disables, masks, or deletes a service."),
    DestructivePattern("firewall-change", ("all",), "network", 50, _rx(r"(?:iptables\b|nft\b|ufw\s+(?:disable|reset|delete)|netsh\s+advfirewall|new-netfirewallrule|remove-netfirewallrule|set-netfirewallprofile)"), "Changes host firewall policy."),
    DestructivePattern("network-reset", ("all",), "network", 50, _rx(r"(?:ip\s+(?:addr|route|link)\s+(?:del|flush)|ifconfig\b[^\n]*down|netsh\s+(?:interface|winsock)\s+reset|disable-netadapter|remove-netroute)"), "Disables or resets network configuration."),
    DestructivePattern("user-account-change", ("all",), "identity", 55, _rx(r"(?:userdel\b|deluser\b|usermod\b|passwd\b|net\s+user\b|remove-localuser\b|disable-localuser\b|set-localuser\b)"), "Changes or deletes a user account."),
    DestructivePattern("group-membership-change", ("all",), "identity", 60, _rx(r"(?:groupdel\b|gpasswd\b|add-localgroupmember\b|remove-localgroupmember\b|net\s+localgroup\b)"), "Changes privileged or local group membership."),
    DestructivePattern("permission-change", ("all",), "identity", 45, _rx(r"(?:chmod\b|chown\b|setfacl\b|icacls\b|takeown\b)"), "Changes ownership or access permissions."),
    DestructivePattern("scheduled-persistence", ("all",), "persistence", 55, _rx(r"(?:crontab\b|at\b|schtasks\b|register-scheduledtask\b|new-service\b|systemctl\s+enable\b)"), "Creates or alters scheduled execution or service persistence."),
    DestructivePattern("package-removal", ("all",), "software", 45, _rx(r"(?:(?:apt|apt-get|yum|dnf|pacman|zypper)\s+(?:remove|purge|autoremove)\b|uninstall-package\b|winget\s+uninstall\b|choco\s+uninstall\b)"), "Removes installed software or dependencies."),
    DestructivePattern("database-destructive", ("all",), "database", 80, _rx(r"\b(?:drop\s+(?:database|schema|table)|truncate\s+table|delete\s+from\s+\S+\s*;?)\b"), "Deletes database objects or bulk data."),
    DestructivePattern("container-prune", ("all",), "container", 55, _rx(r"(?:docker\s+(?:system|image|volume|container)\s+prune\b|docker\s+rm\b[^\n]*-[a-z]*f|podman\s+system\s+prune\b)"), "Removes container resources."),
    DestructivePattern("cluster-delete", ("all",), "orchestration", 65, _rx(r"(?:kubectl\s+delete\b|helm\s+uninstall\b|terraform\s+destroy\b)"), "Deletes cluster or infrastructure resources."),
    DestructivePattern("cloud-delete", ("all",), "cloud", 70, _rx(r"(?:(?:aws|az|gcloud)\b[^\n]*\b(?:delete|terminate|destroy|remove)\b)"), "Deletes or terminates cloud resources."),
    DestructivePattern("git-history-rewrite", ("all",), "source-control", 55, _rx(r"(?:git\s+push\b[^\n]*(?:--force|-f)\b|git\s+reset\s+--hard\b|git\s+clean\b[^\n]*-[a-z]*f)"), "Rewrites remote history or discards local work."),
    DestructivePattern("registry-delete", ("windows",), "system", 65, _rx(r"(?:reg(?:\.exe)?\s+delete\b|remove-item\b[^\n]*(?:hklm:|hkcu:))"), "Deletes Windows registry data."),
    DestructivePattern("shadow-copy-delete", ("windows",), "recovery", 90, _rx(r"(?:vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|delete-shadowcopy)"), "Deletes recovery shadow copies."),
    DestructivePattern("log-erasure", ("all",), "evasion", 75, _rx(r"(?:journalctl\s+--vacuum|wevtutil\s+cl\b|clear-eventlog\b|remove-item\b[^\n]*(?:/var/log|\\winevt\\logs))"), "Erases or truncates audit logs."),
    DestructivePattern("security-control-change", ("all",), "defense-evasion", 85, _rx(r"(?:set-mppreference\b[^\n]*(?:disablerealtimemonitoring|disablebehaviormonitoring)|uninstall-windowsfeature\b[^\n]*defender|systemctl\s+(?:stop|disable|mask)\b[^\n]*(?:auditd|apparmor|selinux)|setenforce\s+0\b)"), "Disables or weakens security controls."),
)


def match_destructive_actions(command: str) -> list[DestructivePattern]:
    return [item for item in DESTRUCTIVE_ACTIONS if item.pattern.search(command)]

