"""Core audit engine.

Given an SCM snapshot plus resolved ACLs for service binaries, their
parent directories and the service objects themselves, decide whether a
low-privilege principal can hijack each service by replacing its binary,
modifying its parameters, or reconfiguring the service.
"""

from __future__ import annotations

import os

from .acl import controls_object, effective_rights
from .models import (
    DIR_REPLACE_RIGHTS,
    FILE_MODIFY_RIGHTS,
    HIGH_VALUE_ACCOUNTS,
    SCRIPT_EXTENSIONS,
    SERVICE_CONFIG_RIGHTS,
    Capability,
    Evidence,
    EvidenceKind,
    ObjectACL,
    ServiceConfig,
    ServiceReport,
    Severity,
)


def normalize_path(path: str) -> str:
    return path.strip().replace("/", "\\").rstrip("\\").lower()


def parent_dir(path: str) -> str:
    return path.rsplit("\\", 1)[0] if "\\" in path else ""


def split_binary_path(command_line: str) -> tuple[str, str, bool]:
    """Split an SCM BINARY_PATH_NAME into (executable, arguments, quoted)."""
    command_line = command_line.strip()
    if command_line.startswith('"'):
        end = command_line.find('"', 1)
        if end != -1:
            return command_line[1:end], command_line[end + 1 :].strip(), True
    lowered = command_line.lower()
    exe_at = lowered.find(".exe")
    if exe_at != -1:
        end = exe_at + len(".exe")
        return command_line[:end], command_line[end:].strip(), False
    parts = command_line.split(None, 1)
    return parts[0], (parts[1] if len(parts) > 1 else ""), False


def interception_candidates(exe_path: str) -> list[str]:
    """Candidate paths Windows tries for an unquoted path with spaces.

    `C:\\Program Files\\Foo Bar\\svc.exe` is probed as `C:\\Program.exe`,
    then `C:\\Program Files\\Foo.exe`, before the full path.
    """
    candidates: list[str] = []
    segments = exe_path.split("\\")
    for i in range(1, len(segments)):
        prefix = "\\".join(segments[:i])
        head, _, _ = segments[i].partition(" ")
        if head and " " in "\\".join(segments[i:]):
            candidates.append(prefix + "\\" + head + ".exe")
    return candidates


class AuditEngine:
    """Evaluates services from the perspective of one low-privilege user."""

    def __init__(
        self,
        attacker: str,
        attacker_groups: frozenset[str] | set[str] = frozenset(),
        file_acls: dict[str, ObjectACL] | None = None,
        dir_acls: dict[str, ObjectACL] | None = None,
    ) -> None:
        self.attacker = attacker
        self.attacker_groups = frozenset(attacker_groups)
        self.file_acls = {normalize_path(p): acl for p, acl in (file_acls or {}).items()}
        self.dir_acls = {normalize_path(p): acl for p, acl in (dir_acls or {}).items()}

    def audit(self, services: dict[str, ServiceConfig]) -> dict[str, ServiceReport]:
        reports: dict[str, ServiceReport] = {}
        visiting: list[str] = []

        def visit(name: str) -> ServiceReport:
            if name in visiting:
                cycle = visiting[visiting.index(name) :] + [name]
                report = ServiceReport(service=name, account=services[name].account)
                report.evidence.append(
                    Evidence(
                        EvidenceKind.DEPENDENCY_CYCLE,
                        "dependency cycle detected: " + " -> ".join(cycle),
                    )
                )
                return report
            if name in reports:
                return reports[name]
            visiting.append(name)
            report = self._audit_one(services[name])
            for dep in services[name].dependencies:
                if dep not in services:
                    report.evidence.append(
                        Evidence(
                            EvidenceKind.PATH_NOT_FOUND,
                            f"dependency {dep!r} not present in SCM export",
                        )
                    )
                    continue
                dep_report = visit(dep)
                if dep_report.capabilities:
                    report.capabilities |= dep_report.capabilities
                    report.evidence.append(
                        Evidence(
                            EvidenceKind.DEPENDENCY_CHAIN,
                            f"dependency {dep!r} is hijackable; "
                            f"{name!r} inherits {sorted(c.value for c in dep_report.capabilities)}",
                        )
                    )
                for ev in dep_report.evidence:
                    if ev.kind is EvidenceKind.DEPENDENCY_CYCLE and not any(
                        e.kind is EvidenceKind.DEPENDENCY_CYCLE for e in report.evidence
                    ):
                        report.evidence.append(ev)
            visiting.pop()
            report.severity = self._severity(services[name], report)
            reports[name] = report
            return report

        for name in services:
            visit(name)
        return reports

    def _audit_one(self, service: ServiceConfig) -> ServiceReport:
        report = ServiceReport(service=service.name, account=service.account)
        exe_path, arguments, quoted = split_binary_path(service.binary_path)
        exe_key = normalize_path(exe_path)

        self._check_file(exe_key, report)
        self._check_parent_dir(exe_key, report)
        self._check_script(exe_path, arguments, report)
        if not quoted and " " in exe_path:
            self._check_unquoted(exe_path, report)
        self._check_service_acl(service, report)
        return report

    def _check_file(self, exe_key: str, report: ServiceReport) -> None:
        acl = self.file_acls.get(exe_key)
        if acl is None:
            report.evidence.append(
                Evidence(
                    EvidenceKind.PATH_NOT_FOUND,
                    "no ACL snapshot for service binary",
                    path=exe_key,
                )
            )
            return
        rights = effective_rights(acl, self.attacker, self.attacker_groups)
        granted = rights & FILE_MODIFY_RIGHTS
        if granted:
            report.capabilities.add(Capability.REPLACE_BINARY)
            report.evidence.append(
                Evidence(
                    EvidenceKind.WRITABLE_FILE,
                    f"{self.attacker} holds {sorted(granted)} on the service binary",
                    path=exe_key,
                )
            )
        if controls_object(acl, self.attacker, self.attacker_groups):
            report.capabilities.add(Capability.REPLACE_BINARY)
            report.evidence.append(
                Evidence(
                    EvidenceKind.OWNER_CONTROL,
                    f"{self.attacker} can rewrite the binary's DACL "
                    f"(owner={acl.owner})",
                    path=exe_key,
                )
            )

    def _check_parent_dir(self, exe_key: str, report: ServiceReport) -> None:
        parent = parent_dir(exe_key)
        acl = self.dir_acls.get(parent)
        if acl is None:
            report.evidence.append(
                Evidence(
                    EvidenceKind.PATH_NOT_FOUND,
                    "no ACL snapshot for the binary's parent directory",
                    path=parent or exe_key,
                )
            )
            return
        rights = effective_rights(acl, self.attacker, self.attacker_groups)
        granted = rights & DIR_REPLACE_RIGHTS
        if granted:
            report.capabilities.add(Capability.REPLACE_BINARY)
            report.evidence.append(
                Evidence(
                    EvidenceKind.WRITABLE_PARENT_DIR,
                    f"{self.attacker} holds {sorted(granted)} on the binary's "
                    "parent directory and can delete/recreate it",
                    path=parent,
                )
            )
        if controls_object(acl, self.attacker, self.attacker_groups):
            report.capabilities.add(Capability.REPLACE_BINARY)
            report.evidence.append(
                Evidence(
                    EvidenceKind.OWNER_CONTROL,
                    f"{self.attacker} can rewrite the parent directory's DACL "
                    f"(owner={acl.owner})",
                    path=parent,
                )
            )

    def _check_script(self, exe_path: str, arguments: str, report: ServiceReport) -> None:
        ext = os.path.splitext(exe_path)[1].lower()
        script_path = exe_path
        if ext not in SCRIPT_EXTENSIONS and arguments:
            arg_ext = os.path.splitext(arguments.split()[0])[1].lower()
            if arg_ext in SCRIPT_EXTENSIONS:
                script_path = arguments.split()[0].strip('"')
                ext = arg_ext
        if ext not in SCRIPT_EXTENSIONS:
            return
        report.capabilities.add(Capability.MODIFY_PARAMETERS)
        report.evidence.append(
            Evidence(
                EvidenceKind.SCRIPT_INTERPRETER_PATH,
                f"service runs a {ext} script via an interpreter; the script "
                "body and any interpreter on PATH are attack surface",
                path=normalize_path(script_path),
            )
        )

    def _check_unquoted(self, exe_path: str, report: ServiceReport) -> None:
        for candidate in interception_candidates(exe_path):
            parent = parent_dir(normalize_path(candidate))
            acl = self.dir_acls.get(parent)
            if acl is None:
                continue
            rights = effective_rights(acl, self.attacker, self.attacker_groups)
            granted = rights & DIR_REPLACE_RIGHTS
            if granted or controls_object(acl, self.attacker, self.attacker_groups):
                report.capabilities.add(Capability.REPLACE_BINARY)
                report.evidence.append(
                    Evidence(
                        EvidenceKind.UNQUOTED_PATH,
                        f"unquoted path with spaces; {self.attacker} can plant "
                        f"{candidate!r} in writable directory {parent!r}",
                        path=candidate,
                    )
                )

    def _check_service_acl(self, service: ServiceConfig, report: ServiceReport) -> None:
        acl = service.service_acl
        if acl is None:
            return
        rights = effective_rights(acl, self.attacker, self.attacker_groups)
        granted = rights & SERVICE_CONFIG_RIGHTS
        can_control = controls_object(acl, self.attacker, self.attacker_groups)
        if granted or can_control:
            report.capabilities.add(Capability.RECONFIGURE_SERVICE)
            report.capabilities.add(Capability.MODIFY_PARAMETERS)
            how = f"holds {sorted(granted)}" if granted else "controls the service DACL"
            report.evidence.append(
                Evidence(
                    EvidenceKind.WEAK_SERVICE_ACL,
                    f"{self.attacker} {how} on service {service.name!r} and can "
                    "change binPath/start parameters",
                )
            )

    @staticmethod
    def _severity(service: ServiceConfig, report: ServiceReport) -> Severity:
        if report.capabilities:
            if service.account.lower() in HIGH_VALUE_ACCOUNTS:
                return Severity.CRITICAL
            return Severity.HIGH
        if any(e.kind is EvidenceKind.PATH_NOT_FOUND for e in report.evidence):
            return Severity.UNKNOWN
        return Severity.NONE
