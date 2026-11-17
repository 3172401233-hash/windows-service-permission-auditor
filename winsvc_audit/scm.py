"""Parser for `sc.exe qc`-style SCM exports.

Accepts the concatenated output of `sc qc <service>` for one or more
services and produces ServiceConfig objects. ACLs are attached separately
by the caller.
"""

from __future__ import annotations

import re

from .models import ServiceConfig

_SERVICE_NAME_RE = re.compile(r"^SERVICE_NAME:\s*(?P<name>.+?)\s*$")
_FIELD_RE = re.compile(r"^\s*(?P<key>[A-Z_]+)\s*:\s*(?P<value>.*)$")

_START_TYPES = {
    "0": "BOOT_START",
    "1": "SYSTEM_START",
    "2": "AUTO_START",
    "3": "DEMAND_START",
    "4": "DISABLED",
}


def parse_scm_export(text: str) -> dict[str, ServiceConfig]:
    """Parse one or more `sc qc` blocks into ServiceConfig objects."""
    services: dict[str, ServiceConfig] = {}
    current: dict[str, str] | None = None
    current_name: str | None = None
    dependencies: list[str] = []
    in_dependencies = False

    def flush() -> None:
        nonlocal current, current_name, dependencies
        if current is None or current_name is None:
            return
        start_raw = current.get("START_TYPE", "2").split()[0]
        services[current_name] = ServiceConfig(
            name=current_name,
            account=current.get("SERVICE_START_NAME", "LocalSystem"),
            binary_path=current.get("BINARY_PATH_NAME", ""),
            start_type=_START_TYPES.get(start_raw, start_raw),
            dependencies=tuple(dependencies),
        )
        current = None
        current_name = None
        dependencies = []

    for line in text.splitlines():
        name_match = _SERVICE_NAME_RE.match(line)
        if name_match:
            flush()
            current = {}
            current_name = name_match.group("name")
            in_dependencies = False
            continue
        if current is None:
            continue
        field_match = _FIELD_RE.match(line)
        if field_match:
            key = field_match.group("key")
            value = field_match.group("value").strip()
            in_dependencies = key == "DEPENDENCIES"
            if in_dependencies:
                if value:
                    dependencies.append(value)
                continue
            current[key] = value
            continue
        # Continuation lines: sc.exe wraps long DEPENDENCIES lists onto
        # indented lines shaped like "                           : DcomLaunch".
        if in_dependencies and line.strip():
            dependencies.append(line.strip().lstrip(":").strip())

    flush()
    return services
