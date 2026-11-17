"""Data model for the Windows service permission auditor.

All inputs are plain Python objects so the auditor can be fed from an SCM
export, hand-built fixtures, or a JSON snapshot collected on a host.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Rights:
    """Subset of Windows access rights relevant to service hijacking."""

    # File / directory rights
    FILE_WRITE_DATA = "FILE_WRITE_DATA"
    FILE_APPEND_DATA = "FILE_APPEND_DATA"
    FILE_ADD_FILE = "FILE_ADD_FILE"
    FILE_DELETE_CHILD = "FILE_DELETE_CHILD"
    DELETE = "DELETE"
    WRITE_DAC = "WRITE_DAC"
    WRITE_OWNER = "WRITE_OWNER"
    GENERIC_WRITE = "GENERIC_WRITE"
    GENERIC_ALL = "GENERIC_ALL"

    # Service control manager / service rights
    SERVICE_CHANGE_CONFIG = "SERVICE_CHANGE_CONFIG"
    SERVICE_START = "SERVICE_START"
    SERVICE_STOP = "SERVICE_STOP"


# Rights that let a principal modify the bytes of an existing file.
FILE_MODIFY_RIGHTS = frozenset(
    {
        Rights.FILE_WRITE_DATA,
        Rights.FILE_APPEND_DATA,
        Rights.GENERIC_WRITE,
        Rights.GENERIC_ALL,
    }
)

# Rights on a directory that let a principal remove and recreate a child.
DIR_REPLACE_RIGHTS = frozenset(
    {
        Rights.FILE_ADD_FILE,
        Rights.FILE_DELETE_CHILD,
        Rights.DELETE,
        Rights.GENERIC_WRITE,
        Rights.GENERIC_ALL,
    }
)

# Rights that let a principal rewrite an object's DACL (directly or by
# first taking ownership).
ACL_CONTROL_RIGHTS = frozenset(
    {Rights.WRITE_DAC, Rights.WRITE_OWNER, Rights.GENERIC_ALL}
)

# Rights on a service object that let a principal reconfigure it.
SERVICE_CONFIG_RIGHTS = frozenset(
    {Rights.SERVICE_CHANGE_CONFIG, Rights.GENERIC_ALL}
)

# Accounts whose compromise yields elevated code execution.
HIGH_VALUE_ACCOUNTS = frozenset(
    {
        "localsystem",
        "nt authority\\system",
        "system",
        "nt authority\\localservice",
        "nt authority\\networkservice",
        "localservice",
        "networkservice",
    }
)

# Extensions whose "binary" is really a script run by an interpreter.
SCRIPT_EXTENSIONS = frozenset(
    {".bat", ".cmd", ".ps1", ".py", ".vbs", ".js", ".wsf"}
)


@dataclass(frozen=True)
class AceEntry:
    """One access control entry on an object."""

    principal: str
    rights: frozenset[str]
    allow: bool = True


@dataclass
class ObjectACL:
    """Resolved (post-inheritance) DACL plus owner for one object."""

    owner: str
    entries: list[AceEntry] = field(default_factory=list)


@dataclass
class ServiceConfig:
    """One row of an SCM export."""

    name: str
    account: str
    binary_path: str
    start_type: str = "AUTO_START"
    dependencies: tuple[str, ...] = ()
    service_acl: ObjectACL | None = None


class Capability(Enum):
    """What the audited low-privilege user can do to a service."""

    REPLACE_BINARY = "replace_binary"
    MODIFY_PARAMETERS = "modify_parameters"
    RECONFIGURE_SERVICE = "reconfigure_service"


class EvidenceKind(Enum):
    WRITABLE_FILE = "writable_file"
    WRITABLE_PARENT_DIR = "writable_parent_dir"
    OWNER_CONTROL = "owner_control"
    WEAK_SERVICE_ACL = "weak_service_acl"
    SCRIPT_INTERPRETER_PATH = "script_interpreter_path"
    UNQUOTED_PATH = "unquoted_path"
    DEPENDENCY_CHAIN = "dependency_chain"
    DEPENDENCY_CYCLE = "dependency_cycle"
    PATH_NOT_FOUND = "path_not_found"


@dataclass
class Evidence:
    kind: EvidenceKind
    detail: str
    path: str | None = None


class Severity(Enum):
    NONE = "none"
    UNKNOWN = "unknown"
    LOW = "low"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ServiceReport:
    service: str
    account: str
    capabilities: set[Capability] = field(default_factory=set)
    evidence: list[Evidence] = field(default_factory=list)
    severity: Severity = Severity.NONE

    @property
    def exploitable(self) -> bool:
        return bool(self.capabilities)
