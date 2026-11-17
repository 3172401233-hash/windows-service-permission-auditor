"""Simplified ACL evaluation.

This is intentionally a model, not a reimplementation of the Windows
access check. See README.md for the exact divergences from real
AccessCheck semantics.
"""

from __future__ import annotations

from .models import ACL_CONTROL_RIGHTS, ObjectACL


def _matches(principal: str, attacker: str, attacker_groups: frozenset[str]) -> bool:
    principal = principal.lower()
    return principal == attacker.lower() or principal in {g.lower() for g in attacker_groups}


def effective_rights(acl: ObjectACL, attacker: str, attacker_groups: frozenset[str]) -> set[str]:
    """Union of allow rights minus deny rights for the attacker.

    Deny entries win over allow entries, matching the common (deny-first)
    ordering of Windows DACLs.
    """
    allowed: set[str] = set()
    denied: set[str] = set()
    for entry in acl.entries:
        if not _matches(entry.principal, attacker, attacker_groups):
            continue
        if entry.allow:
            allowed.update(entry.rights)
        else:
            denied.update(entry.rights)
    return allowed - denied


def controls_object(acl: ObjectACL, attacker: str, attacker_groups: frozenset[str]) -> bool:
    """True if the attacker can rewrite the object's DACL.

    Owners implicitly hold WRITE_DAC on Windows, so ownership alone is
    enough to regain full control even with an empty DACL.
    """
    if acl.owner.lower() == attacker.lower():
        return True
    return bool(effective_rights(acl, attacker, attacker_groups) & ACL_CONTROL_RIGHTS)
