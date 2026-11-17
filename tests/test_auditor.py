import unittest

from winsvc_audit import (
    AceEntry,
    AuditEngine,
    Capability,
    EvidenceKind,
    ObjectACL,
    Rights,
    ServiceConfig,
    Severity,
    parse_scm_export,
)

ATTACKER = "CORP\\lowpriv"
GROUPS = frozenset({"Everyone", "BUILTIN\\Users"})
ADMIN = "BUILTIN\\Administrators"


def acl(owner, *entries):
    return ObjectACL(owner=owner, entries=list(entries))


def allow(principal, *rights):
    return AceEntry(principal=principal, rights=frozenset(rights), allow=True)


def deny(principal, *rights):
    return AceEntry(principal=principal, rights=frozenset(rights), allow=False)


def kinds(report):
    return {e.kind for e in report.evidence}


def make_engine(file_acls=None, dir_acls=None):
    return AuditEngine(
        attacker=ATTACKER,
        attacker_groups=GROUPS,
        file_acls=file_acls or {},
        dir_acls=dir_acls or {},
    )


class SystemServiceTests(unittest.TestCase):
    """LocalSystem service whose binary lives in a user-writable directory."""

    def setUp(self):
        self.service = ServiceConfig(
            name="VulnSvc",
            account="LocalSystem",
            binary_path="C:\\Users\\lowpriv\\svc\\svc.exe",
        )
        self.engine = make_engine(
            file_acls={
                "C:\\Users\\lowpriv\\svc\\svc.exe": acl(
                    ADMIN, allow("BUILTIN\\Users", "FILE_READ_DATA")
                )
            },
            dir_acls={
                "C:\\Users\\lowpriv\\svc": acl(
                    ATTACKER,
                    allow(ATTACKER, Rights.FILE_ADD_FILE, Rights.FILE_DELETE_CHILD),
                )
            },
        )

    def test_replace_binary_via_writable_parent_dir(self):
        report = self.engine.audit({"VulnSvc": self.service})["VulnSvc"]
        self.assertIn(Capability.REPLACE_BINARY, report.capabilities)
        self.assertIn(EvidenceKind.WRITABLE_PARENT_DIR, kinds(report))

    def test_system_account_is_critical(self):
        report = self.engine.audit({"VulnSvc": self.service})["VulnSvc"]
        self.assertEqual(Severity.CRITICAL, report.severity)

    def test_owner_control_on_parent_dir(self):
        report = self.engine.audit({"VulnSvc": self.service})["VulnSvc"]
        self.assertIn(EvidenceKind.OWNER_CONTROL, kinds(report))

    def test_writable_file_evidence(self):
        engine = make_engine(
            file_acls={
                "C:\\svc\\svc.exe": acl(ADMIN, allow("Everyone", Rights.FILE_WRITE_DATA))
            },
            dir_acls={"C:\\svc": acl(ADMIN)},
        )
        svc = ServiceConfig("Svc", "LocalSystem", "C:\\svc\\svc.exe")
        report = engine.audit({"Svc": svc})["Svc"]
        self.assertIn(EvidenceKind.WRITABLE_FILE, kinds(report))
        self.assertIn(Capability.REPLACE_BINARY, report.capabilities)


class NormalUserServiceTests(unittest.TestCase):
    """Same misconfiguration, but the service runs as a low-privilege user."""

    def test_low_priv_account_is_high_not_critical(self):
        engine = make_engine(
            file_acls={
                "C:\\Users\\lowpriv\\svc.exe": acl(
                    ADMIN, allow("Everyone", Rights.GENERIC_WRITE)
                )
            },
            dir_acls={"C:\\Users\\lowpriv": acl(ATTACKER)},
        )
        svc = ServiceConfig("UserSvc", "CORP\\lowpriv", "C:\\Users\\lowpriv\\svc.exe")
        report = engine.audit({"UserSvc": svc})["UserSvc"]
        self.assertIn(Capability.REPLACE_BINARY, report.capabilities)
        self.assertEqual(Severity.HIGH, report.severity)


class EmptyServiceDirectoryTests(unittest.TestCase):
    """No ACL snapshot for the binary or its (empty/missing) directory."""

    def test_missing_snapshots_are_unknown_not_exploitable(self):
        engine = make_engine()
        svc = ServiceConfig("GhostSvc", "LocalSystem", "D:\\empty\\svc.exe")
        report = engine.audit({"GhostSvc": svc})["GhostSvc"]
        self.assertFalse(report.capabilities)
        self.assertEqual(Severity.UNKNOWN, report.severity)
        self.assertIn(EvidenceKind.PATH_NOT_FOUND, kinds(report))


class DependencyTests(unittest.TestCase):
    def test_dependency_chain_inherits_capabilities(self):
        dep = ServiceConfig("DepSvc", "LocalSystem", "C:\\writable\\dep.exe")
        top = ServiceConfig(
            "TopSvc", "LocalSystem", "C:\\safe\\top.exe", dependencies=("DepSvc",)
        )
        engine = make_engine(
            file_acls={
                "C:\\writable\\dep.exe": acl(ADMIN, allow("Everyone", Rights.GENERIC_ALL)),
                "C:\\safe\\top.exe": acl(ADMIN),
            },
            dir_acls={"C:\\writable": acl(ADMIN), "C:\\safe": acl(ADMIN)},
        )
        reports = engine.audit({"TopSvc": top, "DepSvc": dep})
        self.assertIn(Capability.REPLACE_BINARY, reports["TopSvc"].capabilities)
        self.assertIn(EvidenceKind.DEPENDENCY_CHAIN, kinds(reports["TopSvc"]))

    def test_dependency_cycle_does_not_hang(self):
        a = ServiceConfig("SvcA", "LocalSystem", "C:\\a\\a.exe", dependencies=("SvcB",))
        b = ServiceConfig("SvcB", "LocalSystem", "C:\\b\\b.exe", dependencies=("SvcA",))
        engine = make_engine(
            file_acls={"C:\\a\\a.exe": acl(ADMIN), "C:\\b\\b.exe": acl(ADMIN)},
            dir_acls={"C:\\a": acl(ADMIN), "C:\\b": acl(ADMIN)},
        )
        reports = engine.audit({"SvcA": a, "SvcB": b})
        self.assertFalse(reports["SvcA"].capabilities)
        self.assertFalse(reports["SvcB"].capabilities)
        self.assertTrue(
            any(EvidenceKind.DEPENDENCY_CYCLE in kinds(r) for r in reports.values())
        )


class SameAclDifferentOwnerTests(unittest.TestCase):
    """Identical DACL, different owner: ownership alone grants WRITE_DAC."""

    def _report_for_owner(self, owner):
        entries = [allow("BUILTIN\\Users", "FILE_READ_DATA")]
        engine = make_engine(
            file_acls={"C:\\svc\\svc.exe": acl(owner, *entries)},
            dir_acls={"C:\\svc": acl(ADMIN)},
        )
        svc = ServiceConfig("Svc", "LocalSystem", "C:\\svc\\svc.exe")
        return engine.audit({"Svc": svc})["Svc"]

    def test_attacker_owned_binary_is_exploitable(self):
        report = self._report_for_owner(ATTACKER)
        self.assertIn(Capability.REPLACE_BINARY, report.capabilities)
        self.assertIn(EvidenceKind.OWNER_CONTROL, kinds(report))

    def test_admin_owned_binary_with_same_acl_is_safe(self):
        report = self._report_for_owner(ADMIN)
        self.assertFalse(report.capabilities)
        self.assertNotIn(EvidenceKind.OWNER_CONTROL, kinds(report))


class WeakServiceAclTests(unittest.TestCase):
    def test_change_config_allows_reconfigure(self):
        svc = ServiceConfig(
            "WeakSvc",
            "LocalSystem",
            "C:\\svc\\svc.exe",
            service_acl=acl(ADMIN, allow("BUILTIN\\Users", Rights.SERVICE_CHANGE_CONFIG)),
        )
        engine = make_engine(
            file_acls={"C:\\svc\\svc.exe": acl(ADMIN)},
            dir_acls={"C:\\svc": acl(ADMIN)},
        )
        report = engine.audit({"WeakSvc": svc})["WeakSvc"]
        self.assertIn(EvidenceKind.WEAK_SERVICE_ACL, kinds(report))
        self.assertIn(Capability.RECONFIGURE_SERVICE, report.capabilities)
        self.assertIn(Capability.MODIFY_PARAMETERS, report.capabilities)
        self.assertEqual(Severity.CRITICAL, report.severity)


class ScriptInterpreterTests(unittest.TestCase):
    def test_powershell_script_service(self):
        svc = ServiceConfig("ScriptSvc", "LocalSystem", "C:\\svc\\runner.ps1 -Verbose")
        engine = make_engine(
            file_acls={"C:\\svc\\runner.ps1": acl(ADMIN)},
            dir_acls={"C:\\svc": acl(ADMIN)},
        )
        report = engine.audit({"ScriptSvc": svc})["ScriptSvc"]
        self.assertIn(EvidenceKind.SCRIPT_INTERPRETER_PATH, kinds(report))
        self.assertIn(Capability.MODIFY_PARAMETERS, report.capabilities)

    def test_interpreter_with_script_argument(self):
        svc = ServiceConfig(
            "PySvc", "LocalSystem", '"C:\\Python312\\python.exe" C:\\svc\\job.py'
        )
        engine = make_engine(
            file_acls={"C:\\Python312\\python.exe": acl(ADMIN)},
            dir_acls={"C:\\Python312": acl(ADMIN)},
        )
        report = engine.audit({"PySvc": svc})["PySvc"]
        self.assertIn(EvidenceKind.SCRIPT_INTERPRETER_PATH, kinds(report))


class UnquotedPathTests(unittest.TestCase):
    def test_unquoted_path_with_spaces(self):
        svc = ServiceConfig(
            "SpaceSvc", "LocalSystem", "C:\\Program Files\\Acme Tool\\svc.exe"
        )
        engine = make_engine(
            file_acls={"C:\\Program Files\\Acme Tool\\svc.exe": acl(ADMIN)},
            dir_acls={
                "C:\\Program Files\\Acme Tool": acl(ADMIN),
                "C:\\": acl(ADMIN, allow("BUILTIN\\Users", Rights.FILE_ADD_FILE)),
            },
        )
        report = engine.audit({"SpaceSvc": svc})["SpaceSvc"]
        self.assertIn(EvidenceKind.UNQUOTED_PATH, kinds(report))
        self.assertIn(Capability.REPLACE_BINARY, report.capabilities)

    def test_quoted_path_with_spaces_is_not_flagged(self):
        svc = ServiceConfig(
            "QuotedSvc", "LocalSystem", '"C:\\Program Files\\Acme Tool\\svc.exe"'
        )
        engine = make_engine(
            file_acls={"C:\\Program Files\\Acme Tool\\svc.exe": acl(ADMIN)},
            dir_acls={
                "C:\\Program Files\\Acme Tool": acl(ADMIN),
                "C:\\": acl(ADMIN, allow("BUILTIN\\Users", Rights.FILE_ADD_FILE)),
            },
        )
        report = engine.audit({"QuotedSvc": svc})["QuotedSvc"]
        self.assertNotIn(EvidenceKind.UNQUOTED_PATH, kinds(report))


class AclSemanticsTests(unittest.TestCase):
    def test_deny_overrides_allow(self):
        engine = make_engine(
            file_acls={
                "C:\\svc\\svc.exe": acl(
                    ADMIN,
                    allow("Everyone", Rights.GENERIC_WRITE),
                    deny(
                        ATTACKER,
                        Rights.FILE_WRITE_DATA,
                        Rights.FILE_APPEND_DATA,
                        Rights.GENERIC_WRITE,
                        Rights.GENERIC_ALL,
                    ),
                )
            },
            dir_acls={"C:\\svc": acl(ADMIN)},
        )
        svc = ServiceConfig("Svc", "LocalSystem", "C:\\svc\\svc.exe")
        report = engine.audit({"Svc": svc})["Svc"]
        self.assertNotIn(EvidenceKind.WRITABLE_FILE, kinds(report))
        self.assertFalse(report.capabilities)


class ScmParserTests(unittest.TestCase):
    EXPORT = """\
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: VulnSvc
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\\Users\\lowpriv\\svc.exe --run
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Vulnerable Service
        DEPENDENCIES       : RpcSs
                           : DcomLaunch
        SERVICE_START_NAME : LocalSystem

SERVICE_NAME: Other
        START_TYPE         : 3   DEMAND_START
        BINARY_PATH_NAME   : C:\\svc\\other.exe
        DEPENDENCIES       :
        SERVICE_START_NAME : NT AUTHORITY\\NetworkService
"""

    def test_parse_multiple_services(self):
        services = parse_scm_export(self.EXPORT)
        self.assertEqual({"VulnSvc", "Other"}, set(services))
        vuln = services["VulnSvc"]
        self.assertEqual("LocalSystem", vuln.account)
        self.assertEqual("C:\\Users\\lowpriv\\svc.exe --run", vuln.binary_path)
        self.assertEqual("AUTO_START", vuln.start_type)
        self.assertEqual(("RpcSs", "DcomLaunch"), vuln.dependencies)
        self.assertEqual((), services["Other"].dependencies)

    def test_parsed_export_feeds_engine(self):
        services = parse_scm_export(self.EXPORT)
        engine = make_engine(
            file_acls={
                "C:\\Users\\lowpriv\\svc.exe": acl(
                    ADMIN, allow("Everyone", Rights.FILE_WRITE_DATA)
                ),
                "C:\\svc\\other.exe": acl(ADMIN),
            },
            dir_acls={"C:\\Users\\lowpriv": acl(ADMIN), "C:\\svc": acl(ADMIN)},
        )
        reports = engine.audit(services)
        self.assertTrue(reports["VulnSvc"].exploitable)
        self.assertFalse(reports["Other"].exploitable)


if __name__ == "__main__":
    unittest.main()
