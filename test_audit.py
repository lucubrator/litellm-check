#!/usr/bin/env python3
"""Unit tests for audit_litellm.py (fleet-scanning wrapper)."""

import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from safe_litellm_detector import Classification, inspect_site_packages
from audit_litellm import (
    Auditor,
    AuditFinding,
    AuditReport,
    EnvKind,
    GlobalPythonDiscovery,
    RepoVenvDiscovery,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_repo_with_venv(base: Path, name: str = "my_repo") -> Path:
    """Creates a minimal repo directory with a venv containing site-packages."""
    repo = base / name
    sp = repo / ".venv" / "lib" / "python3.12" / "site-packages"
    (repo / ".git").mkdir(parents=True)
    sp.mkdir(parents=True)
    return sp


def _plant_litellm(site_packages: Path, *, version: str = "1.82.6") -> None:
    """Plants a fake litellm footprint into *site_packages*."""
    (site_packages / "litellm").mkdir(exist_ok=True)
    dist = site_packages / f"litellm-{version}.dist-info"
    dist.mkdir(exist_ok=True)
    (dist / "METADATA").write_text(
        textwrap.dedent(f"""\
            Metadata-Version: 2.1
            Name: litellm
            Version: {version}
        """)
    )


def _plant_pth_backdoor(site_packages: Path) -> None:
    """Creates the malicious ``litellm_init.pth`` file."""
    (site_packages / "litellm_init.pth").write_text("import os\n")


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

class TestRepoVenvDiscovery(unittest.TestCase):
    """Tests for Git repository and venv site-packages discovery."""

    def test_finds_git_repos(self):
        """Detects a ``.git`` directory as a repository root."""
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d) / "my_repo"
            (repo / ".git").mkdir(parents=True)
            repos = RepoVenvDiscovery._git_repos(Path(d))
            self.assertEqual(len(repos), 1)
            self.assertEqual(repos[0], repo)

    def test_finds_venv_site_packages(self):
        """Locates ``site-packages`` inside a ``.venv`` directory."""
        with tempfile.TemporaryDirectory() as d:
            sp = _make_repo_with_venv(Path(d))
            found = RepoVenvDiscovery._find_venv_site_packages(Path(d) / "my_repo")
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0], sp)

    def test_returns_empty_when_no_venv(self):
        """Returns nothing when no virtual environment exists."""
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d) / "bare_repo"
            (repo / ".git").mkdir(parents=True)
            found = RepoVenvDiscovery._find_venv_site_packages(repo)
            self.assertEqual(found, [])

    def test_discover_yields_site_packages(self):
        """End-to-end: discover yields site-packages paths."""
        with tempfile.TemporaryDirectory() as d:
            sp = _make_repo_with_venv(Path(d))
            discovery = RepoVenvDiscovery([Path(d)])
            results = list(discovery.discover())
            self.assertEqual(len(results), 1)
            label, path, kind = results[0]
            self.assertEqual(path, sp)
            self.assertEqual(kind, EnvKind.REPOSITORY)
            self.assertIn("my_repo", label)


class TestGlobalPythonDiscovery(unittest.TestCase):
    """Tests for system Python site-packages discovery."""

    def test_discovers_at_least_one_environment(self):
        """At least one global site-packages directory should be found."""
        discovery = GlobalPythonDiscovery()
        results = list(discovery.discover())
        self.assertGreater(len(results), 0)

    def test_all_results_are_global_kind(self):
        """Every result should have ``EnvKind.GLOBAL``."""
        discovery = GlobalPythonDiscovery()
        for _, _, kind in discovery.discover():
            self.assertEqual(kind, EnvKind.GLOBAL)


# ---------------------------------------------------------------------------
# Report model
# ---------------------------------------------------------------------------

class TestAuditReport(unittest.TestCase):
    """Tests for the AuditReport data model."""

    def _make_finding(self, sp: Path, *, installed: bool = False,
                      version: str | None = None,
                      kind: EnvKind = EnvKind.GLOBAL) -> AuditFinding:
        """Helper to build an AuditFinding from a real inspection."""
        if installed and version:
            _plant_litellm(sp, version=version)
        detail = inspect_site_packages(sp)
        return AuditFinding(label="test", kind=kind, detail=detail)

    def test_worst_compromised(self):
        """Report surfaces compromised-candidate as worst."""
        with tempfile.TemporaryDirectory() as d:
            sp = Path(d) / "sp"
            sp.mkdir()
            _plant_litellm(sp, version="1.82.8")
            _plant_pth_backdoor(sp)
            af = AuditFinding(
                label="x", kind=EnvKind.REPOSITORY,
                detail=inspect_site_packages(sp),
            )
            report = AuditReport(findings=[af])
            self.assertEqual(
                report.worst_classification,
                Classification.COMPROMISED_CANDIDATE,
            )

    def test_worst_clean(self):
        """Clean findings → clean worst classification."""
        with tempfile.TemporaryDirectory() as d:
            sp = Path(d)
            af = AuditFinding(
                label="x", kind=EnvKind.GLOBAL,
                detail=inspect_site_packages(sp),
            )
            report = AuditReport(findings=[af])
            self.assertEqual(report.worst_classification, Classification.CLEAN)

    def test_by_kind_filters(self):
        """``by_kind`` returns only findings matching the requested kind."""
        with tempfile.TemporaryDirectory() as d:
            sp = Path(d)
            detail = inspect_site_packages(sp)
            report = AuditReport(findings=[
                AuditFinding("repo", EnvKind.REPOSITORY, detail),
                AuditFinding("sys", EnvKind.GLOBAL, detail),
            ])
            self.assertEqual(len(report.by_kind(EnvKind.REPOSITORY)), 1)
            self.assertEqual(len(report.by_kind(EnvKind.GLOBAL)), 1)

    def test_empty_report(self):
        """Empty report has clean worst classification."""
        report = AuditReport()
        self.assertEqual(report.worst_classification, Classification.CLEAN)
        self.assertEqual(report.total_checked, 0)


# ---------------------------------------------------------------------------
# Auditor (end-to-end)
# ---------------------------------------------------------------------------

class TestAuditor(unittest.TestCase):
    """Tests for the Auditor orchestrator."""

    def test_deduplicates_site_packages(self):
        """The same resolved ``site-packages`` is only checked once."""
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            _make_repo_with_venv(base, "repo_a")
            repo_b = base / "repo_b"
            (repo_b / ".git").mkdir(parents=True)
            (repo_b / ".venv").symlink_to(base / "repo_a" / ".venv")

            discovery = RepoVenvDiscovery([base])
            report = Auditor([discovery]).run()
            self.assertEqual(report.total_checked, 1)

    def test_detects_planted_litellm(self):
        """Auditor correctly identifies a planted litellm installation."""
        with tempfile.TemporaryDirectory() as d:
            sp = _make_repo_with_venv(Path(d))
            _plant_litellm(sp, version="1.82.8")
            _plant_pth_backdoor(sp)

            discovery = RepoVenvDiscovery([Path(d)])
            report = Auditor([discovery]).run()

            self.assertEqual(
                report.worst_classification,
                Classification.COMPROMISED_CANDIDATE,
            )
            f = report.findings[0].detail
            self.assertTrue(f.litellm_present)
            self.assertEqual(f.version, "1.82.8")
            self.assertTrue(f.pth_present)

    def test_clean_environment(self):
        """Auditor reports clean for an environment without litellm."""
        with tempfile.TemporaryDirectory() as d:
            _make_repo_with_venv(Path(d))
            discovery = RepoVenvDiscovery([Path(d)])
            report = Auditor([discovery]).run()

            self.assertEqual(report.worst_classification, Classification.CLEAN)
            self.assertEqual(report.total_checked, 1)
            self.assertFalse(report.findings[0].detail.litellm_present)

    def test_strict_1827_propagates(self):
        """--strict-1827 flag reaches the classifier."""
        with tempfile.TemporaryDirectory() as d:
            sp = _make_repo_with_venv(Path(d))
            _plant_litellm(sp, version="1.82.7")

            discovery = RepoVenvDiscovery([Path(d)])
            report = Auditor([discovery], strict_1827=True).run()

            self.assertEqual(
                report.worst_classification,
                Classification.COMPROMISED_CANDIDATE,
            )


if __name__ == "__main__":
    unittest.main()
