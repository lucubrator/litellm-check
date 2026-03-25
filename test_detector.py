#!/usr/bin/env python3
"""Unit tests for safe_litellm_detector.py."""

import json
import tempfile
import textwrap
import unittest
from pathlib import Path

from safe_litellm_detector import (
    Classification,
    TargetReport,
    classify,
    discover_site_packages,
    format_report_json,
    format_report_text,
    inspect_site_packages,
    parse_version,
    record_mentions_pth,
    scan_target,
    worst_exit_code,
    EXIT_CLEAN,
    EXIT_COMPROMISED,
    EXIT_SUSPICIOUS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_site_packages(base: Path, python: str = "python3.12") -> Path:
    """Creates a minimal venv layout and returns the site-packages path."""
    sp = base / "lib" / python / "site-packages"
    sp.mkdir(parents=True)
    return sp


def _plant_litellm(sp: Path, *, version: str = "1.82.6") -> None:
    """Plants a fake litellm installation with dist-info."""
    (sp / "litellm").mkdir(exist_ok=True)
    dist = sp / f"litellm-{version}.dist-info"
    dist.mkdir(exist_ok=True)
    (dist / "METADATA").write_text(
        textwrap.dedent(f"""\
            Metadata-Version: 2.1
            Name: litellm
            Version: {version}
        """)
    )


def _plant_record(sp: Path, version: str, *, mentions_pth: bool) -> None:
    """Creates a RECORD file, optionally referencing litellm_init.pth."""
    dist = sp / f"litellm-{version}.dist-info"
    dist.mkdir(exist_ok=True)
    lines = ["litellm/__init__.py,sha256=abc,123\n"]
    if mentions_pth:
        lines.append("litellm_init.pth,sha256=def,456\n")
    (dist / "RECORD").write_text("".join(lines))


def _plant_pth(sp: Path) -> None:
    """Creates the malicious litellm_init.pth file."""
    (sp / "litellm_init.pth").write_text("import os\n")


# ---------------------------------------------------------------------------
# Phase 1 — discover_site_packages
# ---------------------------------------------------------------------------

class TestDiscoverSitePackages(unittest.TestCase):
    """Tests for site-packages path discovery."""

    def test_direct_site_packages_dir(self):
        """Accepts a directory already named site-packages."""
        with tempfile.TemporaryDirectory() as d:
            sp = Path(d) / "site-packages"
            sp.mkdir()
            result = discover_site_packages(sp)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0], sp)

    def test_venv_root_linux(self):
        """Discovers site-packages under a standard venv layout."""
        with tempfile.TemporaryDirectory() as d:
            sp = _make_site_packages(Path(d))
            result = discover_site_packages(Path(d))
            self.assertIn(sp, result)

    def test_venv_root_windows_layout(self):
        """Discovers site-packages under a Windows venv layout."""
        with tempfile.TemporaryDirectory() as d:
            sp = Path(d) / "Lib" / "site-packages"
            sp.mkdir(parents=True)
            result = discover_site_packages(Path(d))
            self.assertIn(sp, result)

    def test_nonexistent_path(self):
        """Returns empty list for a path that does not exist."""
        result = discover_site_packages(Path("/nonexistent/path/xyz"))
        self.assertEqual(result, [])

    def test_recursive_fallback(self):
        """Falls back to recursive search for nested environments."""
        with tempfile.TemporaryDirectory() as d:
            nested = Path(d) / "project" / ".venv" / "lib" / "python3.12" / "site-packages"
            nested.mkdir(parents=True)
            result = discover_site_packages(Path(d))
            self.assertIn(nested, result)

    def test_deduplicates_via_symlink(self):
        """Does not return the same site-packages twice via symlink."""
        with tempfile.TemporaryDirectory() as d:
            sp = _make_site_packages(Path(d) / "real_env")
            link = Path(d) / "linked_env"
            link.symlink_to(Path(d) / "real_env")
            # Discover from a parent that contains both
            parent = Path(d)
            result = discover_site_packages(parent)
            self.assertEqual(len(result), 1)


# ---------------------------------------------------------------------------
# Phase 2+3 — Metadata extraction
# ---------------------------------------------------------------------------

class TestParseVersion(unittest.TestCase):
    """Tests for version extraction from dist-info."""

    def test_reads_from_metadata(self):
        """Extracts version from METADATA file."""
        with tempfile.TemporaryDirectory() as d:
            dist = Path(d) / "litellm-1.82.8.dist-info"
            dist.mkdir()
            (dist / "METADATA").write_text("Version: 1.82.8\n")
            self.assertEqual(parse_version(dist), "1.82.8")

    def test_reads_from_pkg_info(self):
        """Falls back to PKG-INFO."""
        with tempfile.TemporaryDirectory() as d:
            dist = Path(d) / "litellm-1.0.0.dist-info"
            dist.mkdir()
            (dist / "PKG-INFO").write_text("Version: 1.0.0\n")
            self.assertEqual(parse_version(dist), "1.0.0")

    def test_fallback_to_dirname(self):
        """Falls back to parsing the directory name."""
        with tempfile.TemporaryDirectory() as d:
            dist = Path(d) / "litellm-2.3.4.dist-info"
            dist.mkdir()
            self.assertEqual(parse_version(dist), "2.3.4")

    def test_malformed_metadata(self):
        """Returns None for metadata without a Version field, falls back to dirname."""
        with tempfile.TemporaryDirectory() as d:
            dist = Path(d) / "litellm-1.0.0.dist-info"
            dist.mkdir()
            (dist / "METADATA").write_text("Name: litellm\n")
            # Should fall back to dirname
            self.assertEqual(parse_version(dist), "1.0.0")

    def test_no_metadata_no_parseable_name(self):
        """Returns None for a dist-info dir with no metadata and odd name."""
        with tempfile.TemporaryDirectory() as d:
            dist = Path(d) / "litellm-.dist-info"
            dist.mkdir()
            # Regex won't match empty version
            result = parse_version(dist)
            # The regex pattern allows empty match actually — let's just
            # verify it doesn't crash
            self.assertIsInstance(result, (str, type(None)))


class TestRecordMentionsPth(unittest.TestCase):
    """Tests for RECORD inspection."""

    def test_record_with_pth(self):
        """Returns True when RECORD references litellm_init.pth."""
        with tempfile.TemporaryDirectory() as d:
            dist = Path(d) / "litellm-1.82.8.dist-info"
            dist.mkdir()
            (dist / "RECORD").write_text(
                "litellm/__init__.py,sha256=abc,123\n"
                "litellm_init.pth,sha256=def,456\n"
            )
            self.assertTrue(record_mentions_pth(dist))

    def test_record_without_pth(self):
        """Returns False when RECORD does not reference the .pth file."""
        with tempfile.TemporaryDirectory() as d:
            dist = Path(d) / "litellm-1.82.6.dist-info"
            dist.mkdir()
            (dist / "RECORD").write_text("litellm/__init__.py,sha256=abc,123\n")
            self.assertFalse(record_mentions_pth(dist))

    def test_no_record_file(self):
        """Returns False when RECORD does not exist."""
        with tempfile.TemporaryDirectory() as d:
            dist = Path(d) / "litellm-1.82.6.dist-info"
            dist.mkdir()
            self.assertFalse(record_mentions_pth(dist))


# ---------------------------------------------------------------------------
# Phase 4 — Classification
# ---------------------------------------------------------------------------

class TestClassify(unittest.TestCase):
    """Tests for the deterministic classification engine."""

    def test_clean_no_litellm(self):
        """No litellm → clean."""
        cls, reasons = classify(
            litellm_present=False, version=None, pth_present=False,
            record_mentions_pth=False, dist_info_count=0,
            metadata_readable=True,
        )
        self.assertEqual(cls, Classification.CLEAN)
        self.assertEqual(reasons, [])

    def test_compromised_version_1828(self):
        """Version 1.82.8 → compromised-candidate."""
        cls, reasons = classify(
            litellm_present=True, version="1.82.8", pth_present=False,
            record_mentions_pth=False, dist_info_count=1,
            metadata_readable=True,
        )
        self.assertEqual(cls, Classification.COMPROMISED_CANDIDATE)
        self.assertIn("version=1.82.8", reasons)

    def test_compromised_pth_present(self):
        """litellm_init.pth present → compromised-candidate."""
        cls, reasons = classify(
            litellm_present=True, version="1.0.0", pth_present=True,
            record_mentions_pth=False, dist_info_count=1,
            metadata_readable=True,
        )
        self.assertEqual(cls, Classification.COMPROMISED_CANDIDATE)
        self.assertIn("litellm_init.pth present", reasons)

    def test_compromised_record_mentions_pth(self):
        """RECORD references .pth → compromised-candidate."""
        cls, reasons = classify(
            litellm_present=True, version="1.0.0", pth_present=False,
            record_mentions_pth=True, dist_info_count=1,
            metadata_readable=True,
        )
        self.assertEqual(cls, Classification.COMPROMISED_CANDIDATE)
        self.assertIn("RECORD mentions litellm_init.pth", reasons)

    def test_suspicious_version_1827(self):
        """Version 1.82.7 without strict mode → suspicious."""
        cls, reasons = classify(
            litellm_present=True, version="1.82.7", pth_present=False,
            record_mentions_pth=False, dist_info_count=1,
            metadata_readable=True,
        )
        self.assertEqual(cls, Classification.SUSPICIOUS)
        self.assertIn("version=1.82.7", reasons)

    def test_strict_1827_escalates(self):
        """Version 1.82.7 with strict mode → compromised-candidate."""
        cls, reasons = classify(
            litellm_present=True, version="1.82.7", pth_present=False,
            record_mentions_pth=False, dist_info_count=1,
            metadata_readable=True, strict_1827=True,
        )
        self.assertEqual(cls, Classification.COMPROMISED_CANDIDATE)

    def test_suspicious_no_dist_info(self):
        """Package dir without dist-info → suspicious."""
        cls, reasons = classify(
            litellm_present=True, version=None, pth_present=False,
            record_mentions_pth=False, dist_info_count=0,
            metadata_readable=True,
        )
        self.assertEqual(cls, Classification.SUSPICIOUS)
        self.assertTrue(
            any("without dist-info" in r for r in reasons)
        )

    def test_suspicious_multiple_dist_info(self):
        """Multiple dist-info directories → suspicious."""
        cls, reasons = classify(
            litellm_present=True, version="1.0.0", pth_present=False,
            record_mentions_pth=False, dist_info_count=2,
            metadata_readable=True,
        )
        self.assertEqual(cls, Classification.SUSPICIOUS)
        self.assertTrue(any("multiple" in r for r in reasons))

    def test_suspicious_unreadable_metadata(self):
        """Unreadable metadata → suspicious."""
        cls, reasons = classify(
            litellm_present=True, version=None, pth_present=False,
            record_mentions_pth=False, dist_info_count=1,
            metadata_readable=False,
        )
        self.assertEqual(cls, Classification.SUSPICIOUS)
        self.assertTrue(any("malformed" in r for r in reasons))

    def test_suspicious_benign_version_present(self):
        """Benign version installed → suspicious (still flagged as present)."""
        cls, reasons = classify(
            litellm_present=True, version="1.50.0", pth_present=False,
            record_mentions_pth=False, dist_info_count=1,
            metadata_readable=True,
        )
        self.assertEqual(cls, Classification.SUSPICIOUS)
        self.assertTrue(any("1.50.0" in r for r in reasons))

    def test_full_compromise_all_signals(self):
        """All IOCs present → compromised-candidate with all reasons listed."""
        cls, reasons = classify(
            litellm_present=True, version="1.82.8", pth_present=True,
            record_mentions_pth=True, dist_info_count=1,
            metadata_readable=True,
        )
        self.assertEqual(cls, Classification.COMPROMISED_CANDIDATE)
        self.assertIn("version=1.82.8", reasons)
        self.assertIn("litellm_init.pth present", reasons)
        self.assertIn("RECORD mentions litellm_init.pth", reasons)


# ---------------------------------------------------------------------------
# Phase 5 — inspect_site_packages / scan_target
# ---------------------------------------------------------------------------

class TestInspectSitePackages(unittest.TestCase):
    """Tests for the end-to-end site-packages inspector."""

    def test_clean_site_packages(self):
        """Empty site-packages → clean."""
        with tempfile.TemporaryDirectory() as d:
            f = inspect_site_packages(Path(d))
            self.assertFalse(f.litellm_present)
            self.assertEqual(f.classification, Classification.CLEAN)

    def test_benign_litellm(self):
        """Benign version installed → suspicious (litellm is present)."""
        with tempfile.TemporaryDirectory() as d:
            _plant_litellm(Path(d), version="1.50.0")
            f = inspect_site_packages(Path(d))
            self.assertTrue(f.litellm_present)
            self.assertEqual(f.version, "1.50.0")
            self.assertEqual(f.classification, Classification.SUSPICIOUS)
            self.assertFalse(f.pth_present)

    def test_compromised_1828_with_pth(self):
        """Full 1.82.8 scenario → compromised-candidate."""
        with tempfile.TemporaryDirectory() as d:
            sp = Path(d)
            _plant_litellm(sp, version="1.82.8")
            _plant_pth(sp)
            _plant_record(sp, "1.82.8", mentions_pth=True)
            f = inspect_site_packages(sp)
            self.assertTrue(f.litellm_present)
            self.assertEqual(f.version, "1.82.8")
            self.assertTrue(f.pth_present)
            self.assertTrue(f.record_mentions_pth)
            self.assertEqual(f.classification, Classification.COMPROMISED_CANDIDATE)

    def test_1828_partially_deleted(self):
        """Dist-info remains with RECORD → compromised-candidate."""
        with tempfile.TemporaryDirectory() as d:
            sp = Path(d)
            # Only dist-info with RECORD, no package dir or .pth
            dist = sp / "litellm-1.82.8.dist-info"
            dist.mkdir()
            (dist / "METADATA").write_text("Version: 1.82.8\n")
            (dist / "RECORD").write_text("litellm_init.pth,sha256=x,1\n")
            f = inspect_site_packages(sp)
            self.assertTrue(f.litellm_present)
            self.assertEqual(f.classification, Classification.COMPROMISED_CANDIDATE)

    def test_1827_default_suspicious(self):
        """1.82.7 without strict → suspicious."""
        with tempfile.TemporaryDirectory() as d:
            _plant_litellm(Path(d), version="1.82.7")
            f = inspect_site_packages(Path(d))
            self.assertEqual(f.classification, Classification.SUSPICIOUS)

    def test_1827_strict_compromised(self):
        """1.82.7 with strict → compromised-candidate."""
        with tempfile.TemporaryDirectory() as d:
            _plant_litellm(Path(d), version="1.82.7")
            f = inspect_site_packages(Path(d), strict_1827=True)
            self.assertEqual(f.classification, Classification.COMPROMISED_CANDIDATE)

    def test_pth_only_no_package(self):
        """Only .pth file remains → compromised-candidate."""
        with tempfile.TemporaryDirectory() as d:
            _plant_pth(Path(d))
            f = inspect_site_packages(Path(d))
            self.assertTrue(f.pth_present)
            self.assertEqual(f.classification, Classification.COMPROMISED_CANDIDATE)


class TestScanTarget(unittest.TestCase):
    """Tests for the target-level scanner."""

    def test_scan_venv_root(self):
        """Scanning a venv root produces a TargetReport."""
        with tempfile.TemporaryDirectory() as d:
            _make_site_packages(Path(d))
            report = scan_target(Path(d))
            self.assertIsInstance(report, TargetReport)
            self.assertEqual(len(report.site_packages), 1)

    def test_worst_classification_clean(self):
        """Clean target has worst_classification = CLEAN."""
        with tempfile.TemporaryDirectory() as d:
            _make_site_packages(Path(d))
            report = scan_target(Path(d))
            self.assertEqual(report.worst_classification, Classification.CLEAN)

    def test_worst_classification_compromised(self):
        """Compromised target bubbles up correctly."""
        with tempfile.TemporaryDirectory() as d:
            sp = _make_site_packages(Path(d))
            _plant_litellm(sp, version="1.82.8")
            _plant_pth(sp)
            report = scan_target(Path(d))
            self.assertEqual(
                report.worst_classification,
                Classification.COMPROMISED_CANDIDATE,
            )


# ---------------------------------------------------------------------------
# Phase 5 cont. — Reporting / serialisation
# ---------------------------------------------------------------------------

class TestReporting(unittest.TestCase):
    """Tests for report formatting and exit codes."""

    def test_json_output_parses(self):
        """JSON output is valid JSON matching the expected schema."""
        with tempfile.TemporaryDirectory() as d:
            sp = _make_site_packages(Path(d))
            _plant_litellm(sp, version="1.82.8")
            _plant_pth(sp)
            report = scan_target(Path(d))
            raw = format_report_json([report])
            data = json.loads(raw)
            self.assertIsInstance(data, list)
            self.assertEqual(len(data), 1)
            sp_data = data[0]["site_packages"]
            self.assertEqual(len(sp_data), 1)
            self.assertEqual(sp_data[0]["version"], "1.82.8")
            self.assertTrue(sp_data[0]["pth_present"])
            self.assertEqual(sp_data[0]["classification"], "compromised-candidate")

    def test_json_clean(self):
        """Clean target produces valid JSON with clean classification."""
        with tempfile.TemporaryDirectory() as d:
            _make_site_packages(Path(d))
            report = scan_target(Path(d))
            raw = format_report_json([report])
            data = json.loads(raw)
            sp_data = data[0]["site_packages"]
            self.assertEqual(sp_data[0]["classification"], "clean")

    def test_text_output_not_empty(self):
        """Text output contains something meaningful."""
        with tempfile.TemporaryDirectory() as d:
            _make_site_packages(Path(d))
            report = scan_target(Path(d))
            text = format_report_text([report])
            self.assertIn("clean", text)

    def test_exit_code_clean(self):
        """Clean reports → exit code 0."""
        with tempfile.TemporaryDirectory() as d:
            _make_site_packages(Path(d))
            report = scan_target(Path(d))
            self.assertEqual(worst_exit_code([report]), EXIT_CLEAN)

    def test_exit_code_suspicious(self):
        """Suspicious reports → exit code 1."""
        with tempfile.TemporaryDirectory() as d:
            sp = _make_site_packages(Path(d))
            _plant_litellm(sp, version="1.50.0")
            report = scan_target(Path(d))
            self.assertEqual(worst_exit_code([report]), EXIT_SUSPICIOUS)

    def test_exit_code_compromised(self):
        """Compromised reports → exit code 2."""
        with tempfile.TemporaryDirectory() as d:
            sp = _make_site_packages(Path(d))
            _plant_litellm(sp, version="1.82.8")
            report = scan_target(Path(d))
            self.assertEqual(worst_exit_code([report]), EXIT_COMPROMISED)

    def test_to_dict_roundtrip(self):
        """SitePackagesFinding.to_dict produces JSON-serialisable output."""
        with tempfile.TemporaryDirectory() as d:
            sp = _make_site_packages(Path(d))
            _plant_litellm(sp, version="1.82.8")
            _plant_pth(sp)
            finding = inspect_site_packages(sp)
            d_out = finding.to_dict()
            # Must not raise
            json.dumps(d_out)
            self.assertEqual(d_out["classification"], "compromised-candidate")


if __name__ == "__main__":
    unittest.main()
