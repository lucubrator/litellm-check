#!/usr/bin/env python3
"""Incident-response-safe detector for compromised ``litellm`` installations.

**Safety contract:** this module never executes ``python``, ``pip``, or any
other binary from the inspected environment.  All detection is pure filesystem
reads — safe to run against environments that may contain the malicious
``litellm_init.pth`` startup payload from versions 1.82.7 / 1.82.8.

Typical usage::

    # Scan a single venv
    python3 safe_litellm_detector.py /path/to/venv

    # Scan multiple targets with JSON output
    python3 safe_litellm_detector.py /opt/app/.venv ~/work/project --json

    # Recursive scan of a directory tree
    python3 safe_litellm_detector.py ~/work --recursive

See https://github.com/BerriAI/litellm/issues/24512 for incident details.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Sequence

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_COMPROMISED_VERSIONS: frozenset[str] = frozenset({"1.82.8"})
_SUSPICIOUS_VERSIONS: frozenset[str] = frozenset({"1.82.7"})

_VENV_DIR_NAMES: tuple[str, ...] = (
    ".venv", "venv", "env", ".env", "ENV", "virtenv", ".virtenv",
)

# Matches ``litellm-1.82.8.dist-info`` → ``1.82.8``.
_DIST_INFO_VERSION_RE = re.compile(r"^litellm-(.+)\.dist-info$")

# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


class Classification(Enum):
    """Tri-state classification for a site-packages inspection."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    COMPROMISED_CANDIDATE = "compromised-candidate"


# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SitePackagesFinding:
    """Result of inspecting one ``site-packages`` directory."""

    path: Path
    litellm_present: bool
    version: str | None
    dist_info_path: Path | None
    package_path: Path | None
    pth_present: bool
    pth_path: Path | None
    record_mentions_pth: bool
    classification: Classification
    reasons: tuple[str, ...]

    def to_dict(self) -> dict:
        """Returns a JSON-serialisable dictionary."""
        return {
            "path": str(self.path),
            "litellm_present": self.litellm_present,
            "version": self.version,
            "dist_info_path": str(self.dist_info_path) if self.dist_info_path else None,
            "package_path": str(self.package_path) if self.package_path else None,
            "pth_present": self.pth_present,
            "pth_path": str(self.pth_path) if self.pth_path else None,
            "record_mentions_pth": self.record_mentions_pth,
            "classification": self.classification.value,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class TargetReport:
    """Aggregated result for one target path."""

    target: Path
    site_packages: tuple[SitePackagesFinding, ...]

    @property
    def worst_classification(self) -> Classification:
        """Returns the most severe classification across all findings."""
        dominated = Classification.CLEAN
        for f in self.site_packages:
            if f.classification == Classification.COMPROMISED_CANDIDATE:
                return Classification.COMPROMISED_CANDIDATE
            if f.classification == Classification.SUSPICIOUS:
                dominated = Classification.SUSPICIOUS
        return dominated

    def to_dict(self) -> dict:
        """Returns a JSON-serialisable dictionary."""
        return {
            "target": str(self.target),
            "site_packages": [f.to_dict() for f in self.site_packages],
        }


# ---------------------------------------------------------------------------
# Phase 1 — Path discovery
# ---------------------------------------------------------------------------


def discover_site_packages(target: Path) -> list[Path]:
    """Locates all ``site-packages`` directories under *target*.

    Handles:
        * *target* is itself a ``site-packages`` directory.
        * *target* is a venv / conda root (Linux/macOS/Windows layout).
        * *target* is an arbitrary directory (recursive glob).

    Protects against symlink loops via ``resolve()`` deduplication.
    """
    target = target.expanduser()
    if not target.exists():
        return []

    results: list[Path] = []
    seen: set[Path] = set()

    def _add(p: Path) -> None:
        try:
            resolved = p.resolve()
        except OSError:
            return
        if resolved not in seen and resolved.is_dir():
            seen.add(resolved)
            results.append(p)

    # Case 1: target is already a site-packages directory.
    if target.name == "site-packages" and target.is_dir():
        _add(target)
        return results

    # Case 2: venv / conda root with known layouts.
    #   Linux / macOS:  lib/python*/site-packages
    #   Windows:        Lib/site-packages
    for sp in _safe_glob(target, "lib/python*/site-packages"):
        _add(sp)
    lib_sp = target / "Lib" / "site-packages"
    if lib_sp.is_dir():
        _add(lib_sp)

    # Case 3: recursive search for any site-packages (catches nested venvs,
    # conda envs inside a project tree, etc.).  Only used when the above
    # produced no results — avoids redundant work on well-structured targets.
    if not results:
        for sp in _safe_glob(target, "**/site-packages"):
            _add(sp)

    return results


# ---------------------------------------------------------------------------
# Phase 2 — Artifact discovery
# ---------------------------------------------------------------------------


@dataclass
class _RawArtifacts:
    """Intermediate container for filesystem artifacts found in site-packages."""

    package_dir: Path | None = None
    dist_info_dirs: list[Path] = field(default_factory=list)
    pth_file: Path | None = None


def _find_artifacts(site_packages: Path) -> _RawArtifacts:
    """Locates litellm-related filesystem artifacts in *site_packages*."""
    arts = _RawArtifacts()

    pkg = site_packages / "litellm"
    if pkg.is_dir():
        arts.package_dir = pkg

    for entry in _safe_glob(site_packages, "litellm-*.dist-info"):
        if entry.is_dir():
            arts.dist_info_dirs.append(entry)

    pth = site_packages / "litellm_init.pth"
    if pth.is_file():
        arts.pth_file = pth

    return arts


# ---------------------------------------------------------------------------
# Phase 3 — Metadata extraction
# ---------------------------------------------------------------------------


def parse_version(dist_info: Path) -> str | None:
    """Extracts the ``Version`` field from dist-info metadata.

    Tries ``METADATA`` then ``PKG-INFO``.  Falls back to parsing the version
    from the directory name (e.g. ``litellm-1.82.8.dist-info`` → ``1.82.8``).
    """
    for name in ("METADATA", "PKG-INFO"):
        meta = dist_info / name
        if not meta.is_file():
            continue
        version = _extract_version_field(meta)
        if version is not None:
            return version

    # Fallback: directory name.
    m = _DIST_INFO_VERSION_RE.match(dist_info.name)
    return m.group(1) if m else None


def record_mentions_pth(dist_info: Path) -> bool:
    """Returns ``True`` if the ``RECORD`` manifest references ``litellm_init.pth``."""
    record = dist_info / "RECORD"
    if not record.is_file():
        return False
    try:
        text = record.read_text(errors="replace")
    except OSError:
        return False
    return "litellm_init.pth" in text


def _extract_version_field(meta_path: Path) -> str | None:
    """Reads the first ``Version:`` field from a metadata file."""
    try:
        text = meta_path.read_text(errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("Version:"):
            return line.split(":", 1)[1].strip()
    return None


# ---------------------------------------------------------------------------
# Phase 4 — Classification engine
# ---------------------------------------------------------------------------


def classify(
    *,
    litellm_present: bool,
    version: str | None,
    pth_present: bool,
    record_mentions_pth: bool,
    dist_info_count: int,
    metadata_readable: bool,
    strict_1827: bool = False,
) -> tuple[Classification, list[str]]:
    """Determines the classification for a single site-packages finding.

    Returns:
        A ``(classification, reasons)`` pair.
    """
    if not litellm_present:
        return Classification.CLEAN, []

    reasons: list[str] = []

    # --- compromised-candidate signals ---
    if version in _COMPROMISED_VERSIONS:
        reasons.append(f"version={version}")

    if pth_present:
        reasons.append("litellm_init.pth present")

    if record_mentions_pth:
        reasons.append("RECORD mentions litellm_init.pth")

    if strict_1827 and version in _SUSPICIOUS_VERSIONS:
        reasons.append(f"version={version} (strict mode)")

    if reasons:
        return Classification.COMPROMISED_CANDIDATE, reasons

    # --- suspicious signals ---
    suspicious_reasons: list[str] = []

    if version in _SUSPICIOUS_VERSIONS:
        suspicious_reasons.append(f"version={version}")

    if not metadata_readable:
        suspicious_reasons.append("metadata missing or malformed")

    if dist_info_count > 1:
        suspicious_reasons.append(
            f"multiple dist-info directories ({dist_info_count})"
        )

    if dist_info_count == 0:
        suspicious_reasons.append("package directory present without dist-info")

    if suspicious_reasons:
        return Classification.SUSPICIOUS, suspicious_reasons

    # --- present but no IOCs ---
    return Classification.SUSPICIOUS, [f"litellm {version or '(unknown version)'} present"]


# ---------------------------------------------------------------------------
# Phase 5 — Inspection orchestrator
# ---------------------------------------------------------------------------


def inspect_site_packages(
    site_packages: Path,
    *,
    strict_1827: bool = False,
) -> SitePackagesFinding:
    """Inspects a single ``site-packages`` directory for litellm artifacts.

    This is the main entry point that wires together artifact discovery,
    metadata extraction, and classification.
    """
    arts = _find_artifacts(site_packages)

    litellm_present = (
        arts.package_dir is not None
        or bool(arts.dist_info_dirs)
        or arts.pth_file is not None
    )

    # Pick the first dist-info for version / RECORD (most common case).
    dist_info = arts.dist_info_dirs[0] if arts.dist_info_dirs else None
    version = parse_version(dist_info) if dist_info else None
    rec_pth = record_mentions_pth(dist_info) if dist_info else False

    metadata_readable = version is not None if dist_info else True

    cls, reasons = classify(
        litellm_present=litellm_present,
        version=version,
        pth_present=arts.pth_file is not None,
        record_mentions_pth=rec_pth,
        dist_info_count=len(arts.dist_info_dirs),
        metadata_readable=metadata_readable,
        strict_1827=strict_1827,
    )

    return SitePackagesFinding(
        path=site_packages,
        litellm_present=litellm_present,
        version=version,
        dist_info_path=dist_info,
        package_path=arts.package_dir,
        pth_present=arts.pth_file is not None,
        pth_path=arts.pth_file,
        record_mentions_pth=rec_pth,
        classification=cls,
        reasons=tuple(reasons),
    )


def scan_target(
    target: Path,
    *,
    strict_1827: bool = False,
) -> TargetReport:
    """Scans a single target path and returns a full report."""
    site_packages_dirs = discover_site_packages(target)
    findings = tuple(
        inspect_site_packages(sp, strict_1827=strict_1827)
        for sp in site_packages_dirs
    )
    return TargetReport(target=target, site_packages=findings)


# ---------------------------------------------------------------------------
# Phase 5 cont. — Reporting
# ---------------------------------------------------------------------------

# Exit codes per the plan.
EXIT_CLEAN = 0
EXIT_SUSPICIOUS = 1
EXIT_COMPROMISED = 2
EXIT_ERROR = 3


class _Colors:
    """ANSI escape sequences (disabled when stdout is not a TTY)."""

    _on = sys.stdout.isatty()

    GREEN = "\033[92m" if _on else ""
    RED = "\033[91m" if _on else ""
    YELLOW = "\033[93m" if _on else ""
    BOLD = "\033[1m" if _on else ""
    RESET = "\033[0m" if _on else ""


def format_report_text(reports: Sequence[TargetReport]) -> str:
    """Renders reports as human-readable text."""
    c = _Colors
    lines: list[str] = []

    for report in reports:
        lines.append(f"\n{c.BOLD}Target: {report.target}{c.RESET}")

        if not report.site_packages:
            lines.append(f"  {c.YELLOW}No site-packages directories found.{c.RESET}")
            continue

        for f in report.site_packages:
            _append_finding_text(lines, f)

    return "\n".join(lines)


def _append_finding_text(lines: list[str], f: SitePackagesFinding) -> None:
    """Appends formatted text lines for one finding."""
    c = _Colors

    cls_colors = {
        Classification.CLEAN: c.GREEN,
        Classification.SUSPICIOUS: c.YELLOW,
        Classification.COMPROMISED_CANDIDATE: c.RED,
    }
    cls_icons = {
        Classification.CLEAN: "✔",
        Classification.SUSPICIOUS: "⚠",
        Classification.COMPROMISED_CANDIDATE: "✘",
    }
    color = cls_colors[f.classification]
    icon = cls_icons[f.classification]

    lines.append(f"  {color}{icon}{c.RESET} {f.path}")
    lines.append(
        f"    Status: {color}{c.BOLD}{f.classification.value}{c.RESET}"
    )

    if f.reasons:
        lines.append(f"    Reasons:")
        for reason in f.reasons:
            lines.append(f"      - {reason}")

    if f.version:
        lines.append(f"    Version: {f.version}")
    if f.pth_present:
        lines.append(
            f"    {c.RED}{c.BOLD}litellm_init.pth BACKDOOR PRESENT{c.RESET}"
        )
    if f.record_mentions_pth:
        lines.append(
            f"    {c.RED}RECORD references litellm_init.pth{c.RESET}"
        )


def format_report_json(reports: Sequence[TargetReport]) -> str:
    """Renders reports as a JSON string."""
    return json.dumps(
        [r.to_dict() for r in reports],
        indent=2,
    )


def worst_exit_code(reports: Sequence[TargetReport]) -> int:
    """Returns the most severe exit code across all reports."""
    worst = EXIT_CLEAN
    for report in reports:
        cls = report.worst_classification
        if cls == Classification.COMPROMISED_CANDIDATE:
            return EXIT_COMPROMISED
        if cls == Classification.SUSPICIOUS:
            worst = EXIT_SUSPICIOUS
    return worst


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_glob(root: Path, pattern: str) -> list[Path]:
    """Glob with protection against permission errors and symlink loops."""
    try:
        return sorted(root.glob(pattern))
    except (PermissionError, OSError):
        return []


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    """Constructs the argument parser."""
    parser = argparse.ArgumentParser(
        prog="safe_litellm_detector",
        description=(
            "Incident-response-safe detector for compromised litellm "
            "installations.  Inspects Python environments via filesystem "
            "only — never executes a suspect interpreter."
        ),
    )
    parser.add_argument(
        "targets",
        nargs="+",
        type=Path,
        help="Paths to inspect (venv roots, site-packages dirs, or trees).",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        default=False,
        help="Emit JSON instead of human-readable text.",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        default=False,
        help="Recursively search for site-packages under each target.",
    )
    parser.add_argument(
        "--strict-1827",
        action="store_true",
        default=False,
        help="Treat version 1.82.7 as compromised-candidate instead of suspicious.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        default=False,
        help="Suppress output; exit code only.",
    )
    return parser


def _expand_recursive(targets: Sequence[Path]) -> list[Path]:
    """Expands each target into individual venv / conda roots found beneath it."""
    expanded: list[Path] = []
    seen: set[Path] = set()

    for target in targets:
        target = target.expanduser()
        if not target.is_dir():
            expanded.append(target)
            continue

        found_any = False
        for sp in _safe_glob(target, "**/site-packages"):
            # Walk up to the env root: .../lib/pythonX.Y/site-packages → ...
            # or .../Lib/site-packages → ...
            env_root = sp.parent.parent.parent  # lib/pythonX.Y/site-packages
            if env_root.name == "lib" or env_root.name == "Lib":
                env_root = env_root.parent
            try:
                resolved = env_root.resolve()
            except OSError:
                continue
            if resolved not in seen:
                seen.add(resolved)
                expanded.append(env_root)
                found_any = True

        # If nothing was found underneath, scan the target itself (may be a
        # bare site-packages dir or have no Python envs at all).
        if not found_any:
            expanded.append(target)

    return expanded


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point.  Returns an exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    targets: list[Path] = [t.expanduser() for t in args.targets]

    if args.recursive:
        targets = _expand_recursive(targets)

    reports: list[TargetReport] = []
    for target in targets:
        try:
            reports.append(scan_target(target, strict_1827=args.strict_1827))
        except Exception as exc:
            if not args.quiet:
                print(f"Error scanning {target}: {exc}", file=sys.stderr)
            return EXIT_ERROR

    if not args.quiet:
        if args.json_output:
            print(format_report_json(reports))
        else:
            print(format_report_text(reports))

    return worst_exit_code(reports)


if __name__ == "__main__":
    sys.exit(main())
