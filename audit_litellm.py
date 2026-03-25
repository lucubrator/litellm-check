#!/usr/bin/env python3
"""Scans default project directories and global Python installations for litellm.

This is the fleet-scanning wrapper around :mod:`safe_litellm_detector`.  It
walks ``~/projects``, ``~/work``, any extra CLI paths, and every global Python
installation, then feeds discovered ``site-packages`` directories into the
detector's filesystem-only inspection engine.

Usage::

    python3 audit_litellm.py [EXTRA_DIR ...]
    python3 audit_litellm.py --json
    python3 audit_litellm.py ~/src --strict-1827 --json
"""

from __future__ import annotations

import abc
import argparse
import os
import re
import sys
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Iterable, Sequence

from safe_litellm_detector import (
    Classification,
    SitePackagesFinding,
    TargetReport,
    discover_site_packages,
    format_report_json,
    inspect_site_packages,
    worst_exit_code,
    EXIT_CLEAN,
    EXIT_ERROR,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_VENV_DIR_NAMES: tuple[str, ...] = (
    ".venv", "venv", "env", ".env", "ENV", "virtenv", ".virtenv",
)

_WELL_KNOWN_PYTHONS: tuple[str, ...] = (
    "/usr/bin/python3",
    "/usr/local/bin/python3",
    "/opt/homebrew/bin/python3",
)

_PYTHON_EXE_RE = re.compile(r"^python\d?(\.\d+)?$")

# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------


class EnvKind(Enum):
    """Classification of a discovered environment's origin."""

    REPOSITORY = auto()
    GLOBAL = auto()


@dataclass(frozen=True)
class AuditFinding:
    """Pairs an environment label with the detector's finding for one site-packages."""

    label: str
    kind: EnvKind
    detail: SitePackagesFinding


@dataclass
class AuditReport:
    """Aggregated results across all environments."""

    findings: list[AuditFinding] = field(default_factory=list)

    @property
    def worst_classification(self) -> Classification:
        """Returns the most severe classification across all findings."""
        worst = Classification.CLEAN
        for f in self.findings:
            if f.detail.classification == Classification.COMPROMISED_CANDIDATE:
                return Classification.COMPROMISED_CANDIDATE
            if f.detail.classification == Classification.SUSPICIOUS:
                worst = Classification.SUSPICIOUS
        return worst

    @property
    def total_checked(self) -> int:
        """Number of site-packages directories inspected."""
        return len(self.findings)

    def by_kind(self, kind: EnvKind) -> list[AuditFinding]:
        """Returns findings filtered by *kind*."""
        return [f for f in self.findings if f.kind == kind]


# ---------------------------------------------------------------------------
# Environment discovery
# ---------------------------------------------------------------------------


class EnvironmentDiscovery(abc.ABC):
    """Yields ``(label, site_packages_path, kind)`` tuples."""

    @abc.abstractmethod
    def discover(self) -> Iterable[tuple[str, Path, EnvKind]]:
        """Generates ``site-packages`` directories to inspect."""


class RepoVenvDiscovery(EnvironmentDiscovery):
    """Finds ``site-packages`` inside virtual environments in Git repos."""

    def __init__(self, root_dirs: Sequence[Path]) -> None:
        self._root_dirs = root_dirs

    def discover(self) -> Iterable[tuple[str, Path, EnvKind]]:
        for root in self._root_dirs:
            if not root.is_dir():
                continue
            for repo in self._git_repos(root):
                for sp in self._find_venv_site_packages(repo):
                    yield f"{repo.name} (venv)", sp, EnvKind.REPOSITORY

    @staticmethod
    def _git_repos(root: Path) -> list[Path]:
        """Returns de-duplicated Git repo paths under *root*."""
        repos: list[Path] = []
        try:
            for git_dir in sorted(root.rglob(".git")):
                repo = git_dir.parent
                if not any(repo.is_relative_to(r) for r in repos):
                    repos.append(repo)
        except (PermissionError, OSError):
            pass
        return repos

    @staticmethod
    def _find_venv_site_packages(repo: Path) -> list[Path]:
        """Returns every ``site-packages`` directory inside recognised venvs."""
        results: list[Path] = []
        for name in _VENV_DIR_NAMES:
            venv = repo / name
            if not venv.is_dir():
                continue
            results.extend(sorted(venv.glob("lib/python*/site-packages")))
            sp = venv / "Lib" / "site-packages"
            if sp.is_dir():
                results.append(sp)
        return results


class GlobalPythonDiscovery(EnvironmentDiscovery):
    """Discovers ``site-packages`` for system-wide Python interpreters.

    Derives paths from the filesystem layout of each interpreter — the
    interpreter itself is **never executed**.
    """

    def discover(self) -> Iterable[tuple[str, Path, EnvKind]]:
        seen: set[Path] = set()
        for python in self._collect_pythons():
            for sp in self._site_packages_for(python):
                resolved = _safe_resolve(sp)
                if resolved is None or resolved in seen:
                    continue
                seen.add(resolved)
                yield f"System ({python})", sp, EnvKind.GLOBAL

    @staticmethod
    def _collect_pythons() -> Iterable[Path]:
        """Yields candidate Python executables (never runs them)."""
        yield Path(sys.executable)
        for p in _WELL_KNOWN_PYTHONS:
            path = Path(p)
            if path.exists():
                yield path
        yield from _pythons_on_path()

    @staticmethod
    def _site_packages_for(python: Path) -> list[Path]:
        """Infers ``site-packages`` from *python*'s filesystem location."""
        results: list[Path] = []
        resolved = _safe_resolve(python)
        if resolved is None:
            return results

        prefix = resolved.parent.parent
        results.extend(prefix.glob("lib/python*/site-packages"))

        results.extend(Path("/opt/homebrew/lib").glob("python*/site-packages"))
        results.extend(Path("/usr/local/lib").glob("python*/site-packages"))

        for clt in (
            Path("/Library/Developer/CommandLineTools/Library/Frameworks/"
                 "Python3.framework/Versions"),
            Path("/Applications/Xcode.app/Contents/Developer/Library/"
                 "Frameworks/Python3.framework/Versions"),
        ):
            if clt.is_dir():
                results.extend(clt.glob("*/lib/python*/site-packages"))

        return [p for p in results if p.is_dir()]


# ---------------------------------------------------------------------------
# Auditor
# ---------------------------------------------------------------------------


class Auditor:
    """Orchestrates discovery, detection (via the detector), and deduplication."""

    def __init__(
        self,
        discoveries: Sequence[EnvironmentDiscovery],
        *,
        strict_1827: bool = False,
    ) -> None:
        self._discoveries = discoveries
        self._strict_1827 = strict_1827

    def run(self) -> AuditReport:
        """Executes the full audit and returns a report."""
        report = AuditReport()
        seen: set[Path] = set()

        for discovery in self._discoveries:
            for label, site_packages, kind in discovery.discover():
                resolved = _safe_resolve(site_packages)
                if resolved is None or resolved in seen:
                    continue
                seen.add(resolved)

                detail = inspect_site_packages(
                    site_packages, strict_1827=self._strict_1827,
                )
                report.findings.append(AuditFinding(
                    label=label, kind=kind, detail=detail,
                ))
        return report


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


class _Colors:
    """ANSI escape sequences (disabled when stdout is not a TTY)."""

    _on = sys.stdout.isatty()

    GREEN = "\033[92m" if _on else ""
    RED = "\033[91m" if _on else ""
    YELLOW = "\033[93m" if _on else ""
    BOLD = "\033[1m" if _on else ""
    RESET = "\033[0m" if _on else ""


_CLS_STYLE: dict[Classification, tuple[str, str]] = {}


def _cls_style(cls: Classification) -> tuple[str, str]:
    """Returns ``(color, icon)`` for a classification."""
    c = _Colors
    return {
        Classification.CLEAN: (c.GREEN, "✔"),
        Classification.SUSPICIOUS: (c.YELLOW, "⚠"),
        Classification.COMPROMISED_CANDIDATE: (c.RED, "✘"),
    }[cls]


def print_report(report: AuditReport) -> None:
    """Prints a human-readable audit report to stdout."""
    c = _Colors
    _banner("AUDIT SUMMARY")

    if not report.findings:
        print(f"{c.YELLOW}No environments found to check.{c.RESET}\n")
    else:
        for kind, heading in (
            (EnvKind.REPOSITORY, "Repository Virtual Environments"),
            (EnvKind.GLOBAL, "Global Python Installations"),
        ):
            group = report.by_kind(kind)
            if not group:
                continue
            print(f"{c.BOLD}{heading}:{c.RESET}")
            for af in group:
                _print_finding(af)
            print()

        print(
            f"{c.BOLD}Total environments checked: "
            f"{report.total_checked}{c.RESET}"
        )

    _banner("FINAL VERDICT")
    worst = report.worst_classification

    color, _ = _cls_style(worst)
    verdicts = {
        Classification.CLEAN: "no issues found",
        Classification.SUSPICIOUS: "suspicious — review needed",
        Classification.COMPROMISED_CANDIDATE: "possibly compromised",
    }
    print(f"{color}{c.BOLD}{verdicts[worst]}{c.RESET}")


def _banner(title: str) -> None:
    """Prints a section banner line."""
    c = _Colors
    sep = "=" * 70
    print(f"\n{c.BOLD}{sep}\n{title}\n{sep}{c.RESET}\n")


def _print_finding(af: AuditFinding) -> None:
    """Prints a single environment finding."""
    c = _Colors
    f = af.detail
    color, icon = _cls_style(f.classification)

    print(f"\n  {color}{icon}{c.RESET} {af.label}")
    print(f"      site-packages: {f.path}")
    print(f"      Status: {color}{c.BOLD}{f.classification.value}{c.RESET}")

    if f.reasons:
        for reason in f.reasons:
            print(f"        - {reason}")

    if f.pth_present:
        print(
            f"      {c.RED}{c.BOLD}"
            f"litellm_init.pth BACKDOOR PRESENT{c.RESET}"
        )
    if f.record_mentions_pth:
        print(f"      {c.RED}RECORD references litellm_init.pth{c.RESET}")


def print_json_report(report: AuditReport) -> None:
    """Prints findings as JSON to stdout."""
    import json

    data = [
        {
            "label": af.label,
            "kind": af.kind.name.lower(),
            **af.detail.to_dict(),
        }
        for af in report.findings
    ]
    print(json.dumps(data, indent=2))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pythons_on_path() -> Iterable[Path]:
    """Yields ``python*`` executables found on ``$PATH``."""
    for directory in os.environ.get("PATH", "").split(":"):
        try:
            for entry in Path(directory).iterdir():
                if _PYTHON_EXE_RE.match(entry.name) and entry.is_file():
                    yield entry
        except (PermissionError, OSError):
            continue


def _safe_resolve(path: Path) -> Path | None:
    """Resolves a symlink / relative path, returning ``None`` on failure."""
    try:
        return path.resolve()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    """Constructs the argument parser."""
    parser = argparse.ArgumentParser(
        prog="audit_litellm",
        description=(
            "Scans project directories and global Python installations for "
            "litellm.  Uses filesystem-only inspection — never executes a "
            "suspect interpreter."
        ),
    )
    parser.add_argument(
        "extra_dirs",
        nargs="*",
        type=Path,
        metavar="DIR",
        help="Additional directories to scan (beyond ~/projects and ~/work).",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        default=False,
        help="Emit JSON instead of human-readable text.",
    )
    parser.add_argument(
        "--strict-1827",
        action="store_true",
        default=False,
        help="Treat version 1.82.7 as compromised-candidate.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        default=False,
        help="Suppress output; exit code only.",
    )
    return parser


_EXIT_FOR_CLASSIFICATION: dict[Classification, int] = {
    Classification.CLEAN: 0,
    Classification.SUSPICIOUS: 1,
    Classification.COMPROMISED_CANDIDATE: 2,
}


def main(argv: Sequence[str] | None = None) -> int:
    """Runs the fleet audit and returns an exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    home = Path.home()
    root_dirs = [home / "projects", home / "work"]
    if args.extra_dirs:
        root_dirs.extend(p.expanduser() for p in args.extra_dirs)

    discoveries: list[EnvironmentDiscovery] = [
        RepoVenvDiscovery(root_dirs),
        GlobalPythonDiscovery(),
    ]

    auditor = Auditor(discoveries, strict_1827=args.strict_1827)
    report = auditor.run()

    if not args.quiet:
        if args.json_output:
            print_json_report(report)
        else:
            print_report(report)

    return _EXIT_FOR_CLASSIFICATION.get(
        report.worst_classification, EXIT_ERROR,
    )


if __name__ == "__main__":
    sys.exit(main())
