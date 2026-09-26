"""Config-driven suppression: the last filter before findings are surfaced.

Two mechanisms (CLAUDE.md "Suppression mechanism"):

1. Inline marker — a comment like ``// security-review: ignore`` on the flagged
   line or the line directly above it drops that finding. Lets a developer
   accept a specific finding at the point of code.
2. Baseline / allowlist file — a list of accepted, recurring risks. A finding
   matching any baseline entry (by file glob, and optionally CWE and/or a title
   substring) is dropped. Lets a team accept known risks org-wide without
   re-triaging them every PR.

Everything here is pure logic (no LLM/API), so it is unit-tested without a key.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import BaseModel

from .config import ReviewConfig
from .diff import ChangedFile
from .models import Finding


class BaselineEntry(BaseModel):
    """One accepted risk. An entry matches a finding when every field it
    specifies matches; a file-only entry accepts all findings in that file."""

    file: str  # glob, matched against the finding's file path
    cwe: str | None = None
    title: str | None = None  # case-insensitive substring of the finding's title

    def matches(self, finding: Finding) -> bool:
        if not fnmatch.fnmatch(finding.file, self.file):
            return False
        if self.cwe is not None and finding.cwe != self.cwe:
            return False
        return self.title is None or self.title.lower() in finding.title.lower()


def load_baseline(path: str | Path) -> list[BaselineEntry]:
    """Load a baseline file (a YAML list of entries). Missing file -> empty."""
    p = Path(path)
    if not p.exists():
        return []
    data = yaml.safe_load(p.read_text()) or []
    return [BaselineEntry.model_validate(e) for e in data]


@dataclass
class Suppressed:
    finding: Finding
    reason: str  # "inline" | "baseline"


def _inline_suppressed(finding: Finding, changed: dict[str, ChangedFile], marker: str) -> bool:
    cf = changed.get(finding.file)
    if cf is None or finding.line is None:
        return False
    # Marker on the flagged line itself or the line immediately above it.
    for ln in (finding.line, finding.line - 1):
        text = cf.new_lines.get(ln)
        if text is not None and marker in text:
            return True
    return False


def apply_suppressions(
    findings: list[Finding],
    changed_files: list[ChangedFile],
    config: ReviewConfig,
    base_dir: str | Path = ".",
) -> tuple[list[Finding], list[Suppressed]]:
    """Split findings into (kept, suppressed). Inline markers take precedence
    over the baseline so the reason is attributed to the closest signal."""
    marker = config.suppression.inline_marker
    changed = {cf.path: cf for cf in changed_files}

    baseline: list[BaselineEntry] = []
    if config.suppression.baseline_file:
        baseline = load_baseline(Path(base_dir) / config.suppression.baseline_file)

    kept: list[Finding] = []
    suppressed: list[Suppressed] = []
    for f in findings:
        if _inline_suppressed(f, changed, marker):
            suppressed.append(Suppressed(f, "inline"))
        elif any(entry.matches(f) for entry in baseline):
            suppressed.append(Suppressed(f, "baseline"))
        else:
            kept.append(f)
    return kept, suppressed
