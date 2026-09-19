"""Diff extraction and changed-line mapping.

Deliberately language-agnostic: we parse unified diff structure only, never
tokenize source. The one place language matters is `ignore_paths` filtering,
which is glob-based and caller-supplied.

Mapping findings back to correct diff line positions (for inline PR comments)
is the fiddly part called out in CLAUDE.md build step 7 — `changed_line_numbers`
is the primitive that work will build on.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

from unidiff import PatchSet


@dataclass
class ChangedFile:
    path: str
    # New-file line numbers that were added/modified in this diff.
    added_lines: set[int] = field(default_factory=set)
    # The raw per-file patch text, for feeding to the generator.
    patch_text: str = ""


def parse_diff(diff_text: str, ignore_paths: list[str] | None = None) -> list[ChangedFile]:
    """Parse a unified diff into changed files, skipping ignored globs and
    removed files (nothing to review in a deletion)."""
    ignore = ignore_paths or []
    patch = PatchSet(diff_text)
    result: list[ChangedFile] = []

    for pf in patch:
        path = pf.path
        if pf.is_removed_file:
            continue
        if any(fnmatch.fnmatch(path, pat) for pat in ignore):
            continue

        added: set[int] = set()
        for hunk in pf:
            for line in hunk:
                if line.is_added and line.target_line_no is not None:
                    added.add(line.target_line_no)

        result.append(ChangedFile(path=path, added_lines=added, patch_text=str(pf)))

    return result
