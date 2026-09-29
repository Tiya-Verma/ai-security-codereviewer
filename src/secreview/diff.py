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
    # New-file line number -> content, for every line present in the new file
    # within the diff's hunks (added + context). Used to read inline suppress
    # markers, and the primitive for finding->diff-position mapping (M5 step 7).
    new_lines: dict[int, str] = field(default_factory=dict)
    # New-file line number -> GitHub diff "position": the 1-based offset counted
    # down from the file's FIRST @@ hunk header. It increments through context,
    # added AND removed lines, plus every subsequent @@ header — so it is NOT
    # the file line number. Required by the legacy inline-comment API.
    positions: dict[int, int] = field(default_factory=dict)


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
        new_lines: dict[int, str] = {}
        positions: dict[int, int] = {}
        # GitHub diff position: the line just below the first @@ header is 1.
        # The first header is the reference (0); each later header is itself a
        # counted line. Removed lines count too (they appear in the diff).
        position = 0
        for hunk_index, hunk in enumerate(pf):
            if hunk_index > 0:
                position += 1  # a subsequent @@ header occupies a diff line
            for line in hunk:
                position += 1
                if line.target_line_no is None:
                    continue  # removed line: counted above, but not in new file
                if line.is_added or line.is_context:
                    new_lines[line.target_line_no] = line.value.rstrip("\n")
                    positions[line.target_line_no] = position
                if line.is_added:
                    added.add(line.target_line_no)

        result.append(
            ChangedFile(
                path=path,
                added_lines=added,
                patch_text=str(pf),
                new_lines=new_lines,
                positions=positions,
            )
        )

    return result
