"""Map findings to GitHub PR review comments, and route them inline vs. summary.

The fiddly part (CLAUDE.md build step 7) is putting a comment on the *right*
line. GitHub's review-comment API accepts two addressing schemes:

- modern: ``line`` (the file line number) + ``side`` (RIGHT for added lines);
- legacy: ``position`` (offset from the first @@ hunk header, see diff.py).

We emit both, so callers can use whichever the endpoint/library expects, and we
only ever comment on lines that are actually part of the diff — anything else
(no line, or a line outside the changed hunks) is routed to the summary comment
instead, where it can't 422 the API.

Routing policy (CLAUDE.md "route by confidence"): high/medium-confidence,
mappable findings go inline; low-confidence or unmappable findings collapse into
the summary so the bot stays quiet where it's least sure. Pure logic, no network.
"""

from __future__ import annotations

from dataclasses import dataclass

from .diff import ChangedFile
from .models import Confidence, Finding

# Confidence buckets that are allowed to post as inline comments.
INLINE_CONFIDENCES = frozenset({Confidence.HIGH, Confidence.MEDIUM})


@dataclass
class ReviewComment:
    """A GitHub PR review comment payload. `line`/`side` is the modern form;
    `position` is the legacy form — both address the same spot."""

    path: str
    line: int
    side: str  # "RIGHT" (added/context lines) — we never comment on deletions
    position: int
    body: str

    def to_api_payload(self, *, legacy: bool = False) -> dict:
        """dict for POST .../pulls/{n}/comments. `legacy=True` uses `position`."""
        base = {"path": self.path, "body": self.body}
        if legacy:
            return {**base, "position": self.position}
        return {**base, "line": self.line, "side": self.side}


def render_body(finding: Finding) -> str:
    """Markdown body for an inline comment."""
    cwe = f" ({finding.cwe})" if finding.cwe else ""
    lines = [f"**{finding.severity.value.upper()}{cwe}: {finding.title}**", "", finding.description]
    if finding.remediation:
        lines += ["", f"_Remediation:_ {finding.remediation}"]
    lines += ["", f"<sub>confidence: {finding.confidence.value} · secreview</sub>"]
    return "\n".join(lines)


def build_review_comment(
    finding: Finding, changed: dict[str, ChangedFile]
) -> ReviewComment | None:
    """Build a comment payload, or None if the finding can't be pinned to a line
    in the diff (missing line, unknown file, or a line outside the changed hunks)."""
    if finding.line is None:
        return None
    cf = changed.get(finding.file)
    if cf is None:
        return None
    position = cf.positions.get(finding.line)
    if position is None:
        return None  # line exists in the file but not in the PR diff -> summary
    return ReviewComment(
        path=finding.file,
        line=finding.line,
        side="RIGHT",
        position=position,
        body=render_body(finding),
    )


def route_findings(
    findings: list[Finding],
    changed_files: list[ChangedFile],
    inline_confidences: frozenset[Confidence] = INLINE_CONFIDENCES,
) -> tuple[list[ReviewComment], list[Finding]]:
    """Split findings into (inline comments, summary-only findings).

    A finding goes inline only if it is confident enough AND maps to a diff line;
    everything else falls back to the summary."""
    changed = {cf.path: cf for cf in changed_files}
    inline: list[ReviewComment] = []
    summary: list[Finding] = []
    for f in findings:
        comment = build_review_comment(f, changed) if f.confidence in inline_confidences else None
        if comment is None:
            summary.append(f)
        else:
            inline.append(comment)
    return inline, summary
