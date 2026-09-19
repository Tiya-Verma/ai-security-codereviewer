"""Core data models shared across the pipeline.

These are deliberately plain: the generator emits `Finding`s, the verifier
annotates them with a `Verdict`, and the benchmark scores `Finding`s against
labeled ground truth. Keeping them in one place means the JSON schema forced
on the model (via tool_use) and the schema the benchmark reads are the same.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        order = ["info", "low", "medium", "high", "critical"]
        return order.index(self.value)


class Confidence(StrEnum):
    """Routing bucket. Calibrated against benchmark precision per bucket —
    a "high" bucket that isn't more precise than "low" is decoration, not signal.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Finding(BaseModel):
    """A single candidate vulnerability. Produced by the generator, may be
    dropped or down-ranked by the verifier."""

    file: str = Field(description="Path relative to repo root.")
    line: int | None = Field(
        default=None, description="1-indexed line in the new file, if pinpointable."
    )
    title: str = Field(description="Short, specific summary of the issue.")
    description: str = Field(description="What the vulnerability is and why it matters.")
    severity: Severity
    cwe: str | None = Field(default=None, description="CWE id, e.g. 'CWE-89'.")
    confidence: Confidence = Confidence.MEDIUM
    remediation: str | None = Field(
        default=None, description="Suggested fix, educational/pattern-level only."
    )
    # Populated by the verifier pass.
    verdict: Verdict | None = None


class Verdict(BaseModel):
    """Result of the adversarial verifier pass on one finding."""

    upheld: bool = Field(description="True if the finding survives adversarial re-check.")
    confidence: Confidence
    rationale: str = Field(description="Why the finding was upheld or rejected.")
    context_that_would_change_this: str | None = Field(
        default=None,
        description="What additional context could flip the assessment "
        "(guards against overconfidence from incomplete context).",
    )


# Resolve the forward reference in Finding.verdict.
Finding.model_rebuild()


class ReviewResult(BaseModel):
    """Everything produced for one diff/PR: the surviving findings plus the
    raw generator output, so the benchmark can compare generator-only vs.
    generator+verifier numbers."""

    generator_findings: list[Finding] = Field(default_factory=list)
    final_findings: list[Finding] = Field(default_factory=list)
