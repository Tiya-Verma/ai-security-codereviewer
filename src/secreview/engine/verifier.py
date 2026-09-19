"""Verifier pass: adversarially re-check each candidate finding.

The verifier's job is the opposite of the generator's: assume each finding is a
false positive and try to prove the code is actually safe. This directly targets
the "flagged intentional design patterns" and "overconfidence from incomplete
context" failure modes in CLAUDE.md. It also reports what context would change
its assessment, so we never surface unwarranted certainty.
"""

from __future__ import annotations

from ..config import ReviewConfig
from ..llm import LLMClient
from ..models import Finding, Verdict

_SYSTEM = """You are an adversarial reviewer. You are given a security finding another
model proposed about a code change. Assume it is a FALSE POSITIVE and try to prove the
code is actually safe: look for parameterization, validation, framework guarantees, or
intentional design patterns the first pass may have missed.

Uphold the finding ONLY if you cannot disprove it. Report your confidence and, critically,
what additional context (call sites, definitions, config) would change your assessment."""


def verify_one(
    client: LLMClient,
    config: ReviewConfig,
    finding: Finding,
    context: str = "",
) -> Verdict:
    system = _SYSTEM
    if config.false_positive_instructions:
        system += (
            "\n\nProject-specific false-positive guidance:\n"
            f"{config.false_positive_instructions}"
        )

    user = (
        "Adversarially verify this finding.\n\n"
        f"File: {finding.file}\n"
        f"Line: {finding.line}\n"
        f"Title: {finding.title}\n"
        f"Severity: {finding.severity.value}\n"
        f"CWE: {finding.cwe}\n"
        f"Description: {finding.description}\n"
    )
    if context:
        user += f"\nAdditional repository context:\n{context}"

    return client.structured(
        model=config.models.verifier,
        system=system,
        user=user,
        schema_model=Verdict,
        max_tokens=config.models.max_tokens,
    )


def verify(
    client: LLMClient,
    config: ReviewConfig,
    findings: list[Finding],
    context: str = "",
) -> list[Finding]:
    """Verify each finding, attach its verdict, and keep only the upheld ones."""
    upheld: list[Finding] = []
    for f in findings:
        verdict = verify_one(client, config, f, context)
        f.verdict = verdict
        if verdict.upheld:
            # Let the verifier's (adversarial) confidence override the generator's.
            f.confidence = verdict.confidence
            upheld.append(f)
    return upheld
