"""Generator pass: propose candidate findings from a diff.

This is intentionally high-recall — it is allowed to over-report, because the
verifier pass is what buys precision. The benchmark measures the delta between
this pass alone and this pass + verifier (CLAUDE.md M1 vs M2).
"""

from __future__ import annotations

from pydantic import BaseModel

from ..config import ReviewConfig
from ..diff import ChangedFile
from ..llm import LLMClient
from ..models import Finding

_SYSTEM = """You are a security engineer reviewing a code change for vulnerabilities.
Report every plausible security issue you can justify from the diff and provided context.
Favor recall: it is acceptable to over-report here, a later verification pass will filter.
For each finding give a specific title, the vulnerability class (CWE id when known),
a severity, and a pattern-level remediation. Do NOT write working exploits."""


class _GeneratorOutput(BaseModel):
    findings: list[Finding]


def generate(
    client: LLMClient,
    config: ReviewConfig,
    changed: list[ChangedFile],
    context: str = "",
) -> list[Finding]:
    """Run the generator pass over all changed files in one call."""
    if not changed:
        return []

    system = _SYSTEM
    if config.scan_instructions:
        system += f"\n\nProject-specific scan instructions:\n{config.scan_instructions}"

    diff_blob = "\n\n".join(f"--- {cf.path} ---\n{cf.patch_text}" for cf in changed)
    user = f"Review this diff for security vulnerabilities.\n\n{diff_blob}"
    if context:
        user += f"\n\nAdditional repository context:\n{context}"

    out = client.structured(
        model=config.models.generator,
        system=system,
        user=user,
        schema_model=_GeneratorOutput,
        max_tokens=config.models.max_tokens,
    )
    return out.findings
