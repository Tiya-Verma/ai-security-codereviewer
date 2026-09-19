"""Wire the passes together: parse diff -> generate -> (optionally) verify ->
severity-threshold filter. Suppression/baseline filtering and PR routing are
layered on by callers (CLI / Action) once findings exist.
"""

from __future__ import annotations

from ..config import ReviewConfig
from ..diff import parse_diff
from ..llm import LLMClient
from ..models import ReviewResult
from .generator import generate
from .verifier import verify


def review_diff(
    diff_text: str,
    config: ReviewConfig | None = None,
    client: LLMClient | None = None,
    context: str = "",
) -> ReviewResult:
    """Run the full detection pipeline over a unified diff.

    With `config.enable_verifier` off, this is the generator-only baseline the
    benchmark compares against (CLAUDE.md M1 vs M2).
    """
    config = config or ReviewConfig()
    client = client or LLMClient()

    changed = parse_diff(diff_text, ignore_paths=config.ignore_paths)
    generator_findings = generate(client, config, changed, context)

    if config.enable_verifier:
        final = verify(client, config, list(generator_findings), context)
    else:
        final = list(generator_findings)

    threshold = config.severity_threshold
    final = [f for f in final if f.severity.rank >= threshold.rank]

    return ReviewResult(generator_findings=generator_findings, final_findings=final)
