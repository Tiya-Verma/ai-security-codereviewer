"""Wire the passes together: parse diff -> generate -> (optionally) verify ->
severity-threshold filter. Suppression/baseline filtering and PR routing are
layered on by callers (CLI / Action) once findings exist.
"""

from __future__ import annotations

from ..config import ReviewConfig
from ..diff import parse_diff
from ..llm import LLMClient, StructuredClient
from ..models import Finding, ReviewResult
from ..suppression import apply_suppressions
from .generator import generate
from .verifier import verify


def review_diff(
    diff_text: str,
    config: ReviewConfig | None = None,
    client: StructuredClient | None = None,
    context: str = "",
    base_dir: str = ".",
    generator_findings: list[Finding] | None = None,
) -> ReviewResult:
    """Run the full detection pipeline over a unified diff.

    With `config.enable_verifier` off, this is the generator-only baseline the
    benchmark compares against (docs/ROADMAP.md M1 vs M2). Passing
    `generator_findings` skips the generator pass and reuses that output, so
    the benchmark can score both modes from one generator run.
    """
    config = config or ReviewConfig()
    client = client or LLMClient()

    changed = parse_diff(diff_text, ignore_paths=config.ignore_paths)
    if generator_findings is None:
        generator_findings = generate(client, config, changed, context)

    if config.enable_verifier:
        final = verify(client, config, list(generator_findings), context)
    else:
        final = list(generator_findings)

    threshold = config.severity_threshold
    final = [f for f in final if f.severity.rank >= threshold.rank]

    # Config-driven suppression is the last filter before findings surface.
    final, suppressed = apply_suppressions(final, changed, config, base_dir=base_dir)

    return ReviewResult(
        generator_findings=generator_findings,
        final_findings=final,
        suppressed_findings=[s.finding for s in suppressed],
    )
