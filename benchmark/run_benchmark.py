"""Standalone benchmark runner — the reproducible-number engine.

Others can re-run this against their own fork or a new model version (docs/ROADMAP.md:
"Benchmark runner as a standalone script/CI job others can re-run"). It reads
the labeled corpus manifest, runs each sample through the pipeline in both
generator-only and generator+verifier modes, and prints the side-by-side
precision/recall/F1 table that is the project's core proof.

Usage:
    python benchmark/run_benchmark.py                 # full corpus, both modes
    python benchmark/run_benchmark.py --limit 5       # smoke test
    python benchmark/run_benchmark.py --backend claude-code   # no API key needed
"""

from __future__ import annotations

import argparse
import hashlib
from datetime import UTC, datetime
from pathlib import Path

import yaml
from metrics import Sample, aggregate, calibration, score  # noqa: E402  (sibling module)
from report import build_report, mode_summary, render_markdown, write_report  # noqa: E402

from secreview import __version__
from secreview.config import ReviewConfig
from secreview.engine import review_diff
from secreview.llm import ClaudeCodeClient, LLMClient, StructuredClient
from secreview.models import Finding

CORPUS_DIR = Path(__file__).parent / "corpus"
MANIFEST = CORPUS_DIR / "manifest.yml"
RESULTS_DIR = Path(__file__).parent / "results"

# One (Sample, findings) pair per corpus sample after running a pipeline mode.
ScoredRun = list[tuple[Sample, list[Finding]]]


def load_corpus(limit: int | None = None) -> list[tuple[Sample, str]]:
    """Return (Sample, diff_text) pairs from the manifest."""
    entries = yaml.safe_load(MANIFEST.read_text()) or []
    pairs: list[tuple[Sample, str]] = []
    for e in entries[: limit or len(entries)]:
        diff_text = (CORPUS_DIR / e["diff"]).read_text()
        sample = Sample(
            id=e["id"],
            is_vulnerable=bool(e["is_vulnerable"]),
            cwe=e.get("cwe"),
        )
        pairs.append((sample, diff_text))
    return pairs


def corpus_sha256() -> str:
    """Hash the manifest so results are traceable to the exact corpus."""
    return hashlib.sha256(MANIFEST.read_bytes()).hexdigest()


def run_both_modes(
    pairs: list[tuple[Sample, str]], config: ReviewConfig, client: StructuredClient
) -> tuple[ScoredRun, ScoredRun]:
    """Run each sample once through the generator, then score that same output
    with and without the verifier. Sharing one generator run per sample means
    the delta between modes is the verifier's effect, not run-to-run noise.
    Keeps per-sample findings (needed for calibration)."""
    gen_config = config.model_copy(update={"enable_verifier": False})
    verify_config = config.model_copy(update={"enable_verifier": True})
    gen_run: ScoredRun = []
    verify_run: ScoredRun = []
    for i, (sample, diff_text) in enumerate(pairs, 1):
        gen = review_diff(diff_text, config=gen_config, client=client)
        verified = review_diff(
            diff_text,
            config=verify_config,
            client=client,
            generator_findings=gen.generator_findings,
        )
        gen_run.append((sample, gen.final_findings))
        verify_run.append((sample, verified.final_findings))
        print(
            f"  [{i}/{len(pairs)}] {sample.id}: "
            f"{len(gen.final_findings)} generated, {len(verified.final_findings)} upheld",
            flush=True,
        )
    return gen_run, verify_run


def make_client(backend: str) -> StructuredClient:
    if backend == "claude-code":
        return ClaudeCodeClient()
    return LLMClient()


def summarize(run: ScoredRun) -> dict:
    """Aggregate metrics + calibration for one mode's run."""
    metrics = aggregate([score(s, f) for s, f in run])
    return mode_summary(metrics, calibration(run))


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the security-review benchmark.")
    ap.add_argument("--limit", type=int, default=None, help="Only run the first N samples.")
    ap.add_argument(
        "--backend",
        choices=["api", "claude-code"],
        default="api",
        help="api = Messages API (needs ANTHROPIC_API_KEY); "
        "claude-code = headless `claude -p` on the logged-in subscription.",
    )
    args = ap.parse_args()

    pairs = load_corpus(limit=args.limit)
    if not pairs:
        print("Corpus is empty. Add samples to benchmark/corpus/ and list them in manifest.yml.")
        return

    config = ReviewConfig()
    client = make_client(args.backend)
    print(f"Running {len(pairs)} sample(s) in both modes via {args.backend}...")
    gen_run, verify_run = run_both_modes(pairs, config, client)
    gen_only = summarize(gen_run)
    gen_verify = summarize(verify_run)

    report = build_report(
        tool_version=__version__,
        backend=args.backend,
        models={"generator": config.models.generator, "verifier": config.models.verifier},
        corpus={"samples": len(pairs), "sha256": corpus_sha256()},
        generator_only=gen_only,
        generator_plus_verifier=gen_verify,
        generated_at=datetime.now(UTC).isoformat(),
    )
    latest, versioned = write_report(RESULTS_DIR, report)

    print()
    print(render_markdown(report))
    print(f"Wrote {latest} and {versioned.name}")
    if isinstance(client, ClaudeCodeClient):
        print(
            f"Claude Code usage at API rates: ${client.total_cost_usd:.2f} "
            "(plan usage, not billed)"
        )


if __name__ == "__main__":
    main()
