"""Standalone benchmark runner — the reproducible-number engine.

Others can re-run this against their own fork or a new model version (CLAUDE.md:
"Benchmark runner as a standalone script/CI job others can re-run"). It reads
the labeled corpus manifest, runs each sample through the pipeline in both
generator-only and generator+verifier modes, and prints the side-by-side
precision/recall/F1 table that is the project's core proof.

Usage:
    python benchmark/run_benchmark.py                 # full corpus, both modes
    python benchmark/run_benchmark.py --limit 5       # smoke test
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
from secreview.llm import LLMClient
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


def run_mode(
    pairs: list[tuple[Sample, str]], config: ReviewConfig, *, enable_verifier: bool
) -> ScoredRun:
    """Run one pipeline mode, keeping per-sample findings (needed for calibration)."""
    client = LLMClient()
    config = config.model_copy(update={"enable_verifier": enable_verifier})
    out: ScoredRun = []
    for sample, diff_text in pairs:
        result = review_diff(diff_text, config=config, client=client)
        out.append((sample, result.final_findings))
    return out


def summarize(run: ScoredRun) -> dict:
    """Aggregate metrics + calibration for one mode's run."""
    metrics = aggregate([score(s, f) for s, f in run])
    return mode_summary(metrics, calibration(run))


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the security-review benchmark.")
    ap.add_argument("--limit", type=int, default=None, help="Only run the first N samples.")
    args = ap.parse_args()

    pairs = load_corpus(limit=args.limit)
    if not pairs:
        print("Corpus is empty. Add samples to benchmark/corpus/ and list them in manifest.yml.")
        return

    config = ReviewConfig()
    print(f"Running {len(pairs)} sample(s) in both modes...")
    gen_only = summarize(run_mode(pairs, config, enable_verifier=False))
    gen_verify = summarize(run_mode(pairs, config, enable_verifier=True))

    report = build_report(
        tool_version=__version__,
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


if __name__ == "__main__":
    main()
