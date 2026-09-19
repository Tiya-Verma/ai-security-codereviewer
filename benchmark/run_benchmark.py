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
from pathlib import Path

import yaml
from metrics import Metrics, Sample, aggregate, score  # noqa: E402  (sibling module)

from secreview.config import ReviewConfig
from secreview.engine import review_diff
from secreview.llm import LLMClient

CORPUS_DIR = Path(__file__).parent / "corpus"
MANIFEST = CORPUS_DIR / "manifest.yml"


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


def run_mode(pairs: list[tuple[Sample, str]], *, enable_verifier: bool) -> Metrics:
    client = LLMClient()
    config = ReviewConfig()
    config.enable_verifier = enable_verifier
    per_sample = []
    for sample, diff_text in pairs:
        result = review_diff(diff_text, config=config, client=client)
        per_sample.append(score(sample, result.final_findings))
    return aggregate(per_sample)


def _print_comparison(gen_only: Metrics, gen_verify: Metrics) -> None:
    g, v = gen_only.as_dict(), gen_verify.as_dict()
    keys = ["precision", "recall", "f1", "false_positives_per_pr", "tp", "fp", "fn"]
    width = max(len(k) for k in keys)
    print(f"\n{'metric'.ljust(width)}   gen-only   gen+verify")
    print("-" * (width + 24))
    for k in keys:
        print(f"{k.ljust(width)}   {str(g[k]).ljust(8)}   {v[k]}")
    print(f"\nsamples: {gen_verify.samples}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the security-review benchmark.")
    ap.add_argument("--limit", type=int, default=None, help="Only run the first N samples.")
    args = ap.parse_args()

    pairs = load_corpus(limit=args.limit)
    if not pairs:
        print("Corpus is empty. Add samples to benchmark/corpus/ and list them in manifest.yml.")
        return

    print(f"Running {len(pairs)} sample(s) in both modes...")
    gen_only = run_mode(pairs, enable_verifier=False)
    gen_verify = run_mode(pairs, enable_verifier=True)
    _print_comparison(gen_only, gen_verify)


if __name__ == "__main__":
    main()
