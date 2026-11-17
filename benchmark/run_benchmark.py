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
    python benchmark/run_benchmark.py --context file          # diff + full source files
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import yaml
from metrics import Sample, aggregate, calibration, is_hit, score  # noqa: E402  (sibling module)
from report import build_report, mode_summary, render_markdown, write_report  # noqa: E402

from secreview import __version__
from secreview.config import ReviewConfig
from secreview.engine import review_diff
from secreview.llm import ClaudeCodeClient, LLMClient, StructuredClient
from secreview.models import Finding, ReviewResult

CORPUS_DIR = Path(__file__).parent / "corpus"
MANIFEST = CORPUS_DIR / "manifest.yml"
RESULTS_DIR = Path(__file__).parent / "results"
ENGINE_DIR = Path(__file__).parent.parent / "src" / "secreview"

# Context strategies (M3). `diff` = the diff alone; `file` = the diff plus the
# full source file(s) it touches, at the same revision, from the sample's
# `context` entries. Samples without context files are run diff-only either way.
CONTEXT_STRATEGIES = ("diff", "file")

# One (Sample, findings) pair per corpus sample after running a pipeline mode.
ScoredRun = list[tuple[Sample, list[Finding]]]


def _context_text(entry: dict) -> str:
    """Concatenate a sample's context files, each under a path header."""
    parts = []
    for rel in entry.get("context", []):
        path = CORPUS_DIR / rel
        # Header with the path as it sits in the source repo, not the corpus.
        repo_path = Path(rel).relative_to(Path("context") / entry["id"])
        parts.append(f"--- {repo_path} (full file) ---\n{path.read_text()}")
    return "\n\n".join(parts)


def load_corpus(limit: int | None = None, context: str = "diff") -> list[tuple[Sample, str, str]]:
    """Return (Sample, diff_text, context_text) triples from the manifest.
    `context_text` is empty under the `diff` strategy."""
    entries = yaml.safe_load(MANIFEST.read_text()) or []
    out: list[tuple[Sample, str, str]] = []
    for e in entries[: limit or len(entries)]:
        diff_text = (CORPUS_DIR / e["diff"]).read_text()
        sample = Sample(
            id=e["id"],
            is_vulnerable=bool(e["is_vulnerable"]),
            cwe=e.get("cwe"),
        )
        out.append((sample, diff_text, _context_text(e) if context == "file" else ""))
    return out


def corpus_sha256() -> str:
    """Hash every corpus file (manifest, diffs, context) so results are
    traceable to the exact corpus, not just the index."""
    h = hashlib.sha256()
    for path in sorted(p for p in CORPUS_DIR.rglob("*") if p.is_file()):
        h.update(path.relative_to(CORPUS_DIR).as_posix().encode() + b"\0")
        h.update(path.read_bytes() + b"\0")
    return h.hexdigest()


def _finding_record(sample: Sample, f: Finding) -> dict:
    return {**f.model_dump(mode="json"), "hit": is_hit(sample, f)}


def sample_record(
    sample: Sample, has_context: bool, gen: ReviewResult, verified: ReviewResult
) -> dict:
    """Per-sample detail for error analysis: what the generator surfaced, and the
    verifier's verdict on each finding (upheld and rejected)."""
    return {
        "id": sample.id,
        "is_vulnerable": sample.is_vulnerable,
        "cwe": sample.cwe,
        "context_provided": has_context,
        "generator_only": [_finding_record(sample, f) for f in gen.final_findings],
        "upheld": [_finding_record(sample, f) for f in verified.final_findings],
        "rejected": [_finding_record(sample, f) for f in verified.rejected_findings],
    }


def record_findings(record: dict, key: str) -> list[Finding]:
    """Rebuild the findings stored under `key` in a per-sample record."""
    return [
        Finding.model_validate({k: v for k, v in f.items() if k not in ("hit", "verdict")})
        for f in record[key]
    ]


def checkpoint_path(context: str, backend: str, config: ReviewConfig) -> Path:
    """Where a run's finished samples are saved as they complete. Keyed by
    everything that changes the output — including the engine source, so a
    resume never mixes samples from before and after a pipeline change."""
    engine = hashlib.sha256()
    for path in sorted(ENGINE_DIR.rglob("*.py")):
        engine.update(path.read_bytes())
    key = json.dumps(
        [context, backend, config.models.model_dump(), corpus_sha256(), engine.hexdigest()],
        sort_keys=True,
    )
    digest = hashlib.sha256(key.encode()).hexdigest()[:12]
    return RESULTS_DIR / ".partial" / f"{context}-{backend}-{digest}.jsonl"


def _load_checkpoint(path: Path | None) -> dict[str, dict]:
    if path is None or not path.exists():
        return {}
    records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    return {r["id"]: r for r in records}


def run_corpus(
    corpus: list[tuple[Sample, str, str]],
    config: ReviewConfig,
    client: StructuredClient,
    checkpoint: Path | None = None,
) -> list[dict]:
    """Run each sample once through the generator, then verify that same output.
    Sharing one generator run per sample means the delta between modes is the
    verifier's effect, not run-to-run noise.

    Each finished sample is appended to `checkpoint`; samples already in it are
    skipped, so a stopped run resumes where it left off."""
    gen_config = config.model_copy(update={"enable_verifier": False})
    verify_config = config.model_copy(update={"enable_verifier": True})
    done = _load_checkpoint(checkpoint)
    if checkpoint is not None:
        checkpoint.parent.mkdir(parents=True, exist_ok=True)
    records: list[dict] = []
    for i, (sample, diff_text, context) in enumerate(corpus, 1):
        if sample.id in done:
            records.append(done[sample.id])
            print(f"  [{i}/{len(corpus)}] {sample.id}: resumed from checkpoint", flush=True)
            continue
        gen = review_diff(diff_text, config=gen_config, client=client, context=context)
        verified = review_diff(
            diff_text,
            config=verify_config,
            client=client,
            context=context,
            generator_findings=gen.generator_findings,
        )
        record = sample_record(sample, bool(context), gen, verified)
        if checkpoint is not None:
            with checkpoint.open("a") as fh:
                fh.write(json.dumps(record) + "\n")
        records.append(record)
        print(
            f"  [{i}/{len(corpus)}] {sample.id}: "
            f"{len(gen.final_findings)} generated, {len(verified.final_findings)} upheld",
            flush=True,
        )
    return records


def scored_runs(
    corpus: list[tuple[Sample, str, str]], records: list[dict]
) -> tuple[ScoredRun, ScoredRun]:
    """(generator-only, generator+verifier) findings per sample, from the records."""
    by_id = {r["id"]: r for r in records}
    gen_run = [(s, record_findings(by_id[s.id], "generator_only")) for s, _, _ in corpus]
    verify_run = [(s, record_findings(by_id[s.id], "upheld")) for s, _, _ in corpus]
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
    ap.add_argument(
        "--context",
        choices=CONTEXT_STRATEGIES,
        default="diff",
        help="diff = diff only; file = diff + full source files from each sample's "
        "`context` entries (samples without them stay diff-only).",
    )
    ap.add_argument(
        "--fresh",
        action="store_true",
        help="Ignore any checkpoint from an interrupted run and start over.",
    )
    args = ap.parse_args()

    corpus = load_corpus(limit=args.limit, context=args.context)
    if not corpus:
        print("Corpus is empty. Add samples to benchmark/corpus/ and list them in manifest.yml.")
        return

    config = ReviewConfig()
    client = make_client(args.backend)
    print(
        f"Running {len(corpus)} sample(s) in both modes via {args.backend}, "
        f"context={args.context}..."
    )
    checkpoint = checkpoint_path(args.context, args.backend, config)
    if args.fresh:
        checkpoint.unlink(missing_ok=True)
    records = run_corpus(corpus, config, client, checkpoint)
    gen_run, verify_run = scored_runs(corpus, records)
    gen_only = summarize(gen_run)
    gen_verify = summarize(verify_run)

    report = build_report(
        tool_version=__version__,
        backend=args.backend,
        context=args.context,
        models={"generator": config.models.generator, "verifier": config.models.verifier},
        corpus={"samples": len(corpus), "sha256": corpus_sha256()},
        generator_only=gen_only,
        generator_plus_verifier=gen_verify,
        generated_at=datetime.now(UTC).isoformat(),
        samples=records,
    )
    latest, versioned = write_report(RESULTS_DIR, report)
    # A --limit run is a subset; keep its checkpoint so the full run can reuse it.
    if args.limit is None:
        checkpoint.unlink(missing_ok=True)

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
