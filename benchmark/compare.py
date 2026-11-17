"""Compare benchmark results across context strategies (M3).

Re-scores each run from its per-sample records, both over the whole corpus and
over only the samples that had context files — the samples where the strategies
actually differ, so the effect isn't diluted by diff-only samples.

Usage:
    python benchmark/compare.py results/<diff-run>.json results/<file-run>.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from metrics import Sample, aggregate, score  # sibling module
from run_benchmark import record_findings  # sibling module

_MODES = (("generator_only", "gen"), ("upheld", "gen+verify"))
_ROWS = ("precision", "recall", "f1", "false_positives_per_pr", "tp", "fp", "fn")


def _rescore(records: list[dict], key: str) -> dict:
    per_sample = []
    for r in records:
        sample = Sample(id=r["id"], is_vulnerable=r["is_vulnerable"], cwe=r["cwe"])
        per_sample.append(score(sample, record_findings(r, key)))
    return aggregate(per_sample).as_dict()


def compare(reports: list[dict]) -> str:
    # The subset is defined by the run that provided context, so diff-only runs
    # are scored on the same samples.
    context_ids = {r["id"] for rep in reports for r in rep["samples"] if r["context_provided"]}
    lines = []
    for title, keep in (
        ("All samples", lambda r: True),
        (f"Samples with context files ({len(context_ids)})", lambda r: r["id"] in context_ids),
    ):
        header = [f"{rep['context']} {label}" for rep in reports for _, label in _MODES]
        lines += [f"### {title}", "", "| Metric | " + " | ".join(header) + " |"]
        lines.append("|---" * (len(header) + 1) + "|")
        scored = [
            _rescore([r for r in rep["samples"] if keep(r)], key)
            for rep in reports
            for key, _ in _MODES
        ]
        for row in _ROWS:
            lines.append(f"| {row} | " + " | ".join(str(s[row]) for s in scored) + " |")
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description="Compare benchmark results side by side.")
    ap.add_argument("results", nargs="+", type=Path, help="Result JSON files to compare.")
    args = ap.parse_args()
    reports = [json.loads(p.read_text()) for p in args.results]
    if any(not rep.get("samples") for rep in reports):
        raise SystemExit("Every result file needs per-sample records (re-run the benchmark).")
    print(compare(reports))


if __name__ == "__main__":
    main()
