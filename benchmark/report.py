"""Build, render, and persist benchmark results.

The results record is the project's core published artifact, so it is versioned:
tagged with the tool version, the generator/verifier model ids, and a corpus
hash so any number can be traced back to exactly what produced it (CLAUDE.md
"Keeping it honest"). `render_markdown` produces the gen-only vs. gen+verify
table that drops straight into the README.

Everything here is pure/offline and unit-tested without an API key; the runner
supplies the live metrics.
"""

from __future__ import annotations

import json
from pathlib import Path

from metrics import Metrics  # sibling module

# Row order for the comparison table.
_METRIC_ROWS = [
    ("precision", "Precision"),
    ("recall", "Recall"),
    ("f1", "F1"),
    ("false_positives_per_pr", "False positives / PR"),
    ("tp", "True positives"),
    ("fp", "False positives"),
    ("fn", "False negatives"),
]


def mode_summary(metrics: Metrics, calibration: dict[str, dict[str, float | int]]) -> dict:
    """One pipeline mode's numbers: aggregate metrics + per-bucket calibration."""
    return {"metrics": metrics.as_dict(), "calibration": calibration}


def build_report(
    *,
    tool_version: str,
    models: dict[str, str],
    corpus: dict[str, object],
    generator_only: dict,
    generator_plus_verifier: dict,
    generated_at: str,
) -> dict:
    """Assemble the versioned results record. `generated_at` is passed in (not
    stamped here) so the report is deterministic and testable."""
    return {
        "tool_version": tool_version,
        "generated_at": generated_at,
        "models": models,
        "corpus": corpus,
        "modes": {
            "generator_only": generator_only,
            "generator_plus_verifier": generator_plus_verifier,
        },
    }


def _fmt(v: object) -> str:
    return str(v)


def render_markdown(report: dict) -> str:
    """Render the report as the README results section."""
    models = report["models"]
    corpus = report["corpus"]
    provenance = (
        f"_Tool `secreview` v{report['tool_version']} · "
        f"generator `{models.get('generator', '?')}` · "
        f"verifier `{models.get('verifier', '?')}` · "
        f"corpus {corpus.get('samples', '?')} samples "
        f"(sha `{str(corpus.get('sha256', '?'))[:8]}`) · "
        f"generated {report['generated_at']}_"
    )

    g = report["modes"]["generator_only"]["metrics"]
    v = report["modes"]["generator_plus_verifier"]["metrics"]

    lines = ["## Results", "", provenance, ""]
    lines.append("| Metric | Generator only | Generator + Verifier |")
    lines.append("|---|---|---|")
    for key, label in _METRIC_ROWS:
        lines.append(f"| {label} | {_fmt(g[key])} | {_fmt(v[key])} |")

    # Calibration for the full pipeline — the check that confidence is meaningful.
    lines += ["", "### Confidence calibration (generator + verifier)", ""]
    lines.append("| Confidence | Findings | Precision |")
    lines.append("|---|---|---|")
    calib = report["modes"]["generator_plus_verifier"]["calibration"]
    for bucket in ("high", "medium", "low"):
        b = calib.get(bucket, {"findings": 0, "precision": 0.0})
        lines.append(f"| {bucket} | {b['findings']} | {b['precision']} |")

    return "\n".join(lines) + "\n"


def write_report(results_dir: str | Path, report: dict) -> tuple[Path, Path]:
    """Write the report to results/latest.json and a version-stamped file.
    Returns (latest_path, versioned_path)."""
    d = Path(results_dir)
    d.mkdir(parents=True, exist_ok=True)

    # Version-stamp: tool version + date portion of the (ISO) timestamp.
    date_part = str(report["generated_at"])[:10]
    versioned = d / f"results-v{report['tool_version']}-{date_part}.json"
    latest = d / "latest.json"

    payload = json.dumps(report, indent=2, sort_keys=True)
    latest.write_text(payload)
    versioned.write_text(payload)
    return latest, versioned
