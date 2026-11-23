"""Local CLI: `secreview scan <diff>` — the primary v1 entrypoint.

Per docs/ROADMAP.md build order, the CLI (generator pass, then generator+verifier)
comes well before the GitHub Action. The Action will eventually shell out to
this same engine so there is one code path.

`secreview replay` renders a saved benchmark run through the same formatter,
so demos and docs show real recorded output without a live (slow,
nondeterministic) model call.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .config import ReviewConfig
from .engine import review_diff
from .llm import LLMClient, dumps
from .models import Finding, ReviewResult, VerifiedFinding

console = Console()

_RATIONALE_MAX = 140
_MIN_REASON = 40


def short_rationale(text: str, limit: int = _RATIONALE_MAX) -> str:
    """First sentence of a verifier rationale, truncated to fit one table cell."""
    text = " ".join(text.split())
    ends = [m.start() for m in re.finditer(r"(?<=[.!?])\s", text)]
    first = text[: ends[0]] if ends else text
    # A bare opener ("The finding is a false positive.") says nothing; keep
    # going to the sentence that carries the actual reason.
    if len(first) < _MIN_REASON and len(ends) > 1:
        first = text[: ends[1]]
    elif len(first) < _MIN_REASON and ends:
        first = text
    if len(first) > limit:
        first = first[: limit - 1].rstrip() + "…"
    return first


def _loc(f: Finding) -> str:
    return f"{f.file}:{f.line}" if f.line else f.file


def _print_table(result: ReviewResult, show_rejected: bool = False) -> None:
    if result.final_findings:
        table = Table(title="Security findings")
        table.add_column("Severity")
        table.add_column("Conf")
        table.add_column("CWE")
        table.add_column("Location")
        table.add_column("Title")
        for f in result.final_findings:
            table.add_row(f.severity.value, f.confidence.value, f.cwe or "-", _loc(f), f.title)
        console.print(table)
    else:
        console.print("[green]No findings above the configured severity threshold.[/green]")

    if show_rejected and result.rejected_findings:
        rejected = Table(
            title=f"Rejected by verifier ({len(result.rejected_findings)})",
            style="dim",
            title_style="dim",
        )
        rejected.add_column("CWE", style="dim")
        rejected.add_column("Title", style="dim strike")
        rejected.add_column("Why it's safe", style="dim")
        for f in result.rejected_findings:
            rejected.add_row(f.cwe or "-", f.title, short_rationale(f.verdict.rationale))
        console.print(rejected)

    if result.suppressed_findings:
        console.print(
            f"[dim]{len(result.suppressed_findings)} finding(s) suppressed "
            f"(inline marker / baseline).[/dim]"
        )


def result_from_record(record: dict, verifier: bool = True) -> ReviewResult:
    """Rebuild a ReviewResult from one per-sample benchmark record.

    The record stores generator-only, upheld and rejected findings (each with a
    `hit` field added by the benchmark). With `verifier=False` the generator's
    output is shown as the final findings — the generator-only baseline.
    """

    def strip(f: dict) -> dict:
        return {k: v for k, v in f.items() if k != "hit"}

    generator = [Finding.model_validate(strip(f)) for f in record["generator_only"]]
    if not verifier:
        return ReviewResult(generator_findings=generator, final_findings=list(generator))
    return ReviewResult(
        generator_findings=generator,
        final_findings=[
            Finding.model_validate({k: v for k, v in strip(f).items() if k != "verdict"})
            for f in record["upheld"]
        ],
        rejected_findings=[VerifiedFinding.model_validate(strip(f)) for f in record["rejected"]],
    )


@click.group()
@click.version_option(__version__)
def main() -> None:
    """AI-powered security review (generator/verifier pipeline)."""


@main.command()
@click.argument("diff_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=None,
              help="Path to .security-review.yml (defaults to repo root).")
@click.option("--no-verifier", is_flag=True, help="Generator-only baseline mode.")
@click.option("--show-rejected", is_flag=True,
              help="Also list findings the verifier rejected, with its reason.")
@click.option("--json", "as_json", is_flag=True, help="Emit findings as JSON.")
def scan(
    diff_file: Path,
    config_path: Path | None,
    no_verifier: bool,
    show_rejected: bool,
    as_json: bool,
) -> None:
    """Scan a unified DIFF_FILE for security vulnerabilities."""
    config = ReviewConfig.load(config_path)
    if no_verifier:
        config.enable_verifier = False

    diff_text = diff_file.read_text()
    result = review_diff(diff_text, config=config, client=LLMClient())

    if as_json:
        console.print_json(dumps(result))
    else:
        _print_table(result, show_rejected=show_rejected)

    # Non-zero exit if anything was surfaced, so CI can gate on it.
    sys.exit(1 if result.final_findings else 0)


@main.command()
@click.argument("results_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("sample_id")
@click.option("--no-verifier", is_flag=True, help="Show the generator-only output.")
@click.option("--show-rejected", is_flag=True,
              help="Also list findings the verifier rejected, with its reason.")
def replay(results_file: Path, sample_id: str, no_verifier: bool, show_rejected: bool) -> None:
    """Render a saved benchmark run for SAMPLE_ID from RESULTS_FILE.

    Output is exactly what was recorded in that run (same formatter as
    `scan`), so it is reproducible and needs no API key.
    """
    data = json.loads(results_file.read_text())
    records = {r["id"]: r for r in data.get("samples", [])}
    if sample_id not in records:
        known = ", ".join(sorted(records)) or "(none)"
        raise click.BadParameter(f"unknown sample {sample_id!r}; known: {known}",
                                 param_hint="SAMPLE_ID")
    result = result_from_record(records[sample_id], verifier=not no_verifier)
    _print_table(result, show_rejected=show_rejected and not no_verifier)


if __name__ == "__main__":  # pragma: no cover
    main()
