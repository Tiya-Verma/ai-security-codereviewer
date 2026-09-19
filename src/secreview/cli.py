"""Local CLI: `secreview scan <diff>` — the primary v1 entrypoint.

Per CLAUDE.md build order, the CLI (generator pass, then generator+verifier)
comes well before the GitHub Action. The Action will eventually shell out to
this same engine so there is one code path.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .config import ReviewConfig
from .engine import review_diff
from .llm import LLMClient, dumps
from .models import ReviewResult

console = Console()


def _print_table(result: ReviewResult) -> None:
    if not result.final_findings:
        console.print("[green]No findings above the configured severity threshold.[/green]")
        return
    table = Table(title="Security findings")
    table.add_column("Severity")
    table.add_column("Conf")
    table.add_column("CWE")
    table.add_column("Location")
    table.add_column("Title")
    for f in result.final_findings:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        table.add_row(f.severity.value, f.confidence.value, f.cwe or "-", loc, f.title)
    console.print(table)


@click.group()
@click.version_option(__version__)
def main() -> None:
    """AI-powered security review (generator/verifier pipeline)."""


@main.command()
@click.argument("diff_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=None,
              help="Path to .security-review.yml (defaults to repo root).")
@click.option("--no-verifier", is_flag=True, help="Generator-only baseline mode.")
@click.option("--json", "as_json", is_flag=True, help="Emit findings as JSON.")
def scan(diff_file: Path, config_path: Path | None, no_verifier: bool, as_json: bool) -> None:
    """Scan a unified DIFF_FILE for security vulnerabilities."""
    config = ReviewConfig.load(config_path)
    if no_verifier:
        config.enable_verifier = False

    diff_text = diff_file.read_text()
    result = review_diff(diff_text, config=config, client=LLMClient())

    if as_json:
        console.print_json(dumps(result))
    else:
        _print_table(result)

    # Non-zero exit if anything was surfaced, so CI can gate on it.
    sys.exit(1 if result.final_findings else 0)


if __name__ == "__main__":  # pragma: no cover
    main()
