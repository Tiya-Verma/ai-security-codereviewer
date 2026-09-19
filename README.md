# AI-Powered Security Review

An AI security reviewer that gives Claude *semantic* understanding of a code
change — not just pattern matching. Its distinguishing bet is not "we use AI to
find bugs" (everyone does that now); it's a **generator/verifier detection
pipeline** measured against a **public, labeled benchmark** so there is a
reproducible number for how often it is right.

> **Status:** early scaffold (v0.1.0). The engine and benchmark harness are
> stubbed and importable; prompts and corpus are being built out. See
> [`CLAUDE.md`](./CLAUDE.md) for the full plan, milestones, and decisions.

## The core idea

```
diff → generate (high-recall candidates) → verify (adversarial re-check) → route by confidence
```

The **generator** favors recall and is allowed to over-report. The **verifier**
does the opposite: it assumes each finding is a false positive and tries to
prove the code is safe. The benchmark publishes generator-only vs.
generator+verifier numbers side by side — that delta is the proof the
architecture works.

## Layout

```
src/secreview/        # the detection engine + CLI
  ├─ models.py        # Finding / Verdict / Severity / Confidence
  ├─ config.py        # .security-review.yml schema (pydantic)
  ├─ diff.py          # language-agnostic unified-diff parsing
  ├─ llm.py           # Anthropic client; structured output via tool_use only
  ├─ engine/          # generator.py, verifier.py, pipeline.py
  └─ cli.py           # `secreview scan <diff>`
benchmark/            # the core differentiator — see benchmark/README.md
  ├─ run_benchmark.py # gen-only vs gen+verify, side by side
  ├─ metrics.py       # precision / recall / F1 / FP-per-PR / "hit" definition
  └─ corpus/          # labeled samples + manifest
tests/                # LLM-free unit tests (config, diff, metrics)
```

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run the LLM-free tests (no API key needed)
pytest

# Scan a diff (needs an API key)
export ANTHROPIC_API_KEY=sk-ant-...
git diff main...HEAD > /tmp/pr.diff
secreview scan /tmp/pr.diff

# Run the benchmark
python benchmark/run_benchmark.py --limit 5
```

## Configuration

Drop a [`.security-review.yml`](./.security-review.yml) in your repo root:
custom scan instructions, false-positive guidance, ignore globs, severity
threshold, suppression markers, and model selection. All fields are optional.

## Decisions so far

- **Engine:** Python.
- **Structured output:** forced via `tool_use`, never free-text parsing.
- **Models:** generator = `claude-sonnet-5`, verifier = `claude-opus-4-8`
  (pay for quality where it matters). Configurable.
- **GitHub Action packaging:** deferred to milestone M5 — build order is
  benchmark-first, so the CLI + corpus come first. The Action will wrap this
  same engine.

## Scope & caveats (v1)

- **Not** a replacement for manual review or pentesting.
- **Not** hardened against prompt injection — restrict to trusted PRs; require
  approval for external contributors.
- **Not** an exploit generator — findings are educational / pattern-level.

## License

MIT — see [`LICENSE`](./LICENSE).
