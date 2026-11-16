# Benchmark

The benchmark is a **first-class deliverable**, not an afterthought. It is both
the proof that the generator/verifier architecture works and the prompt-iteration
test harness used during development.

## Layout

```
benchmark/
├── run_benchmark.py     # standalone runner: gen-only vs gen+verify, side by side
├── metrics.py           # precision / recall / F1 / FP-per-PR / calibration; "hit" definition
├── report.py            # builds + renders + persists the versioned results record
├── corpus/
│   ├── manifest.yml     # labeled sample index (id, label, cwe, source, language)
│   └── samples/         # unified diffs, one per sample
└── results/             # published, versioned result JSON (latest.json + results-v<tool>-<date>.json)
```

## Running

```bash
pip install -e ".[dev]"
export ANTHROPIC_API_KEY=sk-...
python benchmark/run_benchmark.py --limit 5   # smoke test
python benchmark/run_benchmark.py             # full corpus
```

No API key? `--backend claude-code` runs every call through headless Claude
Code (`claude -p`) on whatever subscription it is logged in with. It strips
tools, MCP servers, skills and settings from each call so the model sees only
the pipeline's prompt, and removes `ANTHROPIC_API_KEY` from the subprocess
environment so the run can't silently bill an API account. Results record
which backend produced them.

```bash
python benchmark/run_benchmark.py --backend claude-code
```

Each sample runs through the generator **once**; both columns are scored from
that same output (the verifier column re-checks it), so the delta between
modes is the verifier's effect rather than run-to-run generator noise.

The runner prints generator-only vs. generator+verifier metrics side by side —
the single most persuasive artifact in the project — and writes a
versioned record to `results/` (`latest.json` + `results-v<tool>-<date>.json`),
tagged with the tool version, model ids, and a corpus hash for traceability.

## Results

> First measured run: one pass over the 24-sample corpus. With n=24 and a single
> run, treat these as a baseline, not a precise estimate — re-run before quoting
> small deltas. Regenerate with `run_benchmark.py` (`report.render_markdown`).

_Tool `secreview` v0.1.0 · generator `claude-sonnet-5` · verifier `claude-opus-4-8` · backend `claude-code` · corpus 24 samples (sha `c02803b4`) · generated 2026-11-16T05:21:09.946523+00:00_

| Metric | Generator only | Generator + Verifier |
|---|---|---|
| Precision | 0.4054 | 0.6087 |
| Recall | 1.0 | 0.9333 |
| F1 | 0.5769 | 0.7368 |
| False positives / PR | 0.9167 | 0.375 |
| True positives | 15 | 14 |
| False positives | 22 | 9 |
| False negatives | 0 | 1 |

The generator-only column is the high-recall baseline; the delta to the
generator+verifier column is the proof the adversarial pass buys precision.

### Confidence calibration (generator + verifier)

Validates that confidence is meaningful, not decorative — `high` should be more
precise than `low`.

| Confidence | Findings | Precision |
|---|---|---|
| high | 9 | 1.0 |
| medium | 7 | 0.7143 |
| low | 7 | 0.0 |

## Corpus sourcing (mix sources; don't rely on one)

- **OWASP Benchmark** — pre-labeled Java cases for a fast baseline.
- **Real CVE-fix commit pairs** — `vulnerable_commit`/`fixed_commit` diffs from
  GitHub Security Advisories / OSV.dev. The diff is a labeled positive; the fixed
  version re-scanned is a labeled negative.
- **Synthetic injected vulns** — reintroduce a known class into a clean real PR to
  get a matched vulnerable/safe pair from the *same* codebase context.
- **Deliberate false-positive traps** — safe code that *looks* risky (e.g. the
  parameterized query in `samples/sqli_fp_trap.diff`).

Target for v1: **100–300 labeled samples**, balanced across classes, ≥2–3 languages.

### Current state (starter corpus)

24 samples across Python, JavaScript and Go: 14 synthetic samples (matched
positive / fp-trap pairs, including 4 false-positive traps) and 10 real CVE-fix
samples (5 matched pairs; the pre-fix code is the positive, the fixed code the
negative). Integrity is enforced by `tests/test_corpus.py` (ids unique, every
diff parses, no orphans, labels consistent, CVE provenance present). Still
**TODO**: OWASP Benchmark cases.

## "Hit" definition

Class-level by default: a finding is a true positive if it flags the sample's
labeled CWE. Defined in one place (`metrics.py:is_hit`) so it's auditable and
swappable. **Decide the definition before running the first real eval** to avoid
moving goalposts.

## Keeping it honest

- Version results alongside the tool (tag with tool + model version).
- Re-run on model updates — LLM behavior drifts.
- Publish the corpus (or a reproducible regeneration script), not just summary numbers.
