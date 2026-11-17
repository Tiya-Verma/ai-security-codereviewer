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

### Context strategies (M3)

`--context diff` (default) shows the model only the diff. `--context file` adds
the full source file(s) the change touches, at the same revision, from the
sample's `context` entries in the manifest — the pre-fix revision for a
positive, the fix revision for a negative, fetched verbatim from GitHub with
the tree URL recorded in `context_revision`. Only the real CVE samples have
context files; synthetic samples have no surrounding repo, so they run
diff-only under either strategy.

```bash
python benchmark/run_benchmark.py --backend claude-code --context file
python benchmark/compare.py results/<diff-run>.json results/<file-run>.json
```

`compare.py` re-scores runs from their per-sample records, over the whole
corpus and over only the samples that had context, where the strategies differ.

Every result file also stores per-sample detail: each finding the generator
surfaced, whether it matched the label, and the verifier's verdict on it —
including the reasoning for findings it rejected.

Runs are resumable: each finished sample is saved to
`results/.partial/<context>-<backend>-<key>.jsonl` (git-ignored), and re-running
the same command skips samples already there. The checkpoint is keyed by context
strategy, backend, models and corpus hash, so changing any of them starts a new
run. `--fresh` discards the checkpoint and starts over.

Each sample runs through the generator **once**; both columns are scored from
that same output (the verifier column re-checks it), so the delta between
modes is the verifier's effect rather than run-to-run generator noise.

The runner prints generator-only vs. generator+verifier metrics side by side —
the single most persuasive artifact in the project — and writes a
versioned record to `results/` (`latest.json` + `results-v<tool>-<date>.json`),
tagged with the tool version, model ids, and a corpus hash for traceability.

## Results

> Fixed pipeline, default `diff` context strategy, one pass over the 24-sample
> corpus. With n=24 and a single run, treat these as a baseline, not a precise
> estimate. Regenerate with `run_benchmark.py` (`report.render_markdown`).

_Tool `secreview` v0.1.0 · generator `claude-sonnet-5` · verifier `claude-opus-4-8` · backend `claude-code` · context `diff` · corpus 24 samples (sha `fba95703`) · generated 2026-11-17T12:17:06.500441+00:00_

| Metric | Generator only | Generator + Verifier |
|---|---|---|
| Precision | 0.3333 | 0.619 |
| Recall | 0.9333 | 0.8667 |
| F1 | 0.4912 | 0.7222 |
| False positives / PR | 1.1667 | 0.3333 |
| True positives | 14 | 13 |
| False positives | 28 | 8 |
| False negatives | 1 | 2 |

The generator-only column is the high-recall baseline; the delta to the
generator+verifier column is the proof the adversarial pass buys precision.

### Confidence calibration (generator + verifier)

Validates that confidence is meaningful, not decorative — `high` should be more
precise than `low`.

| Confidence | Findings | Precision |
|---|---|---|
| high | 15 | 0.8 |
| medium | 3 | 0.3333 |
| low | 3 | 0.0 |

### Context strategy: `diff` vs. `file` (M3)

Same fixed pipeline, run in parallel. Only the 10 CVE samples have context
files, so the second table isolates where the strategies differ.

#### All samples

| Metric | diff gen | diff gen+verify | file gen | file gen+verify |
|---|---|---|---|---|
| precision | 0.3333 | 0.619 | 0.359 | 0.5833 |
| recall | 0.9333 | 0.8667 | 0.9333 | 0.9333 |
| f1 | 0.4912 | 0.7222 | 0.5185 | 0.7179 |
| false_positives_per_pr | 1.1667 | 0.3333 | 1.0417 | 0.4167 |
| tp | 14 | 13 | 14 | 14 |
| fp | 28 | 8 | 25 | 10 |
| fn | 1 | 2 | 1 | 1 |

#### Samples with context files (10)

| Metric | diff gen | diff gen+verify | file gen | file gen+verify |
|---|---|---|---|---|
| precision | 0.1379 | 0.375 | 0.16 | 0.3636 |
| recall | 0.8 | 0.6 | 0.8 | 0.8 |
| f1 | 0.2353 | 0.4615 | 0.2667 | 0.5 |
| false_positives_per_pr | 2.5 | 0.5 | 2.1 | 0.7 |
| tp | 4 | 3 | 4 | 4 |
| fp | 25 | 5 | 21 | 7 |
| fn | 1 | 2 | 1 | 1 |

**Reading:** no clear winner at this sample size. Overall F1 is the same
(0.72 vs. 0.72). On the CVE samples, `file` recovered one extra true positive
(ansi-regex: with only the diff, the verifier mistook the vulnerable regex for
the patched one) but upheld two more false positives, and it cost about twice
as much ($7.77 vs. $3.97 at API rates). Every difference is one or two samples,
within single-run noise, so `diff` stays the default until a larger CVE corpus
(M4) and repeated runs can separate them.

### Known issue: verifier was blind before 2026-11-17

Earlier versions passed the verifier only the generator's description of a
finding, not the code. The 2026-11-16 run (`results-v0.1.0-2026-11-16.json`)
was produced that way; its numbers happened to look similar, but a second run
of the same pipeline scored F1 0.56, so those numbers are not reliable. All results above come from the fixed pipeline.

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
