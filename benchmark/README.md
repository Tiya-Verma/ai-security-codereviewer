# Benchmark

The benchmark is a **first-class deliverable**, not an afterthought. It is both
the proof that the generator/verifier architecture works and the prompt-iteration
test harness used during development.

## Layout

```
benchmark/
├── run_benchmark.py     # standalone runner: gen-only vs gen+verify, side by side
├── metrics.py           # precision / recall / F1 / FP-per-PR / calibration; "hit" definition
├── corpus/
│   ├── manifest.yml     # labeled sample index (id, label, cwe, source, language)
│   └── samples/         # unified diffs, one per sample
└── results/             # published, versioned result JSON (tagged w/ tool+model version)
```

## Running

```bash
pip install -e ".[dev]"
export ANTHROPIC_API_KEY=sk-...
python benchmark/run_benchmark.py --limit 5   # smoke test
python benchmark/run_benchmark.py             # full corpus
```

The runner prints generator-only vs. generator+verifier metrics side by side —
the single most persuasive artifact in the project (CLAUDE.md M2).

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

## "Hit" definition

Class-level by default: a finding is a true positive if it flags the sample's
labeled CWE. Defined in one place (`metrics.py:is_hit`) so it's auditable and
swappable. **Decide the definition before running the first real eval** to avoid
moving goalposts.

## Keeping it honest

- Version results alongside the tool (tag with tool + model version).
- Re-run on model updates — LLM behavior drifts.
- Publish the corpus (or a reproducible regeneration script), not just summary numbers.
