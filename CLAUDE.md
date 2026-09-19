# AI-Powered Security Review GitHub Action

## Project Overview

An AI-powered security review GitHub Action that uses Claude to analyze pull
request code changes for security vulnerabilities. Goes beyond pattern-matching
SAST tools by giving Claude semantic understanding of code and, where useful,
tool access to the surrounding repo — not just the raw diff.

**Note:** Anthropic already ships `anthropics/claude-code-security-review` and
a newer `Claude Code Security` (multi-stage verification, confidence scoring,
dashboard). This project should either (a) be a from-scratch learning build,
or (b) differentiate on a specific gap — pick one before writing code. See
"Differentiation Angle" below.

**Differentiation Angle (decided):** A generator/verifier detection pipeline
with a **public, labeled false-positive/false-negative benchmark**. The core
claim of this project is not "we use AI to find bugs" (everyone does that
now) — it's "here is a reproducible number for how often we're right, and
here is the two-pass architecture that gets us there." Ticketing-system
auto-filing was considered and deliberately deferred to a post-v1 roadmap
item — it doesn't improve detection quality, and it's more valuable once
findings are already trustworthy.

---

## Core Features (table stakes)

- [ ] Triggers on `pull_request` (opened, synchronize)
- [ ] Diff-aware scanning — only analyzes changed files by default
- [ ] Language-agnostic analysis (LLM reasoning is language-agnostic; verify
      surrounding tooling — diff parsing, line mapping — isn't secretly
      text/language-specific)
- [ ] Inline PR comments on specific lines
- [ ] One summary comment per PR (counts, severities, links to inline comments)
- [ ] Severity levels: critical / high / medium / low / info
- [ ] Config file in-repo (`.security-review.yml`) for:
  - [ ] custom scan instructions
  - [ ] false-positive-filtering instructions
  - [ ] ignore paths / ignore globs
  - [ ] severity threshold for posting comments
- [ ] Suppression mechanism:
  - [ ] inline suppress comment (e.g. `// security-review: ignore`)
  - [ ] baseline/allowlist file for accepted, recurring risks
- [ ] False positive filtering as its own explicit stage (not just a prompt
      instruction bolted onto the generation pass)

## Primary Differentiator: Generator/Verifier Pipeline + Public Benchmark

This is the project's main bet. Everything else is secondary.

- [ ] Two-pass detection: generator proposes findings, verifier adversarially
      re-checks each one before it's surfaced
- [ ] Confidence score per finding, calibrated against benchmark performance
      (not just a vibes-based 1-10 from the model)
- [ ] Public labeled benchmark corpus (see "Benchmark Design" below)
- [ ] Published, reproducible metrics: precision, recall, F1, false-positive
      rate — versioned alongside the tool so claims don't go stale
- [ ] Benchmark runner as a standalone script/CI job others can re-run against
      their own fork or a new model version
- [ ] Write-up/README section showing before/after numbers for the
      generator-only vs. generator+verifier pipeline — this is the actual proof
      the architecture works, not just an assertion

## Secondary / v2 Roadmap (deferred — don't build before v1 is solid)

- [ ] Ticketing integration (Jira/Linear) for findings above a severity threshold
      — revisit once precision is high enough that auto-filing isn't noisy
- [ ] SARIF output → GitHub Code Scanning tab integration
- [ ] Auto-fix suggestions using GitHub's suggested-change diff format
- [ ] Historical trend tracking — vulnerability density over time per repo/team
- [ ] Org-wide shared policy config (central repo other repos inherit rules from)
- [ ] Shared core library: CLI (local pre-commit use) + Action use the same engine
- [ ] Self-hosted / Bedrock / Vertex model routing for compliance-sensitive orgs
- [ ] Narrow vulnerability-class specialization instead of general coverage
- [ ] Feedback loop: log human accept/dismiss per finding, feed dismissals back
      into filtering prompt periodically (this pairs naturally with the
      benchmark — dismissed findings are candidate new benchmark negatives)

## Explicit Non-Goals (write these down so scope doesn't creep)

- [ ] Not a replacement for manual review / pentesting — state this in the README
- [ ] Not hardened against prompt injection in v1 — restrict to trusted PRs
      only (document the same caveat the upstream project uses)
- [ ] Not generating working exploits — findings should be educational/pattern-level

---

## Known Failure Modes to Design Around

(from real-world testing of Anthropic's own similar tool — design your
pipeline explicitly against these)

1. **False positives on intentional design patterns** — flags something as
   risky when it's actually a deliberate, safe pattern in the codebase.
   → Mitigation: adversarial verifier pass + project-convention context file.
2. **Missed business-logic vulnerabilities** — flaws that require understanding
   an entire subsystem (e.g. full auth flow), not just the diff.
   → Mitigation: give Claude tool access to explore beyond the diff; don't
   rely on diff-only context for high-stakes areas (auth, payments, access control).
3. **Overconfidence from incomplete context** — LLM states findings with
   unwarranted certainty when it hasn't seen the whole picture.
   → Mitigation: confidence scoring, and explicitly prompt for "what context
   would change this assessment."
4. **Noise reduces trust** — too many low-value comments and developers start
   ignoring the bot entirely.
   → Mitigation: route by confidence — high-confidence findings inline,
   low-confidence findings collapsed into a summary only.

---

## Benchmark Design

The benchmark is a first-class deliverable, not an afterthought bolted on at
the end. Build the corpus early — it doubles as your prompt-iteration test
harness during development.

### Corpus sourcing (mix multiple sources — don't rely on one)

- [ ] **OWASP Benchmark project** — pre-labeled Java test cases with known
      true/false vulnerability status; fast way to get a baseline number
- [ ] **Real CVE-fix commit pairs** — pull `vulnerable_commit` /
      `fixed_commit` pairs from public CVE databases (e.g. GitHub Security
      Advisories, OSV.dev) across a few languages. The diff between the two
      is a labeled positive; the fixed version re-scanned is a labeled
      negative for that same vulnerability.
- [ ] **Synthetic injected vulnerabilities** — take clean, real-world PRs
      from popular OSS repos and deliberately (re-)introduce a known
      vulnerability class (SQLi, XSS, broken auth check, etc.) to create a
      matched vulnerable/safe pair from the *same* codebase context — this
      controls for "the model just knows this repo is famous for bugs"
- [ ] **Deliberate false-positive traps** — intentionally safe code that
      *looks* risky (parameterized queries that resemble string concatenation,
      intentional design patterns a naive scanner would flag) — this is where
      the "flagged intentional design patterns as risks" failure mode gets
      caught before it ships
- [ ] Target size for v1: **100–300 labeled samples**, balanced across
      vulnerability classes and covering at least 2–3 languages. Small and
      real beats large and synthetic-only.

### Labeling methodology

- [ ] Each sample gets: file/diff, ground-truth label (vuln / not-vuln),
      vulnerability class (CWE ID where applicable), and severity
- [ ] Define what counts as a "hit" up front: exact line match? Same
      vulnerability class flagged anywhere in the diff? Decide before you
      run the first eval, not after seeing results (avoids moving goalposts)
- [ ] Get a second pass of human review on labels for anything borderline —
      a benchmark with sloppy ground truth undermines the whole pitch

### Metrics to publish

- [ ] **Precision** — of flagged findings, what fraction are real
- [ ] **Recall** — of real vulnerabilities in the corpus, what fraction are caught
- [ ] **F1** — combined score
- [ ] **False positives per PR** (a more intuitive number for developers than
      raw precision)
- [ ] **Confidence calibration** — do "high confidence" findings actually
      have higher precision than "low confidence" ones? (This validates that
      confidence scoring is meaningful, not decorative.)
- [ ] Report generator-only vs. generator+verifier numbers side by side —
      this is the single most persuasive artifact in the whole project

### Keeping it honest

- [ ] Version the benchmark alongside the tool (tag results with tool
      version + model version used)
- [ ] Re-run on model updates — LLM behavior drifts between model versions,
      published numbers go stale
- [ ] Publish the corpus (or a reproducible script to regenerate it) so
      others can verify, not just the summary numbers

---

## Pipeline Architecture

```
PR opened/updated
      │
      ▼
Checkout PR diff (fetch-depth for base+head comparison)
      │
      ▼
Diff extraction & filtering (changed files, language detection)
      │
      ▼
Context expansion (repo tool access: read call sites, definitions,
surrounding functions — not diff-only)
      │
      ▼
Generator pass (Claude proposes candidate findings)
      │
      ▼
Verifier pass (adversarial self-check per finding: "assume this is a false
positive, try to prove it's actually safe")
      │
      ▼
Confidence + severity scoring
      │
      ▼
Suppression / baseline filter (config-driven)
      │
      ▼
Route by confidence:
   high  → inline PR comment + suggested fix diff
   low   → collapsed summary comment
      │
      ▼
Feedback log (human accept/dismiss) → periodic prompt tuning
```

**Build order (benchmark-first, since it's the core differentiator):**
1. [ ] Assemble a small starter corpus (20–30 samples) from OWASP Benchmark +
       a few real CVE-fix pairs. This becomes your test harness immediately.
2. [ ] Local CLI, generator pass only — diff in, findings out. Run against
       the starter corpus, record baseline precision/recall.
3. [ ] Add the verifier pass. Re-run against the same corpus, compare numbers
       against step 2. This before/after comparison is your core pitch.
4. [ ] Nail context strategy: diff-only vs. diff+surrounding function vs.
       full tool access — decide per vulnerability class if needed, re-test
       against corpus after each change.
5. [ ] Grow the corpus to 100–300 samples, add synthetic + false-positive-trap
       samples, get labels double-checked.
6. [ ] Wrap CLI in composite/Docker Action; wire up checkout + diff extraction.
7. [ ] PR comment posting — map findings back to correct diff line positions
       (fiddly with GitHub's line-position API — budget real time for this).
8. [ ] Config + suppression system.
9. [ ] Publish benchmark corpus + methodology + results publicly (repo + README table).
10. [ ] v2 roadmap items (ticketing, SARIF, etc.) as time allows.

---

## Tech Stack

| Layer | Choice | Notes |
|---|---|---|
| Action runtime | _TBD: composite vs Docker container action_ | Docker = more control over environment |
| Engine language | _TBD: TypeScript/Node vs Python_ | Node pairs well with `@actions/*` SDKs; Python nice for AST/repo tooling |
| Claude integration | _TBD: Claude Agent SDK vs plain Messages API_ | Agent SDK gives tool-using analysis out of the box |
| Diff parsing | `unidiff` / `parse-diff` or GitHub compare API | |
| Structured output | Force JSON schema via tool_use, not free text parsing | |
| PR commenting | `@actions/github` (Node) or PyGithub (Python) | GraphQL for inline comment positioning |
| Config | YAML in repo, schema-validated (zod / pydantic) | |
| SARIF (if built) | SARIF 2.1.0 JSON, hand-rolled or `@microsoft/sarif` types | |
| Testing | Corpus of known-vulnerable sample PRs | Regression-test detection quality over time |

---

## Guardrails Checklist

- [ ] Read-only repo access for the analysis tool calls (no arbitrary bash execution)
- [ ] Document prompt-injection risk clearly in README; recommend "require
      approval for external contributors" repo setting
- [ ] Rate limit / cost cap per PR (large diffs = large token spend)
- [ ] Timeout handling for large/slow analyses
- [ ] Never auto-apply fixes — suggestions only, human approves

---

## Open Questions / Decisions Needed Before Coding

- [x] Differentiation angle finalized — generator/verifier pipeline + public benchmark
- [ ] Node or Python for the engine?
- [ ] Composite or Docker action?
- [ ] Diff-only, diff+context, or full tool access — per vulnerability class or uniform?
- [ ] Which model(s) to support (Anthropic API only, or Bedrock/Vertex too)?
- [ ] What's the "hit" definition for benchmark scoring (exact line vs. class-level match)?
- [ ] How many languages does v1's corpus need to cover to be credible?

---

## Milestones

- [ ] **M0:** Repo scaffolded, decisions above resolved, starter corpus (20–30 samples) assembled
- [ ] **M1:** Generator-only CLI produces findings on the corpus; baseline
      precision/recall recorded
- [ ] **M2:** Verifier pass added; before/after comparison against M1 recorded
- [ ] **M3:** Context strategy tuned (diff-only vs. expanded context), re-benchmarked
- [ ] **M4:** Corpus grown to 100–300 samples, labels double-checked
- [ ] **M5:** Wrapped as GitHub Action, posts inline PR comments on a test repo
- [ ] **M6:** Config + suppression system working
- [ ] **M7:** Benchmark corpus, methodology, and results published publicly
- [ ] **M8:** README, security caveats documented, ready to share/open source
- [ ] **M9:** First v2 roadmap item (likely ticketing integration) if time allows
