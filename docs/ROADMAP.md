# Roadmap

## Positioning

Anthropic already ships [`anthropics/claude-code-security-review`](https://github.com/anthropics/claude-code-security-review)
and Claude Code Security. This project's claim is not "we use AI to find bugs" —
it's **a generator/verifier detection pipeline measured against a public,
labeled false-positive/false-negative benchmark**: a reproducible number for how
often the tool is right, and the two-pass architecture that gets it there.

Ticketing-system auto-filing was considered and deliberately deferred to v2: it
doesn't improve detection quality, and it's more valuable once findings are
already trustworthy.

## Pipeline

```
PR opened/updated
  → checkout PR diff (base + head)
  → diff extraction & filtering (changed files, ignore globs)
  → context expansion (call sites, definitions, surrounding functions)
  → generator pass   (high-recall candidate findings)
  → verifier pass    (adversarial: "assume this is a false positive, prove it's safe")
  → confidence + severity scoring
  → suppression / baseline filter (config-driven)
  → route by confidence: high → inline PR comment, low → collapsed summary
  → feedback log (human accept/dismiss) → periodic prompt tuning
```

## Milestones

| | Milestone | Status |
|---|---|---|
| M0 | Scaffold, starter corpus (20–30 samples) | ✅ 24 samples, Python/JS/Go; OWASP cases TODO |
| M1 | Generator-only baseline recorded | ✅ see [results](../benchmark/README.md#results) |
| M2 | Verifier pass, before/after comparison | ✅ re-run after giving the verifier the diff |
| M3 | Context strategy tuned (diff-only vs. expanded), re-benchmarked | 🟡 `diff` vs. `file` compared, no clear winner at n=10; revisit after M4 |
| M4 | Corpus grown to 100–300 samples, labels double-checked | ⬜ |
| M5 | Packaged as a GitHub Action, posting inline comments on a test repo | 🟡 line mapping + routing done; `action.yml` TODO |
| M6 | Config + suppression system | ✅ inline marker + baseline allowlist |
| M7 | Corpus, methodology and results published | ⬜ |
| M8 | README and security caveats ready to open source | ⬜ |
| M9 | First v2 item (likely ticketing) | ⬜ |

## Decisions

- **Engine:** Python.
- **Structured output:** forced through tool use / JSON schema, never free-text parsing.
- **Models:** generator `claude-sonnet-5`, verifier `claude-opus-4-8`; configurable.
- **Backends:** Messages API, or headless Claude Code (`--backend claude-code`).
- **Benchmark hit definition:** class-level — a finding is a true positive if it
  flags the sample's labeled CWE anywhere in the diff (`benchmark/metrics.py`).
- **Open:** composite vs. Docker Action; diff-only vs. expanded context per
  vulnerability class; Bedrock/Vertex support.

## Known failure modes to design around

1. **False positives on intentional design patterns.** Mitigation: adversarial
   verifier + project-convention guidance (`false_positive_instructions`).
2. **Missed business-logic vulnerabilities** that need a whole subsystem in view
   (auth flows, payments, access control). Mitigation: context expansion beyond
   the diff for high-stakes areas.
3. **Overconfidence from incomplete context.** Mitigation: confidence scoring,
   and the verifier reports what context would change its assessment.
4. **Noise erodes trust.** Mitigation: only high-confidence findings go inline;
   the rest are collapsed into the summary comment.

## Benchmark design

**Corpus sources** (mixed on purpose): OWASP Benchmark cases; real CVE-fix
commit pairs (pre-fix = positive, fixed = negative for the same class);
synthetic vulnerabilities injected into clean real-world code, so a matched
vulnerable/safe pair shares its context; and deliberate false-positive traps —
safe code that looks risky. v1 target: 100–300 samples, balanced across classes,
at least 3 languages.

**Labels:** each sample carries its diff, a vuln / not-vuln label, a CWE where
applicable and a severity. Borderline labels get a second human review.

**Metrics:** precision, recall, F1, false positives per PR, and confidence
calibration (high-confidence findings should be more precise than low), always
reported generator-only vs. generator+verifier side by side.

**Keeping it honest:** results are versioned with the tool version, model ids,
backend and a corpus hash; re-run on model updates; publish the corpus, not
just the summary numbers.

## Guardrails

- Read-only repo access for analysis; no arbitrary command execution.
- Prompt-injection risk documented; recommend requiring approval for external
  contributors' workflow runs.
- Per-PR cost cap and timeouts for large diffs.
- Fixes are suggestions only — never auto-applied.

## v2 (deferred until v1 is solid)

- Ticketing integration (Jira/Linear) above a severity threshold
- SARIF output → GitHub Code Scanning
- Auto-fix suggestions in GitHub's suggested-change format
- Historical trend tracking per repo/team
- Org-wide shared policy config
- Shared core for a local pre-commit CLI and the Action
- Bedrock / Vertex / self-hosted model routing
- Feedback loop: human accept/dismiss per finding feeds prompt tuning, and
  dismissed findings become benchmark negatives

## Non-goals

- Not a replacement for manual review or pentesting.
- Not hardened against prompt injection in v1 — trusted PRs only.
- Not an exploit generator — findings stay pattern-level and educational.
