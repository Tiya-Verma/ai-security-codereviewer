import sys
from pathlib import Path

# The benchmark modules live in benchmark/ and import each other as siblings.
sys.path.insert(0, str(Path(__file__).parent.parent / "benchmark"))

import run_benchmark  # noqa: E402
from metrics import Sample  # noqa: E402

from secreview.config import ReviewConfig  # noqa: E402
from secreview.engine import review_diff  # noqa: E402
from secreview.models import (  # noqa: E402
    Confidence,
    Finding,
    ReviewResult,
    Severity,
    Verdict,
    VerifiedFinding,
)


def _finding(cwe: str) -> Finding:
    return Finding(file="a.py", line=1, title=f"t-{cwe}", description="d",
                   severity=Severity.HIGH, cwe=cwe)


def _verdict(upheld: bool) -> Verdict:
    return Verdict(upheld=upheld, confidence=Confidence.LOW, rationale="why")


def test_sample_record_marks_hits_and_keeps_rejected_verdicts() -> None:
    sample = Sample(id="s", is_vulnerable=True, cwe="CWE-89")
    hit, miss = _finding("CWE-89"), _finding("CWE-79")
    gen = ReviewResult(generator_findings=[hit, miss], final_findings=[hit, miss])
    verified = ReviewResult(
        generator_findings=[hit, miss],
        final_findings=[VerifiedFinding(**miss.model_dump(), verdict=_verdict(True))],
        rejected_findings=[VerifiedFinding(**hit.model_dump(), verdict=_verdict(False))],
    )
    rec = run_benchmark.sample_record(sample, False, gen, verified)
    assert [f["hit"] for f in rec["generator_only"]] == [True, False]
    assert rec["upheld"][0]["hit"] is False
    # The dropped true positive is recorded with the verifier's reasoning.
    assert rec["rejected"][0]["hit"] is True
    assert rec["rejected"][0]["verdict"]["rationale"] == "why"


def test_load_corpus_context_only_under_file_strategy() -> None:
    diff_only = run_benchmark.load_corpus(context="diff")
    with_files = run_benchmark.load_corpus(context="file")
    assert all(ctx == "" for _, _, ctx in diff_only)
    assert [s.id for s, _, _ in diff_only] == [s.id for s, _, _ in with_files]
    assert all(d1 == d2 for (_, d1, _), (_, d2, _) in zip(diff_only, with_files, strict=True))


def test_corpus_hash_is_stable() -> None:
    assert run_benchmark.corpus_sha256() == run_benchmark.corpus_sha256()


DIFF = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,1 +1,2 @@
 x = 1
+y = 2
"""


class _RejectAll:
    def structured(self, *, schema_model, **_):
        return _verdict(False)


def test_review_diff_keeps_rejected_findings() -> None:
    f = _finding("CWE-89")
    result = review_diff(DIFF, config=ReviewConfig(), client=_RejectAll(),
                         generator_findings=[f])
    assert result.final_findings == []
    assert [r.title for r in result.rejected_findings] == [f.title]
    assert result.rejected_findings[0].verdict.upheld is False


def _report(context: str, provided: bool, upheld: list[dict]) -> dict:
    hit = {**_finding("CWE-89").model_dump(mode="json"), "hit": True}
    return {
        "context": context,
        "samples": [
            {"id": "cve", "is_vulnerable": True, "cwe": "CWE-89",
             "context_provided": provided, "generator_only": [hit], "upheld": upheld},
            {"id": "synthetic", "is_vulnerable": False, "cwe": None,
             "context_provided": False, "generator_only": [], "upheld": []},
        ],
    }


def test_compare_scores_context_subset_for_both_runs() -> None:
    import compare

    hit = {**_finding("CWE-89").model_dump(mode="json"), "hit": True}
    md = compare.compare([_report("diff", False, []), _report("file", True, [hit])])
    subset = md.split("### Samples with context files (1)")[1]
    # Columns: diff gen, diff gen+verify, file gen, file gen+verify.
    recall_row = next(line for line in subset.splitlines() if line.startswith("| recall |"))
    assert recall_row == "| recall | 1.0 | 0.0 | 1.0 | 1.0 |"
