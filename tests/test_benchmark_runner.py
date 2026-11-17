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


class _CountingClient:
    """Generator returns one CWE-89 finding; verifier upholds it. Raises once
    `fail_after` generator calls have been made, to simulate a stopped run."""

    def __init__(self, fail_after: int | None = None) -> None:
        self.generator_calls = 0
        self.fail_after = fail_after

    def structured(self, *, schema_model, **_):
        if schema_model is Verdict:
            return Verdict(upheld=True, confidence=Confidence.HIGH, rationale="r")
        if self.fail_after is not None and self.generator_calls >= self.fail_after:
            raise RuntimeError("stopped")
        self.generator_calls += 1
        return schema_model(findings=[_finding("CWE-89")])


def _corpus() -> list:
    return [(Sample(id=f"s{i}", is_vulnerable=True, cwe="CWE-89"), DIFF, "") for i in range(3)]


def test_run_corpus_resumes_from_checkpoint(tmp_path: Path) -> None:
    import pytest

    checkpoint = tmp_path / "run.jsonl"
    with pytest.raises(RuntimeError, match="stopped"):
        run_benchmark.run_corpus(_corpus(), ReviewConfig(), _CountingClient(fail_after=2),
                                 checkpoint)
    assert len(checkpoint.read_text().splitlines()) == 2

    client = _CountingClient()
    records = run_benchmark.run_corpus(_corpus(), ReviewConfig(), client, checkpoint)
    assert client.generator_calls == 1  # only the unfinished sample re-ran
    assert [r["id"] for r in records] == ["s0", "s1", "s2"]

    gen_run, verify_run = run_benchmark.scored_runs(_corpus(), records)
    assert [len(f) for _, f in gen_run] == [1, 1, 1]
    assert all(f[0].cwe == "CWE-89" for _, f in verify_run)


def test_checkpoint_path_changes_with_strategy() -> None:
    config = ReviewConfig()
    assert run_benchmark.checkpoint_path("diff", "api", config) != (
        run_benchmark.checkpoint_path("file", "api", config)
    )
