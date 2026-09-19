import sys
from pathlib import Path

# The benchmark modules live in benchmark/ and import each other as siblings.
sys.path.insert(0, str(Path(__file__).parent.parent / "benchmark"))

from metrics import Sample, aggregate, score  # noqa: E402

from secreview.models import Finding, Severity  # noqa: E402


def _finding(cwe: str | None) -> Finding:
    return Finding(
        file="app/users.py",
        title="t",
        description="d",
        severity=Severity.HIGH,
        cwe=cwe,
    )


def test_true_positive_class_match() -> None:
    s = Sample(id="a", is_vulnerable=True, cwe="CWE-89")
    m = score(s, [_finding("CWE-89")])
    assert (m.tp, m.fp, m.fn) == (1, 0, 0)


def test_wrong_class_is_fp_and_fn() -> None:
    s = Sample(id="a", is_vulnerable=True, cwe="CWE-89")
    m = score(s, [_finding("CWE-79")])
    # Missed the real class (fn) and raised an off-class finding (fp).
    assert (m.tp, m.fp, m.fn) == (0, 1, 1)


def test_clean_sample_with_finding_is_fp() -> None:
    s = Sample(id="a", is_vulnerable=False)
    m = score(s, [_finding("CWE-89")])
    assert (m.tp, m.fp, m.tn) == (0, 1, 0)


def test_clean_sample_no_findings_is_tn() -> None:
    s = Sample(id="a", is_vulnerable=False)
    m = score(s, [])
    assert (m.tn, m.fp) == (1, 0)


def test_aggregate_and_derived_metrics() -> None:
    metrics = [
        score(Sample("a", True, "CWE-89"), [_finding("CWE-89")]),  # tp
        score(Sample("b", False), []),  # tn
        score(Sample("c", False), [_finding("CWE-89")]),  # fp
    ]
    total = aggregate(metrics)
    assert total.tp == 1 and total.fp == 1 and total.tn == 1
    assert total.precision == 0.5
    assert total.recall == 1.0
