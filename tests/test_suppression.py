from pathlib import Path

from secreview.config import ReviewConfig
from secreview.diff import ChangedFile
from secreview.models import Finding, Severity
from secreview.suppression import BaselineEntry, apply_suppressions, load_baseline


def _finding(file="app/x.py", line=10, cwe="CWE-89", title="SQL injection") -> Finding:
    return Finding(file=file, line=line, title=title, description="d",
                   severity=Severity.HIGH, cwe=cwe)


def _changed(path="app/x.py", lines=None) -> ChangedFile:
    return ChangedFile(path=path, added_lines=set((lines or {}).keys()),
                       new_lines=lines or {})


def test_inline_marker_on_same_line_suppresses() -> None:
    cf = _changed(lines={10: "run(sql)  # security-review: ignore"})
    kept, suppressed = apply_suppressions([_finding(line=10)], [cf], ReviewConfig())
    assert kept == []
    assert len(suppressed) == 1 and suppressed[0].reason == "inline"


def test_inline_marker_on_line_above_suppresses() -> None:
    cf = _changed(lines={9: "# security-review: ignore", 10: "run(sql)"})
    kept, _ = apply_suppressions([_finding(line=10)], [cf], ReviewConfig())
    assert kept == []


def test_no_marker_keeps_finding() -> None:
    cf = _changed(lines={10: "run(sql)"})
    kept, suppressed = apply_suppressions([_finding(line=10)], [cf], ReviewConfig())
    assert len(kept) == 1 and suppressed == []


def test_baseline_matches_file_and_cwe(tmp_path: Path) -> None:
    baseline = tmp_path / ".security-baseline.yml"
    baseline.write_text("- file: 'app/*.py'\n  cwe: CWE-89\n")
    cfg = ReviewConfig()
    cfg.suppression.baseline_file = ".security-baseline.yml"
    cf = _changed(lines={10: "run(sql)"})
    kept, suppressed = apply_suppressions([_finding()], [cf], cfg, base_dir=tmp_path)
    assert kept == []
    assert suppressed[0].reason == "baseline"


def test_baseline_cwe_mismatch_keeps(tmp_path: Path) -> None:
    baseline = tmp_path / ".security-baseline.yml"
    baseline.write_text("- file: 'app/*.py'\n  cwe: CWE-79\n")  # different class
    cfg = ReviewConfig()
    cfg.suppression.baseline_file = ".security-baseline.yml"
    cf = _changed(lines={10: "run(sql)"})
    kept, _ = apply_suppressions([_finding(cwe="CWE-89")], [cf], cfg, base_dir=tmp_path)
    assert len(kept) == 1


def test_baseline_title_substring() -> None:
    entry = BaselineEntry(file="app/*.py", title="sql injection")
    assert entry.matches(_finding(title="Possible SQL Injection in query"))
    assert not entry.matches(_finding(title="XSS in template"))


def test_load_baseline_missing_file_is_empty(tmp_path: Path) -> None:
    assert load_baseline(tmp_path / "nope.yml") == []


def test_inline_takes_precedence_over_baseline(tmp_path: Path) -> None:
    baseline = tmp_path / ".security-baseline.yml"
    baseline.write_text("- file: 'app/*.py'\n")
    cfg = ReviewConfig()
    cfg.suppression.baseline_file = ".security-baseline.yml"
    cf = _changed(lines={10: "run(sql)  # security-review: ignore"})
    _, suppressed = apply_suppressions([_finding()], [cf], cfg, base_dir=tmp_path)
    assert suppressed[0].reason == "inline"
