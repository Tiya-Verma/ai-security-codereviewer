from secreview.diff import parse_diff
from secreview.models import Confidence, Finding, Severity
from secreview.pr_comments import build_review_comment, route_findings

# Two hunks with a removed line and a second hunk, so `position` must account
# for the removed line and the second @@ header (position != file line number).
DIFF = """diff --git a/a.py b/a.py
index 1111111..2222222 100644
--- a/a.py
+++ b/a.py
@@ -1,3 +1,3 @@
 ctx1
-old
+new1
 ctx2
@@ -10,2 +11,3 @@
 ctx3
+new2
 ctx4
"""


def _cf():
    return parse_diff(DIFF)[0]


def _finding(line, confidence=Confidence.HIGH, file="a.py"):
    return Finding(file=file, line=line, title="t", description="d",
                   severity=Severity.HIGH, cwe="CWE-89", confidence=confidence)


def test_new_lines_and_added() -> None:
    cf = _cf()
    assert cf.new_lines == {1: "ctx1", 2: "new1", 3: "ctx2",
                            11: "ctx3", 12: "new2", 13: "ctx4"}
    assert cf.added_lines == {2, 12}


def test_positions_account_for_removed_lines_and_second_hunk() -> None:
    # ctx1=1, (old removed)=2, new1=3, ctx2=4, (@@ header)=5, ctx3=6, new2=7, ctx4=8
    assert _cf().positions == {1: 1, 2: 3, 3: 4, 11: 6, 12: 7, 13: 8}


def test_build_comment_uses_position_not_file_line() -> None:
    cf = _cf()
    c = build_review_comment(_finding(line=12), {cf.path: cf})
    assert c is not None
    assert c.line == 12 and c.position == 7 and c.side == "RIGHT"
    assert c.to_api_payload() == {"path": "a.py", "body": c.body, "line": 12, "side": "RIGHT"}
    assert c.to_api_payload(legacy=True) == {"path": "a.py", "body": c.body, "position": 7}


def test_unmappable_findings_return_none() -> None:
    cf = _cf()
    changed = {cf.path: cf}
    assert build_review_comment(_finding(line=None), changed) is None      # no line
    assert build_review_comment(_finding(line=99), changed) is None        # line not in diff
    assert build_review_comment(_finding(line=2, file="other.py"), changed) is None  # unknown file


def test_body_includes_severity_and_cwe() -> None:
    body = build_review_comment(_finding(line=2), {"a.py": _cf()}).body
    assert "HIGH" in body and "CWE-89" in body


def test_route_low_confidence_and_unmappable_go_to_summary() -> None:
    cf = _cf()
    findings = [
        _finding(line=2, confidence=Confidence.HIGH),    # inline
        _finding(line=12, confidence=Confidence.LOW),    # low conf -> summary
        _finding(line=99, confidence=Confidence.HIGH),   # unmappable -> summary
        _finding(line=None, confidence=Confidence.MEDIUM),  # no line -> summary
    ]
    inline, summary = route_findings(findings, [cf])
    assert [c.line for c in inline] == [2]
    assert len(summary) == 3
