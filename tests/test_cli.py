import json
from pathlib import Path

from click.testing import CliRunner

from secreview.cli import main, result_from_record, short_rationale


def _f(title: str, hit: bool, verdict: dict | None = None) -> dict:
    f = {
        "file": "app/x.py",
        "line": 3,
        "title": title,
        "description": "d",
        "severity": "high",
        "cwe": "CWE-89",
        "confidence": "high",
        "remediation": None,
        "hit": hit,
    }
    if verdict:
        f["verdict"] = verdict
    return f


UPHELD = {"upheld": True, "confidence": "high", "rationale": "Could not disprove it."}
REJECTED = {
    "upheld": False,
    "confidence": "high",
    "rationale": "The query is parameterized via sqlite placeholders. Nothing else.",
}

RECORD = {
    "id": "s1",
    "is_vulnerable": True,
    "cwe": "CWE-89",
    "context_provided": False,
    "generator_only": [_f("real sqli", True), _f("noise", False)],
    "upheld": [_f("real sqli", True, UPHELD)],
    "rejected": [_f("noise", False, REJECTED)],
}


def _results_file(tmp_path: Path) -> Path:
    p = tmp_path / "results.json"
    p.write_text(json.dumps({"samples": [RECORD]}))
    return p


def test_short_rationale_takes_first_sentence() -> None:
    expected = "The query is parameterized via sqlite placeholders."
    assert short_rationale(REJECTED["rationale"]) == expected


def test_short_rationale_skips_bare_opener() -> None:
    text = "The finding is a false positive. The diff is truncated mid-function. More."
    assert short_rationale(text) == (
        "The finding is a false positive. The diff is truncated mid-function."
    )


def test_short_rationale_truncates() -> None:
    out = short_rationale("x" * 500, limit=20)
    assert len(out) == 20 and out.endswith("…")


def test_result_from_record_modes() -> None:
    verified = result_from_record(RECORD)
    assert [f.title for f in verified.final_findings] == ["real sqli"]
    assert verified.rejected_findings[0].verdict.upheld is False

    gen_only = result_from_record(RECORD, verifier=False)
    assert [f.title for f in gen_only.final_findings] == ["real sqli", "noise"]
    assert gen_only.rejected_findings == []


def test_replay_show_rejected(tmp_path: Path) -> None:
    res = CliRunner().invoke(
        main, ["replay", str(_results_file(tmp_path)), "s1", "--show-rejected"]
    )
    assert res.exit_code == 0, res.output
    assert "real sqli" in res.output
    assert "Rejected by verifier (1)" in res.output
    assert "parameterized via sqlite placeholders." in res.output


def test_replay_generator_only_hides_rejected(tmp_path: Path) -> None:
    res = CliRunner().invoke(
        main, ["replay", str(_results_file(tmp_path)), "s1", "--no-verifier", "--show-rejected"]
    )
    assert res.exit_code == 0, res.output
    assert "noise" in res.output
    assert "Rejected by verifier" not in res.output


def test_replay_unknown_sample(tmp_path: Path) -> None:
    res = CliRunner().invoke(main, ["replay", str(_results_file(tmp_path)), "nope"])
    assert res.exit_code != 0
    assert "unknown sample" in res.output


def test_replay_real_results_file() -> None:
    """The committed benchmark results must stay replayable (the demo depends on it)."""
    results = sorted(Path("benchmark/results").glob("results-*-diff-*.json"))
    assert results
    data = json.loads(results[-1].read_text())
    for record in data["samples"]:
        result_from_record(record)
        result_from_record(record, verifier=False)
