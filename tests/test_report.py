import json
import sys
from pathlib import Path

# The benchmark modules live in benchmark/ and import each other as siblings.
sys.path.insert(0, str(Path(__file__).parent.parent / "benchmark"))

from metrics import Sample, aggregate, calibration, score  # noqa: E402
from report import build_report, mode_summary, render_markdown, write_report  # noqa: E402

from secreview.models import Confidence, Finding, Severity  # noqa: E402


def _finding(cwe: str | None, confidence: Confidence) -> Finding:
    return Finding(
        file="app/x.py",
        title="t",
        description="d",
        severity=Severity.HIGH,
        cwe=cwe,
        confidence=confidence,
    )


def test_calibration_buckets_precision() -> None:
    vuln = Sample(id="v", is_vulnerable=True, cwe="CWE-89")
    clean = Sample(id="c", is_vulnerable=False)
    run = [
        (vuln, [_finding("CWE-89", Confidence.HIGH)]),   # high: correct
        (clean, [_finding("CWE-89", Confidence.HIGH)]),  # high: wrong (clean sample)
        (clean, [_finding("CWE-79", Confidence.LOW)]),   # low: wrong
    ]
    calib = calibration(run)
    assert calib["high"]["findings"] == 2
    assert calib["high"]["precision"] == 0.5
    assert calib["low"]["precision"] == 0.0
    assert calib["medium"]["findings"] == 0  # empty bucket doesn't crash


def _example_report() -> dict:
    vuln = Sample(id="v", is_vulnerable=True, cwe="CWE-89")
    gen_run = [(vuln, [_finding("CWE-89", Confidence.MEDIUM)])]
    summary = mode_summary(aggregate([score(s, f) for s, f in gen_run]), calibration(gen_run))
    return build_report(
        tool_version="0.1.0",
        models={"generator": "claude-sonnet-5", "verifier": "claude-opus-4-8"},
        corpus={"samples": 1, "sha256": "deadbeefcafe"},
        generator_only=summary,
        generator_plus_verifier=summary,
        generated_at="2026-09-19T00:00:00+00:00",
    )


def test_build_report_shape() -> None:
    r = _example_report()
    assert r["tool_version"] == "0.1.0"
    assert set(r["modes"]) == {"generator_only", "generator_plus_verifier"}
    assert "metrics" in r["modes"]["generator_only"]
    assert "calibration" in r["modes"]["generator_only"]


def test_render_markdown_contains_tables() -> None:
    md = render_markdown(_example_report())
    assert "## Results" in md
    assert "Generator only" in md and "Generator + Verifier" in md
    assert "Confidence calibration" in md
    assert "claude-opus-4-8" in md  # provenance line
    assert "deadbeef" in md  # short corpus sha


def test_write_report_persists_latest_and_versioned(tmp_path: Path) -> None:
    r = _example_report()
    latest, versioned = write_report(tmp_path, r)
    assert latest.name == "latest.json"
    assert versioned.name == "results-v0.1.0-2026-09-19.json"
    # Both are valid JSON and equal.
    assert json.loads(latest.read_text()) == json.loads(versioned.read_text()) == r
