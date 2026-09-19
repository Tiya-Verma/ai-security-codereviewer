from pathlib import Path

from secreview.config import ReviewConfig
from secreview.models import Severity


def test_defaults_when_no_file(tmp_path: Path) -> None:
    cfg = ReviewConfig.load(tmp_path / "does-not-exist.yml")
    assert cfg.enable_verifier is True
    assert cfg.severity_threshold is Severity.LOW
    assert cfg.models.verifier == "claude-opus-4-8"


def test_loads_and_validates_yaml(tmp_path: Path) -> None:
    p = tmp_path / ".security-review.yml"
    p.write_text(
        "severity_threshold: high\n"
        "enable_verifier: false\n"
        "ignore_paths:\n  - '**/vendor/**'\n"
    )
    cfg = ReviewConfig.load(p)
    assert cfg.severity_threshold is Severity.HIGH
    assert cfg.enable_verifier is False
    assert cfg.ignore_paths == ["**/vendor/**"]
