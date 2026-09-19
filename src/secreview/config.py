"""Schema for the in-repo `.security-review.yml` config file.

Validated with pydantic so a malformed config fails loudly at load time rather
than silently changing scan behavior. Everything has a sane default so the file
is entirely optional.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from .models import Severity

DEFAULT_CONFIG_NAME = ".security-review.yml"


class SuppressionConfig(BaseModel):
    # Inline comment marker that suppresses findings on the same/next line.
    inline_marker: str = "security-review: ignore"
    # Path to a baseline/allowlist file of accepted, recurring risks.
    baseline_file: str | None = None


class ModelConfig(BaseModel):
    # Split by role so we can pay for quality only where it matters (verifier).
    generator: str = "claude-sonnet-5"
    verifier: str = "claude-opus-4-8"
    max_tokens: int = 4096


class ReviewConfig(BaseModel):
    # Custom scan guidance injected into the generator prompt.
    scan_instructions: str | None = None
    # Custom guidance for the false-positive-filtering / verifier stage.
    false_positive_instructions: str | None = None
    # Glob patterns to skip entirely.
    ignore_paths: list[str] = Field(default_factory=list)
    # Minimum severity to surface as a comment at all.
    severity_threshold: Severity = Severity.LOW
    # Whether the verifier pass runs. Off = generator-only (baseline mode).
    enable_verifier: bool = True

    suppression: SuppressionConfig = Field(default_factory=SuppressionConfig)
    models: ModelConfig = Field(default_factory=ModelConfig)

    @classmethod
    def load(cls, path: str | Path | None = None) -> ReviewConfig:
        """Load config from `path`, or return defaults if it doesn't exist."""
        p = Path(path) if path else Path(DEFAULT_CONFIG_NAME)
        if not p.exists():
            return cls()
        data = yaml.safe_load(p.read_text()) or {}
        return cls.model_validate(data)
