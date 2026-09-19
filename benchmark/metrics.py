"""Benchmark scoring: precision, recall, F1, false-positives-per-PR, and
confidence calibration. These are the published, versioned numbers that are
the whole point of the project (CLAUDE.md "Metrics to publish").

The "hit" definition is class-level by default (a finding counts as a true
positive if it flags the correct CWE class anywhere in the sample's diff).
This is an open decision in CLAUDE.md; it lives here as one function so it can
be swapped without touching the runner, and so the definition is auditable.
"""

from __future__ import annotations

from dataclasses import dataclass

from secreview.models import Finding


@dataclass
class Sample:
    """One labeled benchmark sample."""

    id: str
    is_vulnerable: bool
    cwe: str | None = None  # ground-truth class, when applicable


def is_hit(sample: Sample, finding: Finding) -> bool:
    """Class-level match: same CWE flagged. If the sample has no CWE label,
    any finding on a vulnerable sample counts."""
    if not sample.is_vulnerable:
        return False
    if sample.cwe is None:
        return True
    return finding.cwe == sample.cwe


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    samples: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def false_positives_per_pr(self) -> float:
        return self.fp / self.samples if self.samples else 0.0

    def as_dict(self) -> dict[str, float | int]:
        return {
            "samples": self.samples,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "false_positives_per_pr": round(self.false_positives_per_pr, 4),
        }


def score(sample: Sample, findings: list[Finding]) -> Metrics:
    """Score one sample's findings. Aggregate by summing Metrics across samples."""
    m = Metrics(samples=1)
    hits = [f for f in findings if is_hit(sample, f)]

    if sample.is_vulnerable:
        if hits:
            m.tp += 1
        else:
            m.fn += 1
        # Any finding that is NOT the labeled class is a false positive.
        m.fp += len([f for f in findings if not is_hit(sample, f)])
    else:
        # A clean sample: every finding is a false positive.
        if findings:
            m.fp += len(findings)
        else:
            m.tn += 1
    return m


def aggregate(per_sample: list[Metrics]) -> Metrics:
    total = Metrics()
    for m in per_sample:
        total.tp += m.tp
        total.fp += m.fp
        total.fn += m.fn
        total.tn += m.tn
        total.samples += m.samples
    return total
