"""The two-pass detection pipeline: generator proposes, verifier disproves."""

from .pipeline import review_diff

__all__ = ["review_diff"]
