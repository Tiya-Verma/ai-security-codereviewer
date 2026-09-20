"""Corpus integrity guardrails. A benchmark is only as trustworthy as its
ground truth, so these run without an API key on every `pytest`."""

from pathlib import Path

import yaml

from secreview.diff import parse_diff

CORPUS = Path(__file__).parent.parent / "benchmark" / "corpus"
MANIFEST = CORPUS / "manifest.yml"

_ENTRIES = yaml.safe_load(MANIFEST.read_text())


def test_ids_are_unique() -> None:
    ids = [e["id"] for e in _ENTRIES]
    assert len(ids) == len(set(ids))


def test_every_diff_exists_and_parses() -> None:
    for e in _ENTRIES:
        diff_path = CORPUS / e["diff"]
        assert diff_path.exists(), f"missing diff for {e['id']}: {diff_path}"
        changed = parse_diff(diff_path.read_text())
        assert changed, f"diff parsed to nothing: {e['id']}"
        assert any(c.added_lines for c in changed), f"no added lines: {e['id']}"


def test_no_orphan_diff_files() -> None:
    referenced = {(CORPUS / e["diff"]).resolve() for e in _ENTRIES}
    on_disk = {p.resolve() for p in (CORPUS / "samples").glob("*.diff")}
    assert on_disk - referenced == set(), "orphan diff files not in manifest"


def test_labels_are_consistent() -> None:
    for e in _ENTRIES:
        if e["is_vulnerable"]:
            # A labeled positive must name its class so class-level scoring works.
            assert e.get("cwe"), f"vulnerable sample missing cwe: {e['id']}"
        else:
            # Negatives (fp-traps) must not carry a cwe, or they'd score as positives.
            assert not e.get("cwe"), f"negative sample should not have cwe: {e['id']}"
