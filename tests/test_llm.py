import json
import subprocess

import pytest
from pydantic import BaseModel

from secreview import llm
from secreview.config import ReviewConfig
from secreview.engine import review_diff
from secreview.llm import ClaudeCodeClient
from secreview.models import Confidence, Finding, Severity, Verdict


class _Answer(BaseModel):
    answer: int


def _fake_run(monkeypatch, stdout: str, returncode: int = 0) -> list[dict]:
    """Replace subprocess.run in llm; return a list that records each call."""
    calls: list[dict] = []

    def run(cmd, **kwargs):
        calls.append({"cmd": cmd, **kwargs})
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr="boom")

    monkeypatch.setattr(llm.subprocess, "run", run)
    return calls


def _result(**overrides) -> str:
    payload = {"is_error": False, "subtype": "success", "total_cost_usd": 0.01,
               "structured_output": {"answer": 5}, "result": '{"answer":5}'}
    return json.dumps({**payload, **overrides})


def test_claude_code_parses_structured_output(monkeypatch) -> None:
    calls = _fake_run(monkeypatch, _result())
    client = ClaudeCodeClient()
    out = client.structured(model="claude-sonnet-5", system="sys", user="2+3?",
                            schema_model=_Answer)
    assert out == _Answer(answer=5)
    assert client.total_cost_usd == pytest.approx(0.01)

    cmd = calls[0]["cmd"]
    assert cmd[cmd.index("--model") + 1] == "claude-sonnet-5"
    assert cmd[cmd.index("--system-prompt") + 1] == "sys"
    assert json.loads(cmd[cmd.index("--json-schema") + 1]) == _Answer.model_json_schema()
    # Context-stripping flags: no tools, MCP servers, skills or settings.
    assert cmd[cmd.index("--tools") + 1] == ""
    assert "--strict-mcp-config" in cmd and "--disable-slash-commands" in cmd
    assert calls[0]["input"] == "2+3?"


def test_claude_code_strips_api_credentials(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "tok")
    calls = _fake_run(monkeypatch, _result())
    ClaudeCodeClient().structured(model="m", system="s", user="u", schema_model=_Answer)
    env = calls[0]["env"]
    assert "ANTHROPIC_API_KEY" not in env and "ANTHROPIC_AUTH_TOKEN" not in env


def test_claude_code_raises_on_error_result(monkeypatch) -> None:
    _fake_run(monkeypatch, _result(is_error=True, subtype="error_max_turns",
                                   structured_output=None))
    with pytest.raises(RuntimeError, match="error_max_turns"):
        ClaudeCodeClient().structured(model="m", system="s", user="u", schema_model=_Answer)


def test_claude_code_raises_on_non_json_output(monkeypatch) -> None:
    _fake_run(monkeypatch, "Not logged in", returncode=1)
    with pytest.raises(RuntimeError, match="exited 1"):
        ClaudeCodeClient().structured(model="m", system="s", user="u", schema_model=_Answer)


DIFF = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,1 +1,2 @@
 x = 1
+cur.execute("SELECT * FROM t WHERE id=" + uid)
"""


class _VerifierOnlyClient:
    """Fails if the generator is called; upholds every verified finding."""

    def structured(self, *, schema_model, **_):
        assert schema_model is Verdict, "generator must not run when findings are supplied"
        return Verdict(upheld=True, confidence=Confidence.HIGH, rationale="r",
                       context_that_would_change_this=None)


def test_review_diff_reuses_supplied_generator_findings() -> None:
    finding = Finding(file="app.py", line=2, title="SQLi", description="d",
                      severity=Severity.HIGH, cwe="CWE-89", confidence=Confidence.MEDIUM)
    result = review_diff(DIFF, config=ReviewConfig(), client=_VerifierOnlyClient(),
                         generator_findings=[finding])
    assert result.generator_findings == [finding]
    assert [f.title for f in result.final_findings] == ["SQLi"]
    assert result.final_findings[0].confidence == Confidence.HIGH
