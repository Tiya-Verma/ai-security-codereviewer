"""LLM backends that force structured output.

Structured output is a hard requirement (docs/ROADMAP.md "Decisions"): we never
parse free text. Two interchangeable backends implement `StructuredClient`:

- `LLMClient` calls the Messages API directly. Every call declares a single tool
  whose input_schema is the pydantic model's JSON schema, and we read the
  tool_use block back.
- `ClaudeCodeClient` shells out to headless Claude Code (`claude -p`) with
  `--json-schema`, so the benchmark can run on a Claude subscription without
  an API key.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import Any, Protocol, TypeVar

from pydantic import BaseModel

try:  # anthropic is a runtime dep, but keep import errors legible during setup.
    from anthropic import Anthropic
except ImportError:  # pragma: no cover
    Anthropic = None  # type: ignore[assignment,misc]

T = TypeVar("T", bound=BaseModel)


class StructuredClient(Protocol):
    def structured(
        self,
        *,
        model: str,
        system: str,
        user: str,
        schema_model: type[T],
        max_tokens: int = 4096,
    ) -> T: ...


class LLMClient:
    def __init__(self, api_key: str | None = None) -> None:
        if Anthropic is None:  # pragma: no cover
            raise RuntimeError("The 'anthropic' package is not installed. Run: pip install -e .")
        self._client = Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))

    def structured(
        self,
        *,
        model: str,
        system: str,
        user: str,
        schema_model: type[T],
        max_tokens: int = 4096,
    ) -> T:
        """Make one call and return `schema_model` parsed from the tool_use block."""
        tool_name = "emit_" + schema_model.__name__.lower()
        response = self._client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            tools=[
                {
                    "name": tool_name,
                    "description": f"Emit a structured {schema_model.__name__}.",
                    "input_schema": schema_model.model_json_schema(),
                }
            ],
            tool_choice={"type": "tool", "name": tool_name},
            messages=[{"role": "user", "content": user}],
        )
        payload: dict[str, Any] | None = None
        for block in response.content:
            if getattr(block, "type", None) == "tool_use":
                payload = block.input  # type: ignore[assignment]
                break
        if payload is None:  # pragma: no cover
            raise ValueError(f"Model did not return a {tool_name} tool_use block.")
        return schema_model.model_validate(payload)


# Flags that strip Claude Code down to a bare model call. Without them, every
# call also loads the user's MCP servers, plugins, skills and CLAUDE.md files —
# measured at ~400K tokens of irrelevant context for a one-line prompt.
_CLAUDE_CODE_FLAGS = [
    "--tools", "",
    "--strict-mcp-config",
    "--disable-slash-commands",
    "--setting-sources", "",
    "--no-session-persistence",
    "--output-format", "json",
]

# Credentials that would make `claude -p` bill an API account instead of the
# logged-in subscription.
_API_CREDENTIAL_VARS = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")


class ClaudeCodeClient:
    """Backend that runs each call through headless Claude Code (`claude -p`).

    Uses the subscription Claude Code is logged in with. `max_tokens` is
    accepted for interface parity but Claude Code manages output length itself.
    """

    def __init__(self, executable: str = "claude", timeout: float = 600.0) -> None:
        self.executable = executable
        self.timeout = timeout
        # API-rate cost Claude Code reports; on a subscription this is usage
        # against plan limits, not a charge.
        self.total_cost_usd = 0.0

    def structured(
        self,
        *,
        model: str,
        system: str,
        user: str,
        schema_model: type[T],
        max_tokens: int = 4096,
    ) -> T:
        cmd = [
            self.executable, "-p",
            "--model", model,
            "--system-prompt", system,
            "--json-schema", json.dumps(schema_model.model_json_schema()),
            *_CLAUDE_CODE_FLAGS,
        ]
        env = {k: v for k, v in os.environ.items() if k not in _API_CREDENTIAL_VARS}
        # An empty working directory keeps project CLAUDE.md files out of context.
        with tempfile.TemporaryDirectory() as cwd:
            proc = subprocess.run(
                cmd, input=user, capture_output=True, text=True,
                env=env, cwd=cwd, timeout=self.timeout,
            )
        try:
            result = json.loads(proc.stdout)
        except json.JSONDecodeError:
            raise RuntimeError(
                f"claude -p exited {proc.returncode} without JSON output: "
                f"{(proc.stderr or proc.stdout).strip()[:500]}"
            ) from None
        self.total_cost_usd += float(result.get("total_cost_usd") or 0.0)
        if result.get("is_error") or result.get("structured_output") is None:
            raise RuntimeError(
                f"claude -p returned no {schema_model.__name__}: "
                f"{result.get('subtype')}: {str(result.get('result'))[:500]}"
            )
        return schema_model.model_validate(result["structured_output"])


def dumps(model: BaseModel) -> str:
    return json.dumps(model.model_dump(mode="json"), indent=2)
