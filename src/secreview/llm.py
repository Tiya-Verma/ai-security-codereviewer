"""Thin Anthropic client wrapper that forces structured output via tool_use.

Structured output is a hard requirement (CLAUDE.md tech-stack table): we never
parse free text. Every call declares a single tool whose input_schema is the
pydantic model's JSON schema, and we read the tool_use block back.
"""

from __future__ import annotations

import json
import os
from typing import Any, TypeVar

from pydantic import BaseModel

try:  # anthropic is a runtime dep, but keep import errors legible during setup.
    from anthropic import Anthropic
except ImportError:  # pragma: no cover
    Anthropic = None  # type: ignore[assignment,misc]

T = TypeVar("T", bound=BaseModel)


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


def dumps(model: BaseModel) -> str:
    return json.dumps(model.model_dump(mode="json"), indent=2)
