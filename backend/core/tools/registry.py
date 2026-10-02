from typing import Any

from pydantic import Field

from backend.shared.contracts import StrictModel


class ToolDefinition(StrictModel):
    tool_name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    description: str
    input_schema: dict[str, Any]
    required_capability: str
    enabled: bool = True
    sensitivity: int = Field(default=0, ge=0, le=25)
    data_sensitivity: int = Field(default=0, ge=0, le=20)
    irreversibility: int = Field(default=0, ge=0, le=10)
    behavioral_anomaly: int = Field(default=0, ge=0, le=10)
    max_payload_bytes: int = Field(default=65536, ge=1)
    allowed_destinations: frozenset[str] = frozenset()
    command_fields: frozenset[str] = frozenset({"command", "shell", "cmd", "script", "code"})
    hard_signal: bool = False
    hard_signal_reason: str | None = None


class ToolRegistry:
    def __init__(self, tools: tuple[ToolDefinition, ...] = ()) -> None:
        self._tools = {tool.tool_name: tool for tool in tools}

    def register(self, tool: ToolDefinition) -> None:
        self._tools = {**self._tools, tool.tool_name: tool}

    def resolve(self, tool_name: str) -> ToolDefinition | None:
        return self._tools.get(tool_name)

    def names(self) -> frozenset[str]:
        return frozenset(self._tools)

    def list(self) -> tuple[ToolDefinition, ...]:
        return tuple(self._tools.values())
