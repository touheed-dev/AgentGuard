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


class ToolRegistry:
    def __init__(self, tools: tuple[ToolDefinition, ...] = ()) -> None:
        self._tools = {tool.tool_name: tool for tool in tools}

    def register(self, tool: ToolDefinition) -> None:
        self._tools = {**self._tools, tool.tool_name: tool}

    def resolve(self, tool_name: str) -> ToolDefinition | None:
        return self._tools.get(tool_name)

    def names(self) -> frozenset[str]:
        return frozenset(self._tools)
