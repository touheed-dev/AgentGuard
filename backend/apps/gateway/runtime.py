from backend.core.capabilities.service import CapabilityService
from backend.core.gateway import Gateway
from backend.core.identity.models import Agent
from backend.core.identity.registry import AgentRegistry
from backend.core.identity.service import IdentityService
from backend.core.tools.registry import ToolDefinition, ToolRegistry
from backend.services.executor import StubExecutor


def create_runtime() -> tuple[Gateway, IdentityService, StubExecutor]:
    identity = IdentityService()
    agents = AgentRegistry(
        (
            Agent(
                agent_id="researcher-01",
                name="Researcher",
                task_id="task-1",
                capability_version="cap-v1",
                allowed_tools=frozenset({"echo", "get_demo_data"}),
                scopes=frozenset({"tool:echo", "tool:get_demo_data"}),
            ),
        )
    )
    tools = ToolRegistry(
        (
            ToolDefinition(
                tool_name="echo",
                version="1",
                description="Return a synthetic value.",
                required_capability="tool:echo",
                input_schema={
                    "type": "object",
                    "required": ["value"],
                    "properties": {"value": {"type": "string"}},
                    "additionalProperties": False,
                },
            ),
            ToolDefinition(
                tool_name="get_demo_data",
                version="1",
                description="Return deterministic synthetic data.",
                required_capability="tool:get_demo_data",
                input_schema={"type": "object", "additionalProperties": False},
            ),
        )
    )
    return Gateway(identity, agents, CapabilityService(), tools), identity, StubExecutor()
