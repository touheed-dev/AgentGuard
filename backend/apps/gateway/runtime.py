from backend.core.approval.service import ApprovalService
from backend.core.capabilities.service import CapabilityService
from backend.core.communication.service import CommunicationService
from backend.core.gateway import Gateway
from backend.core.identity.models import Agent
from backend.core.identity.registry import AgentRegistry
from backend.core.identity.service import IdentityService
from backend.core.tools.registry import ToolDefinition, ToolRegistry
from backend.core.task_consistency.service import TaskConsistencyService, TaskDefinition
from backend.core.breaker.service import BreakerService
from backend.core.incidents.service import IncidentService
from backend.deception.honey import HoneyAsset, HoneyAssetRegistry
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
            *(Agent(
                agent_id=agent_id,
                name=agent_id,
                task_id="task-1",
                capability_version="cap-v1",
                allowed_tools=frozenset({"echo", "get_demo_data"}),
                scopes=frozenset({"tool:echo", "tool:get_demo_data"}),
            ) for agent_id in ("planner-01", "coder-01", "executor-01")),
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
    executor_issuer = object()
    executor = StubExecutor(executor_issuer)
    honey_assets = HoneyAssetRegistry((HoneyAsset("honeytoken-01", "token", "AG-HONEY-7F92-XK11"),))
    approvals = ApprovalService()
    communication = CommunicationService(
        edges=frozenset({
            ("planner-01", "researcher-01"),
            ("researcher-01", "planner-01"),
            ("planner-01", "coder-01"),
            ("coder-01", "executor-01"),
        }),
        agents=agents,
    )
    return Gateway(
        identity,
        agents,
        CapabilityService(),
        tools,
        task_consistency=TaskConsistencyService((TaskDefinition(task_id="task-1", label="demo", allowed_tools=frozenset({"echo", "get_demo_data"})),)),
        executor=executor,
        executor_issuer=executor_issuer,
        honey_assets=honey_assets,
        breaker=BreakerService(),
        incidents=IncidentService(),
        approvals=approvals,
        communication=communication,
    ), identity, executor
