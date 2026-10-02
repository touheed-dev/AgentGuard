"""AgentGuard Gateway Runtime — Production Configuration.

Creates the full Gateway with:
  - Registered agents (researcher-01, planner-01, coder-01, executor-01)
  - Real tool registry (read_file, http_fetch, db_query, bash_exec, search_knowledge, echo, get_demo_data)
  - Real executor (RealExecutor with live tool handlers)
  - Honeyasset registry
  - Task consistency
  - Circuit breaker
  - Approval service
  - Communication graph
"""

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
from backend.services.executor import RealExecutor


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

def _build_tool_registry() -> ToolRegistry:
    return ToolRegistry(
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
            ToolDefinition(
                tool_name="read_file",
                version="1.0",
                description="Read contents of a local file within the allowed sandbox.",
                required_capability="tool:read_file",
                input_schema={
                    "type": "object",
                    "required": ["path"],
                    "properties": {"path": {"type": "string"}},
                    "additionalProperties": False,
                },
                sensitivity=15,
                data_sensitivity=15,
            ),
            ToolDefinition(
                tool_name="http_fetch",
                version="1.0",
                description="Fetch external web data from an allowed destination.",
                required_capability="tool:http_fetch",
                input_schema={
                    "type": "object",
                    "required": ["url"],
                    "properties": {"url": {"type": "string"}},
                    "additionalProperties": False,
                },
                allowed_destinations=frozenset({"api.github.com", "example.com", "httpbin.org", "jsonplaceholder.typicode.com"}),
                sensitivity=10,
            ),
            ToolDefinition(
                tool_name="db_query",
                version="1.0",
                description="Execute a database query (SELECT only without approval).",
                required_capability="tool:db_query",
                input_schema={
                    "type": "object",
                    "required": ["query"],
                    "properties": {"query": {"type": "string"}},
                    "additionalProperties": False,
                },
                sensitivity=25,
                data_sensitivity=20,
                irreversibility=10,
            ),
            ToolDefinition(
                tool_name="bash_exec",
                version="1.0",
                description="Execute a whitelisted shell command in a restricted environment.",
                required_capability="tool:bash_exec",
                input_schema={
                    "type": "object",
                    "required": ["command"],
                    "properties": {"command": {"type": "string"}},
                    "additionalProperties": False,
                },
                command_fields=frozenset({"command"}),
                sensitivity=25,
                irreversibility=10,
            ),
            ToolDefinition(
                tool_name="search_knowledge",
                version="1.0",
                description="Search the local knowledge base for relevant information.",
                required_capability="tool:search_knowledge",
                input_schema={
                    "type": "object",
                    "required": ["query"],
                    "properties": {"query": {"type": "string"}},
                    "additionalProperties": False,
                },
                sensitivity=0,
                data_sensitivity=0,
            ),
        )
    )


# ---------------------------------------------------------------------------
# Agent definitions
# ---------------------------------------------------------------------------

_RESEARCHER_TOOLS = frozenset({
    "echo", "get_demo_data", "read_file", "http_fetch", "search_knowledge",
})
_RESEARCHER_SCOPES = frozenset({f"tool:{t}" for t in _RESEARCHER_TOOLS})

_PLANNER_TOOLS = frozenset({"echo", "get_demo_data", "search_knowledge"})
_PLANNER_SCOPES = frozenset({f"tool:{t}" for t in _PLANNER_TOOLS})

_CODER_TOOLS = frozenset({"echo", "get_demo_data", "bash_exec", "read_file"})
_CODER_SCOPES = frozenset({f"tool:{t}" for t in _CODER_TOOLS})

_EXECUTOR_TOOLS = frozenset({"echo", "get_demo_data", "db_query", "bash_exec"})
_EXECUTOR_SCOPES = frozenset({f"tool:{t}" for t in _EXECUTOR_TOOLS})


def _build_agent_registry() -> AgentRegistry:
    return AgentRegistry(
        (
            Agent(
                agent_id="researcher-01",
                name="Researcher",
                task_id="task-1",
                capability_version="cap-v1",
                allowed_tools=_RESEARCHER_TOOLS,
                scopes=_RESEARCHER_SCOPES,
            ),
            Agent(
                agent_id="planner-01",
                name="Planner",
                task_id="task-1",
                capability_version="cap-v1",
                allowed_tools=_PLANNER_TOOLS,
                scopes=_PLANNER_SCOPES,
            ),
            Agent(
                agent_id="coder-01",
                name="Coder",
                task_id="task-1",
                capability_version="cap-v1",
                allowed_tools=_CODER_TOOLS,
                scopes=_CODER_SCOPES,
            ),
            Agent(
                agent_id="executor-01",
                name="Executor",
                task_id="task-1",
                capability_version="cap-v1",
                allowed_tools=_EXECUTOR_TOOLS,
                scopes=_EXECUTOR_SCOPES,
            ),
        )
    )


# ---------------------------------------------------------------------------
# Task registry
# ---------------------------------------------------------------------------

def _build_task_registry() -> TaskConsistencyService:
    all_tools = frozenset({
        "echo", "get_demo_data", "read_file", "http_fetch",
        "db_query", "bash_exec", "search_knowledge",
    })
    return TaskConsistencyService(
        (
            TaskDefinition(
                task_id="task-1",
                label="demo",
                allowed_tools=all_tools,
            ),
            TaskDefinition(
                task_id="research-task",
                label="research",
                allowed_tools=frozenset({"read_file", "http_fetch", "search_knowledge", "echo"}),
            ),
            TaskDefinition(
                task_id="coding-task",
                label="coding",
                allowed_tools=frozenset({"bash_exec", "read_file", "echo"}),
            ),
        )
    )


# ---------------------------------------------------------------------------
# Honey assets
# ---------------------------------------------------------------------------

def _build_honey_registry() -> HoneyAssetRegistry:
    return HoneyAssetRegistry(
        (
            HoneyAsset("honeytoken-01", "token", "AG-HONEY-7F92-XK11"),
            HoneyAsset("honeykey-01", "path", "/keys/honey_token.key"),
            HoneyAsset("honeycred-01", "credential", "honey_secret_credential"),
        )
    )


# ---------------------------------------------------------------------------
# Main factory
# ---------------------------------------------------------------------------

def create_runtime() -> tuple[Gateway, IdentityService, RealExecutor]:
    """Create a fully configured AgentGuard runtime.

    Returns
    -------
    tuple[Gateway, IdentityService, RealExecutor]
    """
    identity = IdentityService()
    agents = _build_agent_registry()
    tools = _build_tool_registry()
    executor_issuer = object()
    executor = RealExecutor(executor_issuer)
    honey_assets = _build_honey_registry()
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
        task_consistency=_build_task_registry(),
        executor=executor,
        executor_issuer=executor_issuer,
        honey_assets=honey_assets,
        breaker=BreakerService(),
        incidents=IncidentService(),
        approvals=approvals,
        communication=communication,
    ), identity, executor
