from backend.core.approval.service import ApprovalService
from backend.core.capabilities.service import CapabilityService
from backend.core.communication.service import CommunicationService
from backend.core.gateway import Gateway
from backend.core.identity.models import Agent
from backend.core.identity.registry import AgentRegistry
from backend.core.identity.service import IdentityService
from backend.core.threat_intel.service import ThreatIntelService
from backend.core.tools.registry import ToolDefinition, ToolRegistry
from backend.core.task_consistency.service import TaskConsistencyService, TaskDefinition
from backend.core.breaker.service import BreakerService
from backend.core.incidents.service import IncidentService
from backend.deception.honey import HoneyAsset, HoneyAssetRegistry
from backend.services.executor import StubExecutor

ALL_TOOLS = (
    "echo",
    "get_demo_data",
    "web_request",
    "web_search",
    "bash_command",
    "file_read",
    "file_write",
    "read_file",
    "write_file",
    "search_knowledge",
    "db_query",
    "sql_query",
    "patch_vulnerability",
)
ALL_SCOPES = frozenset({f"tool:{t}" for t in ALL_TOOLS})


def create_runtime(identity: IdentityService | None = None) -> tuple[Gateway, IdentityService, StubExecutor]:
    identity = identity or IdentityService()
    agents = AgentRegistry(
        (
            Agent(
                agent_id="researcher-01",
                name="Researcher",
                task_id="task-1",
                capability_version="cap-v1",
                allowed_tools=frozenset(ALL_TOOLS),
                scopes=ALL_SCOPES,
            ),
            *(Agent(
                agent_id=agent_id,
                name=agent_id,
                task_id="task-1",
                capability_version="cap-v1",
                allowed_tools=frozenset(ALL_TOOLS),
                scopes=ALL_SCOPES,
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
            ToolDefinition(
                tool_name="search_knowledge",
                version="1",
                description="Search internal knowledge base.",
                required_capability="tool:search_knowledge",
                sensitivity=5,
                input_schema={
                    "type": "object",
                    "required": ["query"],
                    "properties": {"query": {"type": "string"}},
                    "additionalProperties": True,
                },
            ),
            ToolDefinition(
                tool_name="web_search",
                version="1",
                description="Search the web.",
                required_capability="tool:web_search",
                sensitivity=10,
                input_schema={
                    "type": "object",
                    "required": ["query"],
                    "properties": {"query": {"type": "string"}},
                    "additionalProperties": True,
                },
            ),
            ToolDefinition(
                tool_name="web_request",
                version="1",
                description="Execute outbound HTTP/HTTPS request.",
                required_capability="tool:web_request",
                sensitivity=15,
                input_schema={
                    "type": "object",
                    "required": ["url"],
                    "properties": {
                        "url": {"type": "string"},
                        "method": {"type": "string"},
                        "headers": {"type": "object"},
                    },
                    "additionalProperties": True,
                },
            ),
            ToolDefinition(
                tool_name="bash_command",
                version="1",
                description="Execute system terminal command.",
                required_capability="tool:bash_command",
                sensitivity=25,
                irreversibility=10,
                input_schema={
                    "type": "object",
                    "required": ["command"],
                    "properties": {
                        "command": {"type": "string"},
                    },
                    "additionalProperties": True,
                },
            ),
            ToolDefinition(
                tool_name="file_read",
                version="1",
                description="Read local file content.",
                required_capability="tool:file_read",
                sensitivity=10,
                input_schema={
                    "type": "object",
                    "required": ["path"],
                    "properties": {
                        "path": {"type": "string"},
                    },
                    "additionalProperties": True,
                },
            ),
            ToolDefinition(
                tool_name="read_file",
                version="1",
                description="Read local file content.",
                required_capability="tool:read_file",
                sensitivity=10,
                input_schema={
                    "type": "object",
                    "required": ["path"],
                    "properties": {
                        "path": {"type": "string"},
                    },
                    "additionalProperties": True,
                },
            ),
            ToolDefinition(
                tool_name="file_write",
                version="1",
                description="Write content to local file.",
                required_capability="tool:file_write",
                sensitivity=20,
                irreversibility=8,
                input_schema={
                    "type": "object",
                    "required": ["path", "content"],
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"},
                    },
                    "additionalProperties": True,
                },
            ),
            ToolDefinition(
                tool_name="write_file",
                version="1",
                description="Write content to local file.",
                required_capability="tool:write_file",
                sensitivity=20,
                irreversibility=8,
                input_schema={
                    "type": "object",
                    "required": ["path", "content"],
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"},
                    },
                    "additionalProperties": True,
                },
            ),
            ToolDefinition(
                tool_name="db_query",
                version="1",
                description="Execute database query requiring human supervisor signoff for dangerous mutations.",
                required_capability="tool:db_query",
                sensitivity=25,
                data_sensitivity=20,
                irreversibility=10,
                behavioral_anomaly=5,
                input_schema={
                    "type": "object",
                    "required": ["query"],
                    "properties": {
                        "query": {"type": "string"},
                    },
                    "additionalProperties": True,
                },
            ),
            ToolDefinition(
                tool_name="sql_query",
                version="1",
                description="Execute SQL database query.",
                required_capability="tool:sql_query",
                sensitivity=15,
                input_schema={
                    "type": "object",
                    "required": ["query"],
                    "properties": {
                        "query": {"type": "string"},
                    },
                    "additionalProperties": True,
                },
            ),
            ToolDefinition(
                tool_name="patch_vulnerability",
                version="1",
                description="Apply security remediation for target CVE.",
                required_capability="tool:patch_vulnerability",
                sensitivity=15,
                input_schema={
                    "type": "object",
                    "required": ["cve_id"],
                    "properties": {
                        "cve_id": {"type": "string"},
                        "action": {"type": "string"},
                    },
                    "additionalProperties": True,
                },
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
    threat_intel = ThreatIntelService()

    return Gateway(
        identity,
        agents,
        CapabilityService(),
        tools,
        task_consistency=TaskConsistencyService((TaskDefinition(task_id="task-1", label="demo", allowed_tools=frozenset(ALL_TOOLS)),)),
        executor=executor,
        executor_issuer=executor_issuer,
        honey_assets=honey_assets,
        breaker=BreakerService(),
        incidents=IncidentService(),
        approvals=approvals,
        communication=communication,
        threat_intel=threat_intel,
    ), identity, executor
