"""AgentGuard Python SDK.

The SDK is a thin integration layer that connects autonomous AI agents
to the AgentGuard Gateway.  All security decisions are made by the Gateway;
the SDK only provides a clean developer interface.

Quick start
-----------
    from agentguard import AgentGuard

    guard = AgentGuard(
        gateway="http://localhost:8000",
        agent_id="researcher-01",
        token=TOKEN,
    )

    result = guard.execute(
        tool="read_file",
        parameters={"path": "/data/report.pdf"},
        task_id="task-001",
    )

Architecture
------------
    Agent
      ↓
    AgentGuard SDK  ← you are here
      ↓
    AgentGuard Gateway  ← all security decisions happen here
      ↓
    Tool Executor
      ↓
    Tool (File / HTTP / DB / Shell)
"""

from agentguard.client import AgentGuard
from agentguard.exceptions import (
    AgentGuardError,
    ApprovalRequiredError,
    AuthenticationError,
    BlockedActionError,
    ConnectionError,
    ExecutionError,
    MalformedResponseError,
    QuarantinedAgentError,
    TimeoutError,
    ValidationError,
)
from agentguard.models import (
    AgentGuardResult,
    AgentStatus,
    Decision,
    EvaluateResult,
    ExecutionDetail,
    ExecutionStatus,
    TraceResult,
    TraceStep,
)

__version__ = "0.1.0"
__all__ = [
    "AgentGuard",
    # Exceptions
    "AgentGuardError",
    "ApprovalRequiredError",
    "AuthenticationError",
    "BlockedActionError",
    "ConnectionError",
    "ExecutionError",
    "MalformedResponseError",
    "QuarantinedAgentError",
    "TimeoutError",
    "ValidationError",
    # Models
    "AgentGuardResult",
    "AgentStatus",
    "Decision",
    "EvaluateResult",
    "ExecutionDetail",
    "ExecutionStatus",
    "TraceResult",
    "TraceStep",
]
