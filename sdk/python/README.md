# AgentGuard Python SDK

Lightweight client for connecting autonomous AI agents to the **AgentGuard Runtime Security Gateway**.

## Installation

```bash
pip install agentguard-sdk
# Or from local source:
pip install -e sdk/python
```

## Quickstart

```python
from agentguard import AgentGuard, BlockedActionError, ApprovalRequiredError, QuarantinedAgentError

# Initialize the guard client
guard = AgentGuard(
    gateway="http://localhost:8000",
    agent_id="researcher-01",
    token="YOUR_AGENT_JWT_TOKEN",
    task_id="task-101",
)

# Execute an action through the Gateway
try:
    result = guard.execute(
        tool="read_file",
        parameters={"path": "data/research_report.txt"},
    )
    print("Execution result:", result.execution.result)

except BlockedActionError as exc:
    print(f"Action blocked by AgentGuard: {exc.reason_codes}")

except ApprovalRequiredError as exc:
    print(f"Action requires human approval. Approval ID: {exc.approval_id}")

except QuarantinedAgentError as exc:
    print("Agent is quarantined due to a previous security violation.")
```

## Core Security Invariant

> **"The agent decides WHAT it wants to do. AgentGuard decides WHETHER it is allowed to do it."**

- The SDK is **NOT** a security authority.
- The SDK contains **no CEL logic**, **no capability checks**, and **no risk calculators**.
- All security decisions are strictly evaluated by the AgentGuard Gateway.
