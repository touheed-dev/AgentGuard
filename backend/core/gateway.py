import hashlib
import json
from typing import Any

import jwt

from backend.core.capabilities.service import CapabilityService
from backend.core.identity.registry import AgentRegistry
from backend.core.identity.service import IdentityService
from backend.core.tools.registry import ToolRegistry
from backend.core.validation.schema import validate_object
from backend.shared.contracts import Decision, DecisionOutcome, Reason, ReasonCode


class Gateway:
    def __init__(
        self,
        identity: IdentityService,
        agents: AgentRegistry,
        capabilities: CapabilityService,
        tools: ToolRegistry,
    ) -> None:
        self.identity = identity
        self.agents = agents
        self.capabilities = capabilities
        self.tools = tools

    def authorize(
        self,
        agent_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        task_id: str,
        trace_id: str,
        token: str,
        execution_id: str | None = None,
    ) -> Decision:
        resolved_execution_id = execution_id or self._execution_id(agent_id, tool_name, arguments, task_id, trace_id)
        context = {
            "agent_id": agent_id,
            "tool_name": tool_name,
            "task_id": task_id,
            "trace_id": trace_id,
            "execution_id": resolved_execution_id,
        }
        try:
            verified_token = self.identity.verify_token(token)
        except (jwt.InvalidTokenError, TypeError, ValueError):
            return self._blocked(ReasonCode.TOKEN_INVALID, "Agent token is invalid.", context)
        if verified_token.agent_id != agent_id:
            return self._blocked(ReasonCode.TOKEN_INVALID, "Token subject does not match the agent.", context)
        agent = self.agents.get(agent_id)
        if agent is None:
            return self._blocked(ReasonCode.TOKEN_INVALID, "Agent identity is not registered.", context)
        tool = self.tools.resolve(tool_name)
        capability = self.capabilities.check(
            agent,
            verified_token,
            tool_name,
            task_id,
            self.tools.names(),
            tool.required_capability if tool is not None else None,
        )
        if not capability.allowed:
            return self._blocked(capability.code or ReasonCode.CAPABILITY_DENIED, capability.message, context)
        if tool is None:
            return self._blocked(ReasonCode.TOOL_UNREGISTERED, "Tool is not registered.", context)
        if not tool.enabled:
            return self._blocked(ReasonCode.CAPABILITY_DENIED, "Tool is disabled.", context)
        valid, message = validate_object(arguments, tool.input_schema)
        if not valid:
            return self._blocked(ReasonCode.SCHEMA_INVALID, message, context)
        return Decision(decision=DecisionOutcome.ALLOW, **context)

    @staticmethod
    def _execution_id(agent_id: str, tool_name: str, arguments: dict[str, Any], task_id: str, trace_id: str) -> str:
        payload = json.dumps([agent_id, tool_name, arguments, task_id, trace_id], sort_keys=True, separators=(",", ":"))
        return f"exec-{hashlib.sha256(payload.encode()).hexdigest()[:24]}"

    @staticmethod
    def _blocked(code: ReasonCode, message: str, context: dict[str, str]) -> Decision:
        reason = Reason(code=code, message=message, severity="critical", source="gateway")
        return Decision(decision=DecisionOutcome.BLOCK, reasons=(reason,), **context)
