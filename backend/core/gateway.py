import hashlib
import json
from threading import Lock
from typing import Any, Protocol
from typing import Any

import jwt

from backend.core.capabilities.service import CapabilityService
from backend.core.decision.service import DecisionService
from backend.core.identity.registry import AgentRegistry
from backend.core.identity.service import IdentityService
from backend.core.risk.service import RiskService
from backend.core.task_consistency.service import TaskConsistencyService
from backend.core.tools.registry import ToolRegistry
from backend.core.validation.schema import validate_object
from backend.core.validation.security import ParameterResult, ParameterValidator
from backend.shared.contracts import AuthorizationReceipt, Decision, DecisionOutcome, Reason, ReasonCode


class ExecutionBoundary(Protocol):
    def issue_grant(self, receipt: Any, issuer: object) -> Any: ...

    def execute(self, receipt: Any) -> dict[str, Any]: ...


class Gateway:
    def __init__(
        self,
        identity: IdentityService,
        agents: AgentRegistry,
        capabilities: CapabilityService,
        tools: ToolRegistry,
        parameter_validator: ParameterValidator | None = None,
        task_consistency: TaskConsistencyService | None = None,
        risk: RiskService | None = None,
        decision_service: DecisionService | None = None,
        executor: ExecutionBoundary | None = None,
        executor_issuer: object | None = None,
    ) -> None:
        self.identity = identity
        self.agents = agents
        self.capabilities = capabilities
        self.tools = tools
        self.parameter_validator = parameter_validator or ParameterValidator()
        self.task_consistency = task_consistency or TaskConsistencyService()
        self.risk = risk or RiskService()
        self.decision_service = decision_service or DecisionService()
        self.executor = executor
        self.executor_issuer = executor_issuer
        self._executed_ids: set[str] = set()
        self._authorized_fingerprints: dict[str, str] = {}
        self._claimed_ids: set[str] = set()
        self._request_ids: set[str] = set()
        self._execution_lock = Lock()

    def authorize(
        self,
        agent_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        task_id: str,
        trace_id: str,
        token: str,
        execution_id: str | None = None,
        request_id: str | None = None,
    ) -> Decision:
        if request_id is not None:
            with self._execution_lock:
                if request_id in self._request_ids:
                    return self._blocked(ReasonCode.REQUEST_REPLAYED, "Request identity has already been processed.", {
                        "agent_id": agent_id, "tool_name": tool_name, "task_id": task_id, "trace_id": trace_id,
                        "execution_id": execution_id or "exec-replayed",
                    })
                self._request_ids.add(request_id)
        if not isinstance(arguments, dict):
            return self._blocked(ReasonCode.SCHEMA_INVALID, "Arguments must be an object.", {
                "agent_id": agent_id,
                "tool_name": tool_name,
                "task_id": task_id,
                "trace_id": trace_id,
                "execution_id": execution_id or "exec-invalid",
            })
        try:
            json.dumps(arguments, allow_nan=False)
        except (TypeError, ValueError):
            return self._blocked(ReasonCode.SCHEMA_INVALID, "Arguments must contain only JSON values.", {
                "agent_id": agent_id,
                "tool_name": tool_name,
                "task_id": task_id,
                "trace_id": trace_id,
                "execution_id": execution_id or "exec-invalid",
            })
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
        parameters = self.parameter_validator.validate(arguments, tool)
        consistency = self.task_consistency.evaluate(task_id, tool_name)
        risk = self.risk.assess(tool, parameters, consistency)
        decision = self.decision_service.decide(
            agent_id=agent_id,
            tool_name=tool_name,
            task_id=task_id,
            trace_id=trace_id,
            execution_id=resolved_execution_id,
            parameters=parameters,
            risk=risk,
            task_consistent=consistency.value == "CONSISTENT",
        )
        if decision.decision in {DecisionOutcome.ALLOW, DecisionOutcome.WARN, DecisionOutcome.REQUIRE_APPROVAL}:
            self._authorized_fingerprints[resolved_execution_id] = self._decision_fingerprint(decision, arguments)
        return decision

    def execute(
        self,
        agent_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        task_id: str,
        trace_id: str,
        token: str,
        execution_id: str | None = None,
        request_id: str | None = None,
    ) -> tuple[Decision, dict[str, Any] | None]:
        decision = self.authorize(agent_id, tool_name, arguments, task_id, trace_id, token, execution_id, request_id)
        return self.execute_authorized(decision, agent_id, tool_name, arguments)

    def reset_replay_state(self) -> None:
        with self._execution_lock:
            self._request_ids.clear()

    def execute_authorized(
        self,
        decision: Decision,
        agent_id: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[Decision, dict[str, Any] | None]:
        if decision.decision not in {DecisionOutcome.ALLOW, DecisionOutcome.WARN}:
            return decision, None
        if decision.agent_id != agent_id or decision.tool_name != tool_name:
            return self._blocked(
                ReasonCode.TOKEN_INVALID,
                "Execution fields do not match the authorization decision.",
                {
                    "agent_id": agent_id,
                    "tool_name": tool_name,
                    "task_id": decision.task_id,
                    "trace_id": decision.trace_id,
                    "execution_id": decision.execution_id,
                },
            ), None
        expected = self._authorized_fingerprints.get(decision.execution_id)
        if expected != self._decision_fingerprint(decision, arguments):
            return self._blocked(
                ReasonCode.TOKEN_INVALID,
                "Execution receipt was not issued by this Gateway.",
                {
                    "agent_id": agent_id,
                    "tool_name": tool_name,
                    "task_id": decision.task_id,
                    "trace_id": decision.trace_id,
                    "execution_id": decision.execution_id,
                },
            ), None
        with self._execution_lock:
            if decision.execution_id in self._executed_ids or decision.execution_id in self._claimed_ids:
                return self._blocked(
                    ReasonCode.EXECUTION_DUPLICATE,
                    "Execution identity has already been used.",
                    {
                        "agent_id": agent_id,
                        "tool_name": tool_name,
                        "task_id": decision.task_id,
                        "trace_id": decision.trace_id,
                        "execution_id": decision.execution_id,
                    },
                ), None
            self._claimed_ids.add(decision.execution_id)
        if self.executor is None:
            raise RuntimeError("Gateway executor boundary is not configured.")
        receipt = AuthorizationReceipt(decision.decision, agent_id, tool_name, arguments, decision.execution_id)
        result = self.executor.execute(self.executor.issue_grant(receipt, self.executor_issuer))
        with self._execution_lock:
            self._claimed_ids.discard(decision.execution_id)
            self._executed_ids.add(decision.execution_id)
        return decision, result

    @staticmethod
    def _execution_id(agent_id: str, tool_name: str, arguments: dict[str, Any], task_id: str, trace_id: str) -> str:
        payload = json.dumps([agent_id, tool_name, arguments, task_id, trace_id], sort_keys=True, separators=(",", ":"), default=lambda _: "<unsupported>")
        return f"exec-{hashlib.sha256(payload.encode()).hexdigest()[:24]}"

    @staticmethod
    def _decision_fingerprint(decision: Decision, arguments: dict[str, Any]) -> str:
        payload = json.dumps(
            [decision.decision.value, decision.agent_id, decision.tool_name, decision.task_id, decision.trace_id, decision.execution_id, arguments],
            sort_keys=True,
            separators=(",", ":"),
            default=lambda _: "<unsupported>",
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    @staticmethod
    def _blocked(code: ReasonCode, message: str, context: dict[str, str]) -> Decision:
        reason = Reason(code=code, message=message, severity="critical", source="gateway")
        return Decision(decision=DecisionOutcome.BLOCK, reasons=(reason,), **context)
