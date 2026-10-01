import hashlib
import json
import time
from threading import Lock
from typing import Any, Protocol

import jwt

from backend.core.approval.service import ApprovalService, ApprovalStatus
from backend.core.capabilities.service import CapabilityService
from backend.core.breaker.service import BreakerService
from backend.core.communication.service import CommunicationResult, CommunicationService
from backend.core.incidents.service import IncidentService
from backend.core.identity.models import AgentStatus, SecurityState
from backend.core.decision.service import DecisionService
from backend.core.identity.registry import AgentRegistry
from backend.core.identity.service import IdentityService
from backend.core.risk.service import RiskService
from backend.core.task_consistency.service import TaskConsistencyService
from backend.core.tools.registry import ToolRegistry
from backend.core.validation.schema import validate_object
from backend.core.validation.security import ParameterResult, ParameterValidator
from backend.deception.honey import HoneyAssetRegistry
from backend.services.executor import UnknownExecutionError
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
        honey_assets: HoneyAssetRegistry | None = None,
        breaker: BreakerService | None = None,
        incidents: IncidentService | None = None,
        approvals: ApprovalService | None = None,
        communication: CommunicationService | None = None,
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
        self.honey_assets = honey_assets or HoneyAssetRegistry()
        self.breaker = breaker or BreakerService()
        self.incidents = incidents or IncidentService()
        self.approvals = approvals or ApprovalService()
        self.communication = communication or CommunicationService(agents=agents)
        self._executed_ids: set[str] = set()
        self._authorized_fingerprints: dict[str, str] = {}
        self._claimed_ids: set[str] = set()
        self._request_ids: set[str] = set()
        self._pending_approvals: dict[str, str] = {}  # execution_id -> approval_id
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
        now: float | None = None,
    ) -> Decision:
        current_time = time.time() if now is None else float(now)
        # Check request ID replay if provided
        if request_id is not None:
            with self._execution_lock:
                if request_id in self._request_ids:
                    return self._blocked(ReasonCode.REQUEST_REPLAYED, "Request identity has already been processed.", {
                        "agent_id": agent_id, "tool_name": tool_name, "task_id": task_id, "trace_id": trace_id,
                        "execution_id": execution_id or "exec-replayed",
                    })

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

        # Check circuit breaker before further evaluation
        breaker_state = self.breaker.check(agent_id, now=current_time)
        if breaker_state.suspended or agent.status == AgentStatus.SUSPENDED:
            return self._blocked(ReasonCode.BREAKER_TRIPPED, "Circuit breaker tripped: agent is suspended.", context)

        # Honey asset check
        honey_asset = self.honey_assets.scan(tool_name, arguments)
        if honey_asset is not None:
            self.agents.replace(agent.model_copy(update={
                "security_state": SecurityState.QUARANTINED,
                "status": AgentStatus.SUSPENDED,
                "security_epoch": agent.security_epoch + 1,
            }))
            self.incidents.create(agent_id, task_id, trace_id, ReasonCode.HONEY_ASSET_TOUCHED.value, "critical", now=current_time)
            self.breaker.record(agent_id, "critical", now=current_time)
            return self._blocked(ReasonCode.HONEY_ASSET_TOUCHED, "Registered honey asset was referenced.", context)

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
            # Capability violation can trip breaker if repeated or high
            b_res = self.breaker.record(agent_id, "high", now=current_time)
            if b_res.suspended:
                self.agents.replace(agent.model_copy(update={"status": AgentStatus.SUSPENDED}))
            self.incidents.create(agent_id, task_id, trace_id, capability.code.value if capability.code else ReasonCode.CAPABILITY_DENIED.value, "high", now=current_time)
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

        # Handle decisions and breaker recording
        if decision.decision == DecisionOutcome.BLOCK:
            sev = "critical" if risk.hard_signal else "high" if risk.score >= 70 else "medium"
            b_res = self.breaker.record(agent_id, sev, now=current_time)
            if b_res.suspended:
                self.agents.replace(agent.model_copy(update={"status": AgentStatus.SUSPENDED}))
            code_val = decision.reasons[0].code.value if decision.reasons else ReasonCode.CUMULATIVE_RISK_HIGH.value
            self.incidents.create(agent_id, task_id, trace_id, code_val, sev, now=current_time)
            return decision

        if decision.decision == DecisionOutcome.REQUIRE_APPROVAL:
            # Create a pending approval with action fingerprint
            approval_payload = {
                "agent_id": agent_id,
                "tool_name": tool_name,
                "arguments": arguments,
                "task_id": task_id,
                "trace_id": trace_id,
                "execution_id": resolved_execution_id,
            }
            # Default TTL: 300 seconds
            approval = self.approvals.create(approval_payload, expires_at=current_time + 300.0)
            self._pending_approvals[resolved_execution_id] = approval.approval_id

        # Only consume request_id upon valid authorization (allowing ALLOW, WARN, REQUIRE_APPROVAL)
        if request_id is not None:
            with self._execution_lock:
                self._request_ids.add(request_id)

        if decision.decision in {DecisionOutcome.ALLOW, DecisionOutcome.WARN, DecisionOutcome.REQUIRE_APPROVAL}:
            self._authorized_fingerprints[resolved_execution_id] = self._decision_fingerprint(decision, arguments)

        return decision

    def authorize_communication(
        self,
        sender_id: str,
        recipient_id: str,
        task_id: str | None = None,
        capability: str | None = None,
    ) -> CommunicationResult:
        result = self.communication.authorize(sender_id, recipient_id, task_id, capability)
        if not result.allowed:
            # Record security incident for unauthorized communication attempt
            self.incidents.create(
                sender_id,
                task_id or "unspecified",
                "comm-trace",
                ReasonCode.COMM_PATH_DENIED.value,
                "high",
                details={"recipient_id": recipient_id, "reason": result.reason},
            )
            b_res = self.breaker.record(sender_id, "high")
            if b_res.suspended:
                sender = self.agents.get(sender_id)
                if sender is not None:
                    self.agents.replace(sender.model_copy(update={"status": AgentStatus.SUSPENDED}))
        return result

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
        approval_id: str | None = None,
        now: float | None = None,
    ) -> tuple[Decision, dict[str, Any] | None]:
        decision = self.authorize(agent_id, tool_name, arguments, task_id, trace_id, token, execution_id, request_id, now=now)
        return self.execute_authorized(decision, agent_id, tool_name, arguments, approval_id=approval_id, now=now)

    def reset_replay_state(self) -> None:
        with self._execution_lock:
            self._request_ids.clear()
            self._executed_ids.clear()
            self._claimed_ids.clear()
            self._authorized_fingerprints.clear()
            self._pending_approvals.clear()

    def execute_authorized(
        self,
        decision: Decision,
        agent_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        approval_id: str | None = None,
        now: float | None = None,
    ) -> tuple[Decision, dict[str, Any] | None]:
        current_time = time.time() if now is None else float(now)
        context = {
            "agent_id": agent_id,
            "tool_name": tool_name,
            "task_id": decision.task_id,
            "trace_id": decision.trace_id,
            "execution_id": decision.execution_id,
        }

        # 1. First verify execution duplicate identity before any other logic
        with self._execution_lock:
            if decision.execution_id in self._executed_ids or decision.execution_id in self._claimed_ids:
                return self._blocked(ReasonCode.EXECUTION_DUPLICATE, "Execution identity has already been used.", context), None

        # 2. Check circuit breaker before execution
        breaker_state = self.breaker.check(agent_id, now=current_time)
        if breaker_state.suspended:
            return self._blocked(ReasonCode.BREAKER_TRIPPED, "Circuit breaker tripped: agent is suspended.", context), None

        # Check approval requirement
        if decision.decision == DecisionOutcome.REQUIRE_APPROVAL:
            app_id = approval_id or self._pending_approvals.get(decision.execution_id)
            if not app_id:
                return self._blocked(ReasonCode.CAPABILITY_DENIED, "Action requires approval before execution.", context), None
            approval = self.approvals.get(app_id)
            if approval is None:
                return self._blocked(ReasonCode.CAPABILITY_DENIED, "Approval record not found.", context), None

            current_payload = {
                "agent_id": agent_id,
                "tool_name": tool_name,
                "arguments": arguments,
                "task_id": decision.task_id,
                "trace_id": decision.trace_id,
                "execution_id": decision.execution_id,
            }
            if current_time >= approval.expires_at:
                return self._blocked(ReasonCode.APPROVAL_STALE, "Approval has expired.", context), None
            if self.approvals.fingerprint(current_payload) != approval.fingerprint:
                return self._blocked(ReasonCode.APPROVAL_STALE, "Action fields do not match approved fingerprint.", context), None
            if approval.status == ApprovalStatus.REJECTED:
                return self._blocked(ReasonCode.CAPABILITY_DENIED, "Action approval was rejected.", context), None
            if approval.status != ApprovalStatus.APPROVED:
                return self._blocked(ReasonCode.CAPABILITY_DENIED, "Action has not been approved.", context), None
        elif decision.decision not in {DecisionOutcome.ALLOW, DecisionOutcome.WARN}:
            return decision, None

        with self._execution_lock:
            if decision.execution_id in self._executed_ids or decision.execution_id in self._claimed_ids:
                return self._blocked(ReasonCode.EXECUTION_DUPLICATE, "Execution identity has already been used.", context), None

        if decision.agent_id != agent_id or decision.tool_name != tool_name:
            return self._blocked(ReasonCode.TOKEN_INVALID, "Execution fields do not match authorization decision.", context), None

        expected = self._authorized_fingerprints.get(decision.execution_id)
        if expected != self._decision_fingerprint(decision, arguments):
            return self._blocked(ReasonCode.TOKEN_INVALID, "Execution receipt was not issued by this Gateway.", context), None

        with self._execution_lock:
            if decision.execution_id in self._executed_ids or decision.execution_id in self._claimed_ids:
                return self._blocked(ReasonCode.EXECUTION_DUPLICATE, "Execution identity has already been used.", context), None
            self._claimed_ids.add(decision.execution_id)

        if self.executor is None:
            raise RuntimeError("Gateway executor boundary is not configured.")

        # Once verified and approved by Gateway, issue execution grant with ALLOW outcome
        execution_outcome = DecisionOutcome.ALLOW if decision.decision in {DecisionOutcome.ALLOW, DecisionOutcome.REQUIRE_APPROVAL} else decision.decision
        receipt = AuthorizationReceipt(execution_outcome, agent_id, tool_name, arguments, decision.execution_id)
        try:
            result = self.executor.execute(self.executor.issue_grant(receipt, self.executor_issuer))
        except UnknownExecutionError:
            with self._execution_lock:
                self._claimed_ids.discard(decision.execution_id)
                self._executed_ids.add(decision.execution_id)
            return self._blocked(ReasonCode.RESULT_UNKNOWN, "Execution outcome cannot be reliably determined.", context), None
        except Exception:
            with self._execution_lock:
                self._claimed_ids.discard(decision.execution_id)
            raise

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
