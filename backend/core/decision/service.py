from backend.core.risk.service import RiskAssessment
from backend.core.validation.security import ParameterResult
from backend.shared.contracts import Decision, DecisionOutcome, Reason, ReasonCode


class DecisionService:
    def decide(
        self,
        agent_id: str,
        tool_name: str,
        task_id: str,
        trace_id: str,
        execution_id: str,
        parameters: ParameterResult,
        risk: RiskAssessment,
        task_consistent: bool,
    ) -> Decision:
        reasons: list[Reason] = []
        for code, message in parameters.reasons:
            reasons.append(Reason(code=code, message=message, severity="critical", source="parameter_validator"))
        if risk.hard_signal:
            hard_code = ReasonCode.CUMULATIVE_RISK_HIGH
            if risk.hard_signal_reason in {code.value for code in ReasonCode}:
                hard_code = ReasonCode(risk.hard_signal_reason)
            reasons.append(Reason(code=hard_code, message=risk.hard_signal_reason or "Critical risk signal detected.", severity="critical", source="risk_engine"))
        if reasons:
            return Decision(
                decision=DecisionOutcome.BLOCK,
                agent_id=agent_id,
                tool_name=tool_name,
                task_id=task_id,
                trace_id=trace_id,
                execution_id=execution_id,
                reasons=tuple(reasons),
                risk={"score": risk.score, "factors": risk.factors},
                parameter_result={"valid": parameters.valid},
            )
        if not task_consistent:
            reasons.append(Reason(code=ReasonCode.TASK_INCONSISTENT, message="Action is outside the task's normal tool set.", severity="warning", source="task_consistency"))
        advisory_only_high_score = not task_consistent and risk.score - risk.factors.get("permission_deviation", 0) < 75
        if risk.hard_signal:
            outcome = DecisionOutcome.BLOCK
        elif risk.score >= 75 and advisory_only_high_score:
            outcome = DecisionOutcome.REQUIRE_APPROVAL
        elif risk.score >= 75:
            outcome = DecisionOutcome.BLOCK
        elif risk.score >= 50:
            outcome = DecisionOutcome.REQUIRE_APPROVAL
        elif risk.score >= 30 or reasons:
            outcome = DecisionOutcome.WARN
        else:
            outcome = DecisionOutcome.ALLOW
        return Decision(
            decision=outcome,
            agent_id=agent_id,
            tool_name=tool_name,
            task_id=task_id,
            trace_id=trace_id,
            execution_id=execution_id,
            reasons=tuple(reasons),
            risk={"score": risk.score, "factors": risk.factors},
        )