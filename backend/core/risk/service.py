from dataclasses import dataclass, field
from typing import Any

from backend.core.task_consistency.service import Consistency
from backend.core.threat_intel.models import EnrichedIndicator, ReputationLevel
from backend.core.tools.registry import ToolDefinition
from backend.core.validation.security import ParameterResult
from backend.shared.contracts import ReasonCode


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    factors: dict[str, int]
    hard_signal: bool = False
    hard_signal_reason: str | None = None
    threat_intel_details: list[dict[str, Any]] = field(default_factory=list)


class RiskService:
    def assess(
        self,
        tool: ToolDefinition,
        parameters: ParameterResult,
        consistency: Consistency,
        threat_intel_indicators: list[EnrichedIndicator] | None = None,
    ) -> RiskAssessment:
        tool_sensitivity = min(25, tool.sensitivity)
        data_sensitivity = min(20, tool.data_sensitivity)
        permission_deviation = 20 if consistency != Consistency.CONSISTENT else 0
        destination_risk = 15 if not parameters.valid else 0
        irreversibility = min(10, tool.irreversibility)
        behavioral_anomaly = min(10, tool.behavioral_anomaly)

        threat_intel_risk = 0
        hard_signal = tool.hard_signal
        hard_signal_reason = tool.hard_signal_reason
        threat_details: list[dict[str, Any]] = []

        if threat_intel_indicators:
            max_threat_score = 0.0
            for ind in threat_intel_indicators:
                threat_details.append({
                    "indicator": ind.indicator,
                    "type": ind.indicator_type.value,
                    "reputation": ind.overall_reputation.value,
                    "risk_score": ind.overall_risk_score,
                    "confidence": ind.max_confidence,
                    "provider": ind.primary_provider,
                    "tags": ind.tags,
                    "summary": ind.summary,
                })
                if ind.overall_risk_score > max_threat_score:
                    max_threat_score = ind.overall_risk_score

                if ind.overall_reputation == ReputationLevel.MALICIOUS or ind.overall_risk_score >= 75.0:
                    hard_signal = True
                    hard_signal_reason = ReasonCode.THREAT_INTEL_MALICIOUS.value

            if not hard_signal and max_threat_score >= 35.0:
                threat_intel_risk = int(min(25, max_threat_score * 0.25))

        base_score = (
            tool_sensitivity
            + data_sensitivity
            + permission_deviation
            + destination_risk
            + behavioral_anomaly
            + irreversibility
            + threat_intel_risk
        )
        score = min(100, base_score)

        if hard_signal:
            score = max(score, 90)

        factors = {
            "tool_sensitivity": tool_sensitivity,
            "data_sensitivity": data_sensitivity,
            "permission_deviation": permission_deviation,
            "destination_risk": destination_risk,
            "behavioral_anomaly": behavioral_anomaly,
            "irreversibility": irreversibility,
        }
        if threat_intel_risk > 0:
            factors["threat_intelligence"] = threat_intel_risk

        return RiskAssessment(
            score=score,
            factors=factors,
            hard_signal=hard_signal,
            hard_signal_reason=hard_signal_reason,
            threat_intel_details=threat_details,
        )
