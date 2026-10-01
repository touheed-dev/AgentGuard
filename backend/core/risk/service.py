from dataclasses import dataclass

from backend.core.task_consistency.service import Consistency
from backend.core.tools.registry import ToolDefinition
from backend.core.validation.security import ParameterResult


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    factors: dict[str, int]
    hard_signal: bool = False
    hard_signal_reason: str | None = None


class RiskService:
    def assess(self, tool: ToolDefinition, parameters: ParameterResult, consistency: Consistency) -> RiskAssessment:
        tool_sensitivity = min(25, tool.sensitivity)
        data_sensitivity = min(20, tool.data_sensitivity)
        permission_deviation = 20 if consistency != Consistency.CONSISTENT else 0
        destination_risk = 15 if not parameters.valid else 0
        irreversibility = min(10, tool.irreversibility)
        behavioral_anomaly = min(10, tool.behavioral_anomaly)
        score = min(100, tool_sensitivity + data_sensitivity + permission_deviation + destination_risk + behavioral_anomaly + irreversibility)
        return RiskAssessment(
            score=max(score, 90) if tool.hard_signal else score,
            factors={
                "tool_sensitivity": tool_sensitivity,
                "data_sensitivity": data_sensitivity,
                "permission_deviation": permission_deviation,
                "destination_risk": destination_risk,
                "behavioral_anomaly": behavioral_anomaly,
                "irreversibility": irreversibility,
            },
            hard_signal=tool.hard_signal,
            hard_signal_reason=tool.hard_signal_reason,
        )
