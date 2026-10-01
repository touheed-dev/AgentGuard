import time
from collections import deque
from dataclasses import dataclass


@dataclass(frozen=True)
class BreakerResult:
    tripped: bool
    suspended: bool
    severity: str


class BreakerService:
    def __init__(self) -> None:
        self._violations: dict[str, deque[tuple[float, str]]] = {}

    def record(self, agent_id: str, severity: str, now: float | None = None) -> BreakerResult:
        current_time = time.time() if now is None else float(now)
        events = self._violations.setdefault(agent_id, deque())
        events.append((current_time, severity))
        while events and events[0][0] < current_time - 60.0:
            events.popleft()
        critical = any(level == "critical" for _, level in events)
        high = sum(level == "high" for _, level in events)
        medium = sum(level == "medium" for _, level in events)
        suspended = critical or high >= 2
        tripped = critical or suspended or medium >= 3
        sev = "critical" if critical else "high" if suspended else "medium"
        return BreakerResult(tripped=tripped, suspended=suspended, severity=sev)

    def check(self, agent_id: str, now: float | None = None) -> BreakerResult:
        current_time = time.time() if now is None else float(now)
        events = self._violations.setdefault(agent_id, deque())
        while events and events[0][0] < current_time - 60.0:
            events.popleft()
        if not events:
            return BreakerResult(tripped=False, suspended=False, severity="low")
        critical = any(level == "critical" for _, level in events)
        high = sum(level == "high" for _, level in events)
        medium = sum(level == "medium" for _, level in events)
        suspended = critical or high >= 2
        tripped = critical or suspended or medium >= 3
        sev = "critical" if critical else "high" if suspended else "medium"
        return BreakerResult(tripped=tripped, suspended=suspended, severity=sev)
