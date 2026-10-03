import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from uuid import uuid4


class IncidentState(StrEnum):
    DETECTED = "DETECTED"
    ANALYZED = "ANALYZED"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"


VALID_TRANSITIONS: dict[IncidentState, set[IncidentState]] = {
    IncidentState.DETECTED: {IncidentState.ANALYZED, IncidentState.CONTAINED, IncidentState.RESOLVED},
    IncidentState.ANALYZED: {IncidentState.CONTAINED, IncidentState.RESOLVED},
    IncidentState.CONTAINED: {IncidentState.RESOLVED},
    IncidentState.RESOLVED: set(),
}


@dataclass(frozen=True)
class Incident:
    incident_id: str
    agent_id: str
    task_id: str
    trace_id: str
    reason_code: str
    severity: str
    state: IncidentState
    created_at: float = field(default_factory=time.time)
    details: dict[str, Any] = field(default_factory=dict)
    dedup_key: str = ""


@dataclass(frozen=True)
class SecuritySOSEvent:
    event_id: str
    incident_id: str
    agent_id: str
    task_id: str
    trace_id: str
    reason_code: str
    severity: str
    timestamp: float
    details: dict[str, Any] = field(default_factory=dict)
    event_type: str = "security.sos"


class IncidentService:
    def __init__(self) -> None:
        self._incidents: dict[str, Incident] = {}
        self._dedup_map: dict[str, str] = {}
        self._sos_events: list[SecuritySOSEvent] = []
        self._subscribers: list[Any] = []

    def create(
        self,
        agent_id: str,
        task_id: str,
        trace_id: str,
        reason_code: str,
        severity: str,
        details: dict[str, Any] | None = None,
        now: float | None = None,
    ) -> Incident:
        # Deduplication key across deterministic triggering context
        dedup_key = f"{agent_id}:{task_id}:{trace_id}:{reason_code}"
        existing_id = self._dedup_map.get(dedup_key)
        if existing_id is not None and existing_id in self._incidents:
            return self._incidents[existing_id]

        incident_id = str(uuid4())
        incident = Incident(
            incident_id=incident_id,
            agent_id=agent_id,
            task_id=task_id,
            trace_id=trace_id,
            reason_code=reason_code,
            severity=severity,
            state=IncidentState.DETECTED,
            created_at=time.time() if now is None else float(now),
            details=details or {},
            dedup_key=dedup_key,
        )
        self._incidents[incident_id] = incident
        self._dedup_map[dedup_key] = incident_id

        if severity == "critical":
            sos = SecuritySOSEvent(
                event_id=str(uuid4()),
                incident_id=incident_id,
                agent_id=agent_id,
                task_id=task_id,
                trace_id=trace_id,
                reason_code=reason_code,
                severity=severity,
                timestamp=incident.created_at,
                details=details or {},
            )
            self._sos_events.append(sos)
            for sub in list(self._subscribers):
                try:
                    sub(sos)
                except Exception:
                    pass

        return incident

    def transition(self, incident_id: str, new_state: IncidentState) -> Incident:
        incident = self._incidents[incident_id]
        if new_state not in VALID_TRANSITIONS.get(incident.state, set()):
            raise ValueError(f"Invalid incident transition from {incident.state} to {new_state}")
        updated = Incident(
            incident_id=incident.incident_id,
            agent_id=incident.agent_id,
            task_id=incident.task_id,
            trace_id=incident.trace_id,
            reason_code=incident.reason_code,
            severity=incident.severity,
            state=new_state,
            created_at=incident.created_at,
            details=incident.details,
            dedup_key=incident.dedup_key,
        )
        self._incidents[incident_id] = updated
        return updated

    def get(self, incident_id: str) -> Incident | None:
        return self._incidents.get(incident_id)

    def list(self) -> tuple[Incident, ...]:
        return tuple(self._incidents.values())

    def get_sos_events(self) -> tuple[SecuritySOSEvent, ...]:
        return tuple(self._sos_events)

    def add_sos_subscriber(self, callback: Any) -> None:
        self._subscribers.append(callback)

    def remove_sos_subscriber(self, callback: Any) -> None:
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    def clear_sos_events(self) -> None:
        self._sos_events.clear()
