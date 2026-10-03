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
    event_type: str
    incident_id: str
    agent_id: str
    reason_code: str
    severity: str
    created_at: float
    task_id: str = ""
    trace_id: str = ""
    details: dict[str, Any] = field(default_factory=dict)


class IncidentService:
    def __init__(self) -> None:
        self._incidents: dict[str, Incident] = {}
        self._dedup_map: dict[str, str] = {}
        self._sos_events: list[SecuritySOSEvent] = []
        self._sos_subscribers: list[Any] = []

    def add_sos_subscriber(self, callback: Any) -> None:
        if callback not in self._sos_subscribers:
            self._sos_subscribers.append(callback)

    def remove_sos_subscriber(self, callback: Any) -> None:
        if callback in self._sos_subscribers:
            self._sos_subscribers.remove(callback)

    def get_sos_events(self) -> list[SecuritySOSEvent]:
        return list(self._sos_events)

    def clear_sos_events(self) -> None:
        self._sos_events.clear()

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
        created_time = time.time() if now is None else float(now)
        incident = Incident(
            incident_id=incident_id,
            agent_id=agent_id,
            task_id=task_id,
            trace_id=trace_id,
            reason_code=reason_code,
            severity=severity,
            state=IncidentState.DETECTED,
            created_at=created_time,
            details=details or {},
            dedup_key=dedup_key,
        )
        self._incidents[incident_id] = incident
        self._dedup_map[dedup_key] = incident_id

        if severity == "critical":
            sos_event = SecuritySOSEvent(
                event_type="security.sos",
                incident_id=incident_id,
                agent_id=agent_id,
                reason_code=reason_code,
                severity=severity,
                created_at=created_time,
                task_id=task_id,
                trace_id=trace_id,
                details=details or {},
            )
            self._sos_events.append(sos_event)
            for subscriber in list(self._sos_subscribers):
                try:
                    subscriber(sos_event)
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

