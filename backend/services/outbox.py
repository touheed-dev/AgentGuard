import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from backend.infrastructure.models import OutboxRecord
from backend.shared.contracts import EventType


async def enqueue(
    session: AsyncSession,
    event_type: EventType | str,
    aggregate_id: str,
    payload: dict[str, Any],
) -> OutboxRecord:
    record = OutboxRecord(
        outbox_id=str(uuid4()),
        event_type=EventType(event_type).value,
        aggregate_id=aggregate_id,
        payload_json=json.dumps(payload, sort_keys=True, separators=(",", ":")),
        created_at=datetime.now(timezone.utc),
    )
    session.add(record)
    await session.flush()
    return record
