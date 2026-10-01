import hashlib
import json
from collections.abc import Mapping
from typing import Any

import rfc8785


GENESIS_HASH = "0" * 64


def canonical_event(event_without_hash_fields: Mapping[str, Any]) -> bytes:
    return rfc8785.dumps(dict(event_without_hash_fields))


def audit_hash(previous_hash: str, event_without_hash_fields: Mapping[str, Any]) -> str:
    if len(previous_hash) != 64:
        raise ValueError("previous_hash must be a 64-character SHA-256 digest")
    try:
        previous_bytes = bytes.fromhex(previous_hash)
    except ValueError as error:
        raise ValueError("previous_hash must be hexadecimal") from error
    return hashlib.sha256(previous_bytes + b"." + canonical_event(event_without_hash_fields)).hexdigest()


def audit_event_json(event_without_hash_fields: Mapping[str, Any]) -> str:
    return json.dumps(dict(event_without_hash_fields), ensure_ascii=False, separators=(",", ":"), sort_keys=True)
