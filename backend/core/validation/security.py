import ipaddress
import json
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlparse

from backend.core.tools.registry import ToolDefinition
from backend.shared.contracts import ReasonCode


@dataclass(frozen=True)
class ParameterResult:
    valid: bool
    reasons: tuple[tuple[ReasonCode, str], ...] = ()


class ParameterValidator:
    def validate(self, arguments: dict[str, Any], tool: ToolDefinition) -> ParameterResult:
        reasons: list[tuple[ReasonCode, str]] = []
        try:
            encoded = json.dumps(arguments, ensure_ascii=False)
        except (TypeError, ValueError):
            return ParameterResult(False, ((ReasonCode.SCHEMA_INVALID, "Arguments are not JSON-serializable."),))
        if len(encoded.encode("utf-8")) > tool.max_payload_bytes:
            reasons.append((ReasonCode.SCHEMA_INVALID, "Request payload exceeds the tool limit."))
        for key, value in self._strings(arguments):
            normalized = value
            for _ in range(8):
                decoded = unquote(normalized)
                if decoded == normalized:
                    break
                normalized = decoded
            if ".." in normalized.replace("\\", "/").split("/"):
                reasons.append((ReasonCode.PATH_TRAVERSAL, f"Argument {key} contains path traversal."))
            if any(marker in normalized.lower() for marker in ("/etc/passwd", "/etc/shadow", "shadow", ".env", "credentials", "secret", "id_rsa")):
                reasons.append((ReasonCode.SENSITIVE_RESOURCE, f"Argument {key} targets a protected resource."))
            if key in tool.command_fields and any(ord(character) < 32 for character in normalized):
                reasons.append((ReasonCode.SCHEMA_INVALID, "Control characters are not permitted in commands."))
            if key in tool.command_fields and any(token in normalized for token in (";", "&&", "||", "|", "`", "$" + "(", "&", ">", "<")):
                reasons.append((ReasonCode.SCHEMA_INVALID, "Shell metacharacters are not permitted."))
            if key in {"url", "uri", "destination"}:
                reasons.extend(self._validate_url(key, value, tool))
        return ParameterResult(not reasons, tuple(reasons))

    @staticmethod
    def _strings(value: Any, prefix: str = "") -> list[tuple[str, str]]:
        if isinstance(value, dict):
            result: list[tuple[str, str]] = []
            for key, child in value.items():
                result.extend(ParameterValidator._strings(child, str(key)))
            return result
        if isinstance(value, list):
            return [item for child in value for item in ParameterValidator._strings(child, prefix)]
        return [(prefix, value)] if isinstance(value, str) else []

    @staticmethod
    def _validate_url(key: str, value: str, tool: ToolDefinition) -> list[tuple[ReasonCode, str]]:
        try:
            parsed = urlparse(value)
        except ValueError:
            return [(ReasonCode.DESTINATION_NOT_ALLOWLISTED, f"Argument {key} is not an allowed URL.")]
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return [(ReasonCode.DESTINATION_NOT_ALLOWLISTED, f"Argument {key} is not an allowed URL.")]
        if parsed.hostname.lower() == "localhost" or not tool.allowed_destinations or parsed.hostname not in tool.allowed_destinations:
            return [(ReasonCode.DESTINATION_NOT_ALLOWLISTED, "Destination is not allowlisted.")]
        try:
            port = parsed.port or 443
        except ValueError:
            return [(ReasonCode.DESTINATION_NOT_ALLOWLISTED, "Destination port is invalid.")]
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            if parsed.hostname.isdigit():
                return [(ReasonCode.DESTINATION_NOT_ALLOWLISTED, "Numeric destination forms are blocked.")]
            try:
                resolved = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)}
            except (OSError, ValueError):
                return [(ReasonCode.DESTINATION_NOT_ALLOWLISTED, "Destination could not be resolved safely.")]
            if any(ParameterValidator._is_private_ip(item) for item in resolved):
                return [(ReasonCode.DESTINATION_NOT_ALLOWLISTED, "Allowlisted destination resolves to a private address.")]
            return []
        if ParameterValidator._is_private_ip(address):
            return [(ReasonCode.DESTINATION_NOT_ALLOWLISTED, "Private or reserved destinations are blocked.")]
        return []

    @staticmethod
    def _is_private_ip(value: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        address = ipaddress.ip_address(value)
        return not address.is_global
