"""AgentGuard SDK — Exceptions.

All exceptions raised by the SDK to give agents and developers
clear, typed error information without leaking internal Gateway state.
"""


class AgentGuardError(Exception):
    """Base class for all AgentGuard SDK errors."""


class ConnectionError(AgentGuardError):
    """Gateway is unreachable or the connection timed out.

    The system is fail-closed: if the Gateway cannot be reached,
    the action is NOT executed.
    """


class AuthenticationError(AgentGuardError):
    """The agent token is missing, invalid, or expired."""


class ValidationError(AgentGuardError):
    """The request was structurally invalid (bad parameters, missing fields)."""


class BlockedActionError(AgentGuardError):
    """The Gateway returned BLOCK.  Tool execution did not occur.

    Attributes
    ----------
    trace_id : str
        Trace identifier for post-incident investigation.
    reason_codes : list[str]
        Machine-readable reason codes from the Gateway.
    """

    def __init__(self, message: str, trace_id: str = "", reason_codes: list[str] | None = None) -> None:
        super().__init__(message)
        self.trace_id = trace_id
        self.reason_codes = reason_codes or []


class ApprovalRequiredError(AgentGuardError):
    """The action requires human approval before execution.

    Attributes
    ----------
    trace_id : str
    execution_id : str
    approval_id : str
        ID of the pending approval record shown in the dashboard.
    reason_codes : list[str]
    risk : dict
    """

    def __init__(
        self,
        message: str,
        trace_id: str = "",
        execution_id: str = "",
        approval_id: str = "",
        reason_codes: list[str] | None = None,
        risk: dict | None = None,
    ) -> None:
        super().__init__(message)
        self.trace_id = trace_id
        self.execution_id = execution_id
        self.approval_id = approval_id
        self.reason_codes = reason_codes or []
        self.risk = risk or {}


class QuarantinedAgentError(AgentGuardError):
    """The agent has been quarantined.  All actions are blocked until reset."""


class ExecutionError(AgentGuardError):
    """The tool action was authorized but execution encountered an error."""


class TimeoutError(AgentGuardError):
    """The Gateway did not respond within the configured timeout."""


class MalformedResponseError(AgentGuardError):
    """The Gateway returned a response that the SDK could not parse."""
