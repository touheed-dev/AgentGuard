import pytest

from backend.apps.gateway.runtime import create_runtime
from backend.services.docker_executor import DockerSandboxProfile, HardenedDockerExecutor
from backend.services.executor import UnknownExecutionError
from backend.shared.contracts import AuthorizationReceipt, DecisionOutcome, ReasonCode


def test_docker_sandbox_profile_security_defaults() -> None:
    profile = DockerSandboxProfile()
    assert profile.read_only_root is True
    assert profile.network_disabled is True
    assert profile.user == "10001:10001"
    assert profile.cap_drop == ("ALL",)
    assert profile.no_new_privileges is True
    assert profile.docker_socket_mounted is False
    assert profile.cpu_limit == 1.0
    assert profile.memory_limit == "512m"
    assert profile.pids_limit == 64
    assert "/tmp" in profile.tmpfs
    assert "noexec" in profile.tmpfs["/tmp"]

    args = profile.to_docker_run_args("sandbox-img", ["echo", "1"])
    assert args["read_only"] is True
    assert args["network_mode"] == "none"
    assert args["user"] == "10001:10001"
    assert args["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in args["security_opt"]
    assert args["mem_limit"] == "512m"


def test_docker_socket_mounting_is_forbidden() -> None:
    unsafe_profile = DockerSandboxProfile(docker_socket_mounted=True)
    with pytest.raises(PermissionError, match="Docker socket mounting is strictly forbidden"):
        unsafe_profile.to_docker_run_args("img", ["cmd"])


def test_hardened_docker_executor_requires_gateway_grant() -> None:
    issuer = object()
    executor = HardenedDockerExecutor(issuer)
    receipt = AuthorizationReceipt(
        DecisionOutcome.ALLOW, "coder-01", "echo", {"value": "secure"}, "exec-doc-1"
    )

    # Calling execute without a grant issued by issuer fails
    with pytest.raises(PermissionError):
        executor.execute(receipt)

    # Valid grant execution
    granted = executor.issue_grant(receipt, issuer)
    result = executor.execute(granted)
    assert result["tool"] == "echo"
    assert result["sandbox"] == "hardened_docker"
    assert executor.execution_count == 1
    assert executor.last_run_config is not None
    assert executor.last_run_config["network_mode"] == "none"
    assert executor.last_run_config["read_only"] is True


def test_hardened_docker_executor_unknown_result_and_failure() -> None:
    issuer = object()
    executor = HardenedDockerExecutor(issuer)
    receipt = AuthorizationReceipt(
        DecisionOutcome.ALLOW, "coder-01", "execute_code", {"code": "run()"}, "exec-doc-2"
    )

    # Failure handling
    executor.force_failure = True
    granted_fail = executor.issue_grant(receipt, issuer)
    with pytest.raises(RuntimeError):
        executor.execute(granted_fail)

    # Unknown result handling
    executor.force_failure = False
    executor.force_unknown = True
    granted_unk = executor.issue_grant(receipt, issuer)
    with pytest.raises(UnknownExecutionError):
        executor.execute(granted_unk)
