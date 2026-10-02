import shutil
import subprocess
import pytest

from backend.apps.gateway.runtime import create_runtime
from backend.services.docker_executor import DockerSandboxProfile, HardenedDockerExecutor
from backend.services.executor import UnknownExecutionError
from backend.shared.contracts import AuthorizationReceipt, DecisionOutcome, ReasonCode


def is_docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        res = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
        return res.returncode == 0
    except Exception:
        return False


# =====================================================================
# 1. CONFIGURATION-LEVEL TESTS (Deterministic sandbox profile checks)
# =====================================================================

def test_docker_sandbox_profile_security_defaults() -> None:
    profile = DockerSandboxProfile()
    assert profile.read_only_root is True
    assert profile.network_disabled is True
    assert profile.user == "10001:10001"
    assert profile.cap_drop == ("ALL",)
    assert profile.cap_add == ()
    assert profile.privileged is False
    assert profile.no_new_privileges is True
    assert profile.docker_socket_mounted is False
    assert profile.cpu_limit == 1.0
    assert profile.memory_limit == "512m"
    assert profile.pids_limit == 64
    assert "/tmp" in profile.tmpfs
    assert "noexec" in profile.tmpfs["/tmp"]
    assert profile.pid_mode == "none"
    assert profile.ipc_mode == "none"

    args = profile.to_docker_run_args("sandbox-img", ["echo", "1"])
    assert args["read_only"] is True
    assert args["network_mode"] == "none"
    assert args["user"] == "10001:10001"
    assert args["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in args["security_opt"]
    assert "seccomp:default_hardened.json" in args["security_opt"]
    assert args["mem_limit"] == "512m"
    assert args["privileged"] is False

    cli_args = profile.to_docker_cli_args("sandbox-img", ["echo", "1"])
    assert "--read-only" in cli_args
    assert "--network" in cli_args and "none" in cli_args
    assert "--user" in cli_args and "10001:10001" in cli_args
    assert "--cap-drop" in cli_args and "ALL" in cli_args


def test_docker_socket_mounting_is_forbidden() -> None:
    with pytest.raises(PermissionError, match="Docker socket mounting is strictly forbidden"):
        DockerSandboxProfile(docker_socket_mounted=True).to_docker_run_args("img", ["cmd"])

    with pytest.raises(PermissionError, match="Mounting Docker socket via volumes is strictly forbidden"):
        DockerSandboxProfile(volumes=("/var/run/docker.sock:/var/run/docker.sock",)).to_docker_run_args("img", ["cmd"])


def test_unsafe_volumes_and_host_mounts_are_forbidden() -> None:
    with pytest.raises(PermissionError, match="Host path mount is forbidden"):
        DockerSandboxProfile(volumes=("/etc:/etc:ro",)).to_docker_run_args("img", ["cmd"])


def test_unconfined_and_missing_seccomp_are_forbidden() -> None:
    with pytest.raises(ValueError, match="Unconfined or empty seccomp profile is strictly forbidden"):
        DockerSandboxProfile(seccomp_profile="unconfined").to_docker_run_args("img", ["cmd"])

    with pytest.raises(ValueError, match="Unconfined or empty seccomp profile is strictly forbidden"):
        DockerSandboxProfile(seccomp_profile="").to_docker_run_args("img", ["cmd"])


def test_privileged_mode_is_forbidden() -> None:
    with pytest.raises(PermissionError, match="Privileged container mode is strictly forbidden"):
        DockerSandboxProfile(privileged=True).to_docker_run_args("img", ["cmd"])


def test_host_namespace_sharing_is_forbidden() -> None:
    with pytest.raises(PermissionError, match="Host PID namespace sharing is strictly forbidden"):
        DockerSandboxProfile(pid_mode="host").to_docker_run_args("img", ["cmd"])

    with pytest.raises(PermissionError, match="Host IPC namespace sharing is strictly forbidden"):
        DockerSandboxProfile(ipc_mode="host").to_docker_run_args("img", ["cmd"])


def test_network_access_and_read_only_violations_are_forbidden() -> None:
    with pytest.raises(PermissionError, match="Read-only root filesystem is mandatory"):
        DockerSandboxProfile(read_only_root=False).to_docker_run_args("img", ["cmd"])

    with pytest.raises(PermissionError, match="Network access is strictly forbidden"):
        DockerSandboxProfile(network_disabled=False).to_docker_run_args("img", ["cmd"])


def test_root_user_and_capability_escalation_are_forbidden() -> None:
    for root_val in ("0", "0:0", "root", ""):
        with pytest.raises(PermissionError, match="Root user execution is strictly forbidden"):
            DockerSandboxProfile(user=root_val).to_docker_run_args("img", ["cmd"])

    with pytest.raises(PermissionError, match="cap_drop ALL is mandatory"):
        DockerSandboxProfile(cap_drop=()).to_docker_run_args("img", ["cmd"])

    with pytest.raises(PermissionError, match="cap_add is strictly forbidden"):
        DockerSandboxProfile(cap_add=("NET_ADMIN",)).to_docker_run_args("img", ["cmd"])

    with pytest.raises(PermissionError, match="no-new-privileges is mandatory"):
        DockerSandboxProfile(no_new_privileges=False).to_docker_run_args("img", ["cmd"])


def test_tmpfs_noexec_and_resource_bounds_enforced() -> None:
    with pytest.raises(PermissionError, match="tmpfs /tmp with noexec mount option is mandatory"):
        DockerSandboxProfile(tmpfs={"/tmp": "rw,size=64m"}).to_docker_run_args("img", ["cmd"])

    with pytest.raises(ValueError, match="cpu_limit out of allowed sandbox bounds"):
        DockerSandboxProfile(cpu_limit=0.0).to_docker_run_args("img", ["cmd"])

    with pytest.raises(ValueError, match="pids_limit out of allowed sandbox bounds"):
        DockerSandboxProfile(pids_limit=500).to_docker_run_args("img", ["cmd"])


# =====================================================================
# 2. GATEWAY BOUNDARY GUARANTEES (Grant, issuer, tamper, replay)
# =====================================================================

def test_hardened_docker_executor_requires_gateway_grant() -> None:
    issuer = object()
    executor = HardenedDockerExecutor(issuer)
    receipt = AuthorizationReceipt(
        DecisionOutcome.ALLOW, "coder-01", "echo", {"value": "secure"}, "exec-doc-1"
    )

    # Calling execute without a grant issued by issuer fails
    with pytest.raises(PermissionError, match="Only Gateway-issued ALLOW and WARN receipts may reach execution"):
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


def test_unauthorized_issuer_cannot_issue_grant() -> None:
    real_issuer = object()
    fake_issuer = object()
    executor = HardenedDockerExecutor(real_issuer)
    receipt = AuthorizationReceipt(
        DecisionOutcome.ALLOW, "coder-01", "echo", {"value": "test"}, "exec-unauth-1"
    )

    with pytest.raises(PermissionError, match="Only the Gateway may issue executor grants"):
        executor.issue_grant(receipt, fake_issuer)


def test_tampered_receipt_or_arguments_rejected() -> None:
    issuer = object()
    executor = HardenedDockerExecutor(issuer)
    receipt = AuthorizationReceipt(
        DecisionOutcome.ALLOW, "coder-01", "echo", {"value": "original"}, "exec-tamp-1"
    )
    granted = executor.issue_grant(receipt, issuer)

    # Tamper with arguments
    tampered = AuthorizationReceipt(
        granted.decision,
        granted.agent_id,
        granted.tool_name,
        {"value": "malicious_tamper"},
        granted.execution_id,
        granted.grant_id,
    )
    with pytest.raises(PermissionError, match="Only Gateway-issued ALLOW and WARN receipts may reach execution"):
        executor.execute(tampered)


def test_grant_replay_is_strictly_rejected() -> None:
    issuer = object()
    executor = HardenedDockerExecutor(issuer)
    receipt = AuthorizationReceipt(
        DecisionOutcome.ALLOW, "coder-01", "echo", {"value": "single-use"}, "exec-replay-1"
    )
    granted = executor.issue_grant(receipt, issuer)

    # First execution succeeds
    res1 = executor.execute(granted)
    assert res1["tool"] == "echo"

    # Second execution with same grant MUST fail (one-time grant consumed)
    with pytest.raises(PermissionError, match="Only Gateway-issued ALLOW and WARN receipts may reach execution"):
        executor.execute(granted)


def test_blocked_and_unapproved_receipts_cannot_execute() -> None:
    issuer = object()
    executor = HardenedDockerExecutor(issuer)

    for blocked_outcome in (DecisionOutcome.BLOCK, DecisionOutcome.REQUIRE_APPROVAL):
        receipt = AuthorizationReceipt(
            blocked_outcome, "coder-01", "echo", {"value": "blocked"}, "exec-blk-1"
        )
        granted = executor.issue_grant(receipt, issuer)
        with pytest.raises(PermissionError, match="Only Gateway-issued ALLOW and WARN receipts may reach execution"):
            executor.execute(granted)


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


# =====================================================================
# 3. LIVE ADVERSARIAL RUNTIME CONTAINMENT TESTS (Skipped if Docker absent)
# =====================================================================

@pytest.mark.skipif(not is_docker_available(), reason="Docker daemon not accessible")
def test_live_docker_root_filesystem_write_blocked() -> None:
    profile = DockerSandboxProfile()
    cli_args = profile.to_docker_cli_args("alpine:latest", ["sh", "-c", "touch /pwn_root.txt"])
    res = subprocess.run(["docker", *cli_args], capture_output=True, text=True, timeout=10)
    assert res.returncode != 0
    assert "Read-only file system" in (res.stderr + res.stdout)


@pytest.mark.skipif(not is_docker_available(), reason="Docker daemon not accessible")
def test_live_docker_network_egress_blocked() -> None:
    profile = DockerSandboxProfile()
    cli_args = profile.to_docker_cli_args("alpine:latest", ["sh", "-c", "wget -T 1 -q -O - http://1.1.1.1"])
    res = subprocess.run(["docker", *cli_args], capture_output=True, text=True, timeout=10)
    assert res.returncode != 0
    assert "Network unreachable" in (res.stderr + res.stdout) or "bad address" in (res.stderr + res.stdout)


@pytest.mark.skipif(not is_docker_available(), reason="Docker daemon not accessible")
def test_live_docker_non_root_uid_enforced() -> None:
    profile = DockerSandboxProfile()
    cli_args = profile.to_docker_cli_args("alpine:latest", ["sh", "-c", "id -u"])
    res = subprocess.run(["docker", *cli_args], capture_output=True, text=True, timeout=10)
    assert res.returncode == 0
    assert res.stdout.strip() == "10001"


@pytest.mark.skipif(not is_docker_available(), reason="Docker daemon not accessible")
def test_live_docker_tmp_scratchpad_and_noexec_containment() -> None:
    profile = DockerSandboxProfile()
    # 1. /tmp is writable for temporary scratch data
    write_args = profile.to_docker_cli_args("alpine:latest", ["sh", "-c", "echo 'scratch_ok' > /tmp/scratch.txt && cat /tmp/scratch.txt"])
    write_res = subprocess.run(["docker", *write_args], capture_output=True, text=True, timeout=10)
    assert write_res.returncode == 0
    assert write_res.stdout.strip() == "scratch_ok"

    # 2. /tmp execution is blocked by noexec mount option
    exec_args = profile.to_docker_cli_args("alpine:latest", ["sh", "-c", "echo '#!/bin/sh' > /tmp/run.sh && echo 'echo pwned' >> /tmp/run.sh && chmod +x /tmp/run.sh && /tmp/run.sh"])
    exec_res = subprocess.run(["docker", *exec_args], capture_output=True, text=True, timeout=10)
    assert exec_res.returncode != 0
    assert "Permission denied" in (exec_res.stderr + exec_res.stdout)


@pytest.mark.skipif(not is_docker_available(), reason="Docker daemon not accessible")
def test_live_docker_socket_isolation() -> None:
    profile = DockerSandboxProfile()
    cli_args = profile.to_docker_cli_args("alpine:latest", ["sh", "-c", "ls -la /var/run/docker.sock"])
    res = subprocess.run(["docker", *cli_args], capture_output=True, text=True, timeout=10)
    assert res.returncode != 0
    assert "No such file or directory" in (res.stderr + res.stdout)
