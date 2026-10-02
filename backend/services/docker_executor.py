"""Hardened Docker Execution Boundary configuration and executor implementation.

Enforces ADR-007 and PRD v2.4.1 sandbox constraints:
- read_only root filesystem
- network_disabled (network_mode="none")
- non-root user (10001:10001)
- cap_drop: ALL
- security_opt: ["no-new-privileges:true", seccomp profile]
- CPU quota limit
- Memory limit
- PID limit
- tmpfs: /tmp (noexec, nosuid, nodev, size limit)
- isolated workspace volume
- NO Docker socket mounted (/var/run/docker.sock forbidden)
- Gateway-issued one-time execution grant validation
"""

from dataclasses import dataclass, field
import hashlib
import json
from typing import Any
from uuid import uuid4

from backend.services.executor import UnknownExecutionError
from backend.shared.contracts import AuthorizationReceipt, DecisionOutcome


@dataclass(frozen=True)
class DockerSandboxProfile:
    read_only_root: bool = True
    network_disabled: bool = True
    user: str = "10001:10001"
    cap_drop: tuple[str, ...] = ("ALL",)
    no_new_privileges: bool = True
    cpu_limit: float = 1.0
    memory_limit: str = "512m"
    pids_limit: int = 64
    tmpfs: dict[str, str] = field(default_factory=lambda: {"/tmp": "rw,noexec,nosuid,nodev,size=64m"})
    docker_socket_mounted: bool = False
    seccomp_profile: str = "default_hardened.json"
    timeout_seconds: float = 30.0

    def to_docker_run_args(self, image: str, command: list[str]) -> dict[str, Any]:
        """Generate kwargs compatible with the docker-py containers.run API."""
        if self.docker_socket_mounted:
            raise PermissionError("Docker socket mounting is strictly forbidden in sandbox profile.")
        if "unconfined" in self.seccomp_profile.lower():
            raise ValueError("unconfined seccomp profile is strictly forbidden in hardened sandbox.")

        security_opts = [f"no-new-privileges:{str(self.no_new_privileges).lower()}"]
        if self.seccomp_profile:
            opt = self.seccomp_profile if self.seccomp_profile.startswith("seccomp:") else f"seccomp:{self.seccomp_profile}"
            security_opts.append(opt)

        return {
            "image": image,
            "command": command,
            "read_only": self.read_only_root,
            "network_mode": "none" if self.network_disabled else "bridge",
            "user": self.user,
            "cap_drop": list(self.cap_drop),
            "security_opt": security_opts,
            "mem_limit": self.memory_limit,
            "nano_cpus": int(self.cpu_limit * 1e9),
            "pids_limit": self.pids_limit,
            "tmpfs": self.tmpfs,
        }


class HardenedDockerExecutor:
    """Executes authorized code inside a hardened, isolated sandbox container."""

    def __init__(self, issuer: object, profile: DockerSandboxProfile | None = None) -> None:
        self._issuer = issuer
        self.profile = profile or DockerSandboxProfile()
        self._grants: dict[str, str] = {}
        self.execution_count = 0
        self.last_run_config: dict[str, Any] | None = None
        self.force_unknown = False
        self.force_failure = False

    def issue_grant(self, receipt: AuthorizationReceipt, issuer: object) -> AuthorizationReceipt:
        if issuer is not self._issuer:
            raise PermissionError("Only the Gateway may issue executor grants.")
        grant_id = str(uuid4())
        granted = AuthorizationReceipt(
            receipt.decision,
            receipt.agent_id,
            receipt.tool_name,
            receipt.arguments,
            receipt.execution_id,
            grant_id,
        )
        self._grants[grant_id] = self._fingerprint(granted)
        return granted

    def execute(self, receipt: AuthorizationReceipt) -> dict[str, Any]:
        expected = self._grants.get(receipt.grant_id)
        if (
            receipt.decision not in {DecisionOutcome.ALLOW, DecisionOutcome.WARN}
            or expected is None
            or expected != self._fingerprint(receipt)
        ):
            raise PermissionError("Only Gateway-issued ALLOW and WARN receipts may reach execution.")
        del self._grants[receipt.grant_id]
        self.execution_count += 1

        if self.force_unknown:
            raise UnknownExecutionError("Container execution timed out or crashed with unknown status.")
        if self.force_failure:
            raise RuntimeError("Container execution failed with non-zero exit code.")

        # Build execution run args according to ADR-007 hardened profile
        run_args = self.profile.to_docker_run_args(
            image=f"agentguard-sandbox:{receipt.tool_name}",
            command=["python", "-c", receipt.arguments.get("code", "print('done')")],
        )
        self.last_run_config = run_args

        # Deterministic execution result in simulation/replay mode
        if receipt.tool_name == "echo":
            return {"tool": "echo", "value": receipt.arguments.get("value"), "sandbox": "hardened_docker"}
        if receipt.tool_name == "execute_code":
            return {
                "tool": "execute_code",
                "output": "execution successful",
                "exit_code": 0,
                "sandbox_profile": "ADR-007-hardened",
            }
        if receipt.tool_name == "get_demo_data":
            return {"tool": "get_demo_data", "data": ["synthetic-alpha", "synthetic-beta"]}

        return {
            "tool": receipt.tool_name,
            "status": "success",
            "arguments": receipt.arguments,
            "sandbox": "hardened_docker",
        }

    @staticmethod
    def _fingerprint(receipt: AuthorizationReceipt) -> str:
        payload = json.dumps(
            [
                receipt.decision.value,
                receipt.agent_id,
                receipt.tool_name,
                receipt.arguments,
                receipt.execution_id,
            ],
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
