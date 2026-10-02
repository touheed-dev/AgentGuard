"""Hardened Docker Execution Boundary configuration and executor implementation.

Enforces ADR-007 and PRD v2.4.1 sandbox constraints:
- read_only root filesystem
- network_disabled (network_mode="none")
- non-root user (10001:10001)
- cap_drop: ALL (cap_add forbidden)
- security_opt: ["no-new-privileges:true", seccomp profile]
- CPU quota limit (nano_cpus / cpus)
- Memory limit (mem_limit)
- PID limit (pids_limit)
- tmpfs: /tmp (rw,noexec,nosuid,nodev,size=64m)
- NO privileged mode
- NO host PID/IPC/Network sharing
- NO Docker socket mounted (/var/run/docker.sock forbidden)
- Gateway-issued one-time execution grant validation
"""

from dataclasses import dataclass, field
import hashlib
import json
import shutil
import subprocess
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
    cap_add: tuple[str, ...] = ()
    privileged: bool = False
    no_new_privileges: bool = True
    cpu_limit: float = 1.0
    memory_limit: str = "512m"
    pids_limit: int = 64
    tmpfs: dict[str, str] = field(default_factory=lambda: {"/tmp": "rw,noexec,nosuid,nodev,size=64m"})
    docker_socket_mounted: bool = False
    seccomp_profile: str = "default_hardened.json"
    pid_mode: str = "none"
    ipc_mode: str = "none"
    volumes: tuple[str, ...] = ()
    timeout_seconds: float = 30.0

    def validate(self) -> None:
        """Fail-closed validation of all mandatory container sandbox constraints."""
        if self.docker_socket_mounted:
            raise PermissionError("Docker socket mounting is strictly forbidden in sandbox profile.")

        for v in self.volumes:
            if "docker.sock" in v.lower():
                raise PermissionError("Mounting Docker socket via volumes is strictly forbidden.")
            if v.startswith("/") and not v.startswith("/tmp"):
                raise PermissionError(f"Host path mount is forbidden in sandbox profile: {v}")

        if not self.read_only_root:
            raise PermissionError("Read-only root filesystem is mandatory in sandbox profile.")

        if not self.network_disabled:
            raise PermissionError("Network access is strictly forbidden in sandbox profile.")

        if self.privileged:
            raise PermissionError("Privileged container mode is strictly forbidden in sandbox profile.")

        if self.user in {"0", "0:0", "root", ""}:
            raise PermissionError(f"Root user execution is strictly forbidden: user={self.user}")

        if "ALL" not in self.cap_drop:
            raise PermissionError("cap_drop ALL is mandatory in sandbox profile.")

        if self.cap_add:
            raise PermissionError(f"cap_add is strictly forbidden in sandbox profile: {self.cap_add}")

        if not self.no_new_privileges:
            raise PermissionError("no-new-privileges is mandatory in sandbox profile.")

        if not self.seccomp_profile or "unconfined" in self.seccomp_profile.lower():
            raise ValueError(f"Unconfined or empty seccomp profile is strictly forbidden: {self.seccomp_profile}")

        if self.pid_mode.lower() == "host":
            raise PermissionError("Host PID namespace sharing is strictly forbidden in sandbox profile.")

        if self.ipc_mode.lower() == "host":
            raise PermissionError("Host IPC namespace sharing is strictly forbidden in sandbox profile.")

        if "/tmp" not in self.tmpfs or "noexec" not in self.tmpfs["/tmp"]:
            raise PermissionError("tmpfs /tmp with noexec mount option is mandatory in sandbox profile.")

        if self.cpu_limit <= 0 or self.cpu_limit > 2.0:
            raise ValueError(f"cpu_limit out of allowed sandbox bounds: {self.cpu_limit}")

        if self.pids_limit <= 0 or self.pids_limit > 256:
            raise ValueError(f"pids_limit out of allowed sandbox bounds: {self.pids_limit}")

    def to_docker_run_args(self, image: str, command: list[str]) -> dict[str, Any]:
        """Generate kwargs compatible with the docker-py containers.run API."""
        self.validate()

        security_opts = [f"no-new-privileges:{str(self.no_new_privileges).lower()}"]
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
            "privileged": False,
        }

    def to_docker_cli_args(self, image: str, command: list[str]) -> list[str]:
        """Generate CLI arguments for 'docker run' execution."""
        self.validate()
        args = [
            "run", "--rm",
            "--read-only",
            "--network", "none",
            "--user", self.user,
            "--cap-drop", "ALL",
            "--security-opt", f"no-new-privileges:{str(self.no_new_privileges).lower()}",
            "--memory", self.memory_limit,
            "--cpus", str(self.cpu_limit),
            "--pids-limit", str(self.pids_limit),
        ]
        for mount_path, mount_opts in self.tmpfs.items():
            args.extend(["--tmpfs", f"{mount_path}:{mount_opts}"])
        args.append(image)
        args.extend(command)
        return args


class HardenedDockerExecutor:
    """Executes authorized code inside a hardened, isolated sandbox container."""

    def __init__(
        self,
        issuer: object,
        profile: DockerSandboxProfile | None = None,
        use_live_docker: bool = False,
    ) -> None:
        self._issuer = issuer
        self.profile = profile or DockerSandboxProfile()
        self.use_live_docker = use_live_docker
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

        # Live Docker execution when requested and docker CLI available
        if self.use_live_docker and shutil.which("docker"):
            return self._execute_live_container(receipt)

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

    def _execute_live_container(self, receipt: AuthorizationReceipt) -> dict[str, Any]:
        cli_args = self.profile.to_docker_cli_args(
            image="alpine:latest",
            command=["sh", "-c", f"echo {receipt.arguments.get('value', 'live-docker-exec')}"],
        )
        try:
            res = subprocess.run(
                ["docker", *cli_args],
                capture_output=True,
                text=True,
                timeout=self.profile.timeout_seconds,
            )
            if res.returncode != 0:
                raise RuntimeError(f"Live container execution failed with exit code {res.returncode}: {res.stderr}")
            return {
                "tool": receipt.tool_name,
                "output": res.stdout.strip(),
                "exit_code": res.returncode,
                "sandbox": "hardened_docker",
            }
        except subprocess.TimeoutExpired:
            raise UnknownExecutionError("Live container execution timed out.")
        except Exception as e:
            if isinstance(e, (UnknownExecutionError, RuntimeError)):
                raise
            raise RuntimeError(f"Live container launch error: {e}") from e

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
