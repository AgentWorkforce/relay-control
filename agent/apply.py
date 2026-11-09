"""Apply reviewed lane files on the existing host; no host or harness restart."""
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys

LEAD_DROPIN = "[Service]\nMemoryAccounting=yes\nMemoryHigh=infinity\nMemoryMax=8G\nRestart=always\nRestartSec=10\n"
USER_DROPIN = "[Slice]\nMemoryAccounting=yes\nMemoryHigh=6G\nMemoryMax=8G\n"
HEAVY = "#!/bin/bash\nset -euo pipefail\n[ $# -gt 0 ] || { echo 'usage: layered-heavy COMMAND [ARGS...]' >&2; exit 2; }\nexec flock --exclusive --wait 1800 /home/agent/state/heavy.lock \"$@\"\n"
LIMIT = 8 * 1024**3


def checked_file(path: Path, content: str, mode: int = 0o644):
    if path.is_symlink():
        raise RuntimeError(f"refusing symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    if any(parent.is_symlink() for parent in path.parents):
        raise RuntimeError(f"refusing symlinked parent: {path}")
    temporary = path.with_name(path.name + ".agent-deploy-new")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "w") as stream:
        stream.write(content)
    os.replace(temporary, path)


def current_memory(unit):
    value = subprocess.check_output(
        ["systemctl", "show", unit, "--property=MemoryCurrent", "--value"], text=True
    ).strip()
    if not value.isdigit():
        raise RuntimeError(f"cannot establish current memory use for {unit}")
    return int(value)


def budget_properties(unit, agent_uid):
    if unit == "agent-host-lead.service":
        return ["MemoryHigh=infinity", "MemoryMax=8G"]
    if unit == f"user-{agent_uid}.slice":
        return ["MemoryHigh=6G", "MemoryMax=8G"]
    raise ValueError("unexpected resource-budget target")


def validate_node_target(path):
    if path.is_symlink():
        raise RuntimeError("refusing symlink at Node guard target")
    if path.exists():
        try:
            existing = path.read_text()
        except UnicodeDecodeError as error:
            raise RuntimeError("refusing to replace an existing Node binary") from error
        if "[layered-test-guard]" not in existing:
            raise RuntimeError("refusing to replace an unrelated Node executable")


def main(payload):
    if os.geteuid() != 0:
        raise RuntimeError("deployment must run through the scoped root SSM command")
    revision = payload["revision"]
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("expected a full Git commit SHA")
    lead = payload["lead_prompt"]
    if not isinstance(lead, str) or not 1 <= len(lead.encode()) <= 16_384:
        raise ValueError("invalid lead prompt")
    guard = payload["node_test_guard"]
    if not isinstance(guard, str) or not 1 <= len(guard.encode()) <= 16_384:
        raise ValueError("invalid Node guard")
    compile(guard, "node-test-guard.py", "exec")
    agent = pwd.getpwnam("agent")
    state = Path(agent.pw_dir) / "state/lead"
    session = state / "session.json"
    before = session.read_bytes()
    json.loads(before)
    if not Path("/opt/agent-host/headless.py").is_file() or not Path("/usr/local/bin/layered-task").is_file():
        raise RuntimeError("existing native runtime is required; migration is separate")
    units = ["agent-host-lead.service", f"user-{agent.pw_uid}.slice"]
    for unit in units:
        if current_memory(unit) >= LIMIT:
            raise RuntimeError(f"{unit} already exceeds the proposed limit; drain it before deployment")
    if not Path("/usr/bin/node").is_file() or not Path("/usr/bin/systemd-run").is_file():
        raise RuntimeError("existing Node runtime and systemd-run are required")
    validate_node_target(Path("/usr/local/bin/node"))
    checked_file(Path("/opt/agent-host/lead-prompt.md"), lead)
    checked_file(Path("/etc/systemd/system/agent-host-lead.service.d/40-memory-budget.conf"), LEAD_DROPIN)
    checked_file(Path(f"/etc/systemd/system/user-{agent.pw_uid}.slice.d/40-agent-memory-budget.conf"), USER_DROPIN)
    checked_file(Path("/usr/local/bin/layered-heavy"), HEAVY, 0o755)
    checked_file(Path("/usr/local/bin/node"), guard, 0o755)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    for unit in units:
        subprocess.run(["systemctl", "set-property", unit, *budget_properties(unit, agent.pw_uid)], check=True)
    subprocess.run(
        ["sudo", "-H", "-u", "agent", "/usr/local/bin/layered-task", "submit",
         "--id", f"public-lane-{revision}", "--sender", "agent-deploy"],
        input="Read /opt/agent-host/lead-prompt.md. Apply the public relay-control lane and heavy-job budget to future work. Preserve the current conversation, ledger and interrupted-task receipts. Report this deployment revision on your existing task channel.\n",
        text=True, check=True,
    )
    if session.read_bytes() != before:
        raise RuntimeError("native session state changed during deployment; inspect before continuing")
    result = {
        "revision": revision,
        "session_sha256": hashlib.sha256(before).hexdigest(),
        "lead_memory_max_bytes": LIMIT,
        "agent_user_memory_max_bytes": LIMIT,
        "node_test_guard_sha256": hashlib.sha256(guard.encode()).hexdigest(),
        "node_test_job_memory_max_bytes": 4 * 1024**3,
        "restart_performed": False,
    }
    checked_file(Path("/var/lib/agent-host/public-lane-deploy.json"), json.dumps(result) + "\n", 0o600)
    print(json.dumps(result))


if __name__ == "__main__":
    main(json.loads(base64.b64decode(sys.argv[1], validate=True)))
