"""Deploy the public lane onto the existing Control host through scoped SSM."""
import argparse
import base64
import json
from pathlib import Path
import re
import subprocess
import time

ACCOUNT = "500268966557"
REGION = "us-west-2"
INSTANCE = "i-0564532755193787a"
HOST_NAME = "relaycast-agent-host-dev-control"


def aws(*arguments):
    return json.loads(subprocess.check_output(
        ["aws", *arguments, "--region", REGION, "--output", "json", "--no-cli-pager"],
        text=True, stderr=subprocess.PIPE,
    ))


def command(revision, directory):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("expected a full Git commit SHA")
    payload = base64.b64encode(json.dumps({
        "revision": revision,
        "lead_prompt": (directory / "lead-prompt.md").read_text(),
    }).encode()).decode()
    implementation = base64.b64encode((directory / "apply.py").read_bytes()).decode()
    return f"python3 - '{payload}' <<'CONTROL_AGENT_DEPLOY'\nimport base64\nexec(compile(base64.b64decode('{implementation}'), 'control-agent-apply.py', 'exec'))\nCONTROL_AGENT_DEPLOY"


def deploy(revision, directory, client=aws, pause=time.sleep, deadline=600):
    if client("sts", "get-caller-identity")["Account"] != ACCOUNT:
        raise RuntimeError("refusing another AWS account")
    reservations = client("ec2", "describe-instances", "--instance-ids", INSTANCE)["Reservations"]
    instances = [instance for group in reservations for instance in group["Instances"]]
    if len(instances) != 1:
        raise RuntimeError("expected exactly the existing Control instance")
    instance = instances[0]
    tags = {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}
    if instance["InstanceId"] != INSTANCE or tags.get("Name") != HOST_NAME or instance["State"]["Name"] != "running":
        raise RuntimeError("existing Control host identity/state does not match")
    information = client("ssm", "describe-instance-information", "--filters", f"Key=InstanceIds,Values={INSTANCE}")["InstanceInformationList"]
    if len(information) != 1 or information[0]["PingStatus"] != "Online":
        raise RuntimeError("Control host is not SSM-online; recover its guest before deployment")
    request = {
        "InstanceIds": [INSTANCE], "DocumentName": "AWS-RunShellScript",
        "Comment": f"Public Control lane deployment {revision}",
        "Parameters": {"commands": [command(revision, directory)], "executionTimeout": ["120"]},
    }
    receipt = client("ssm", "send-command", "--cli-input-json", json.dumps(request))
    identifier = receipt["Command"]["CommandId"]
    print(json.dumps({"command_id": identifier, "instance": INSTANCE, "revision": revision}), flush=True)
    for _ in range(deadline // 5):
        try:
            result = client("ssm", "get-command-invocation", "--command-id", identifier, "--instance-id", INSTANCE)
        except subprocess.CalledProcessError as error:
            if "InvocationDoesNotExist" in (error.stderr or ""):
                pause(5)
                continue
            raise RuntimeError("SSM status read failed; inspect the existing command instead of re-submitting") from error
        status = result["Status"]
        if status == "Success":
            print(result.get("StandardOutputContent", ""))
            return identifier
        if status not in {"Pending", "InProgress", "Delayed"}:
            raise RuntimeError(f"SSM command {identifier}: {status}; inspect its output before another deployment")
        pause(5)
    raise RuntimeError(f"SSM command {identifier} still pending; inspect it without automatically retrying")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--revision", required=True)
    arguments = parser.parse_args()
    deploy(arguments.revision, Path(__file__).parent)
