import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


deploy = load("deploy")
apply = load("apply")
SHA = "a" * 40


class FakeAws:
    def __init__(self, account=deploy.ACCOUNT, name=deploy.HOST_NAME, ping="Online", statuses=None):
        self.account, self.name, self.ping = account, name, ping
        self.statuses = iter(statuses or ["Success"])
        self.calls = []

    def __call__(self, *args):
        self.calls.append(args)
        service, operation = args[:2]
        if (service, operation) == ("sts", "get-caller-identity"):
            return {"Account": self.account}
        if operation == "describe-instances":
            return {"Reservations": [{"Instances": [{"InstanceId": deploy.INSTANCE, "State": {"Name": "running"}, "Tags": [{"Key": "Name", "Value": self.name}]}]}]}
        if operation == "describe-instance-information":
            return {"InstanceInformationList": [{"PingStatus": self.ping}]}
        if operation == "send-command":
            request = json.loads(args[-1])
            assert request["InstanceIds"] == [deploy.INSTANCE]
            assert request["DocumentName"] == "AWS-RunShellScript"
            return {"Command": {"CommandId": "command-1"}}
        result = next(self.statuses)
        if isinstance(result, Exception):
            raise result
        return {"Status": result, "StandardOutputContent": "{}"}


class DeployTests(unittest.TestCase):
    def assert_no_send(self, client):
        self.assertNotIn("send-command", [args[1] for args in client.calls])

    def test_wrong_account_refuses_before_host_access(self):
        client = FakeAws(account="000000000000")
        with self.assertRaisesRegex(RuntimeError, "another AWS account"):
            deploy.deploy(SHA, ROOT, client)
        self.assertEqual(len(client.calls), 1)

    def test_wrong_host_tag_refuses_before_remote_execution(self):
        client = FakeAws(name="some-other-host")
        with self.assertRaisesRegex(RuntimeError, "identity/state"):
            deploy.deploy(SHA, ROOT, client)
        self.assert_no_send(client)

    def test_offline_host_refuses_before_remote_execution(self):
        client = FakeAws(ping="ConnectionLost")
        with self.assertRaisesRegex(RuntimeError, "not SSM-online"):
            deploy.deploy(SHA, ROOT, client)
        self.assert_no_send(client)

    def test_delayed_visibility_polls_same_command_once(self):
        missing = subprocess.CalledProcessError(254, ["aws"], stderr="InvocationDoesNotExist")
        client = FakeAws(statuses=[missing, "InProgress", "Success"])
        self.assertEqual(deploy.deploy(SHA, ROOT, client, pause=lambda _: None), "command-1")
        self.assertEqual(sum(args[1] == "send-command" for args in client.calls), 1)

    def test_failed_command_is_not_resubmitted(self):
        client = FakeAws(statuses=["Failed"])
        with self.assertRaisesRegex(RuntimeError, "inspect"):
            deploy.deploy(SHA, ROOT, client, pause=lambda _: None)
        self.assertEqual(sum(args[1] == "send-command" for args in client.calls), 1)

    def test_invalid_revision_cannot_become_shell_input(self):
        for revision in ["main", SHA + "\nreboot", "$(reboot)"]:
            with self.assertRaises(ValueError):
                deploy.command(revision, ROOT)

    def test_payload_keeps_prompt_out_of_shell_syntax(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prompt = "Literal `reboot` and $(reboot)\nCONTROL_AGENT_DEPLOY\n"
            (root / "lead-prompt.md").write_text(prompt)
            (root / "apply.py").write_text((ROOT / "apply.py").read_text())
            (root / "node_test_guard.py").write_text((ROOT / "node_test_guard.py").read_text())
            script = deploy.command(SHA, root)
            encoded = script.split("'", 2)[1]
            self.assertEqual(json.loads(base64.b64decode(encoded))["lead_prompt"], prompt)
            self.assertEqual(json.loads(base64.b64decode(encoded))["node_test_guard"], (ROOT / "node_test_guard.py").read_text())
            self.assertNotIn("$(reboot)", script)

    def test_privilege_check_precedes_all_host_mutation(self):
        with patch.object(apply.os, "geteuid", return_value=1001), patch.object(apply, "checked_file") as write:
            with self.assertRaisesRegex(RuntimeError, "scoped root SSM"):
                apply.main({"revision": SHA, "lead_prompt": "test"})
            write.assert_not_called()

    def test_exceeded_budget_refuses_before_file_or_unit_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / "state/lead").mkdir(parents=True)
            (home / "state/lead/session.json").write_text('{"session_id":"existing"}')
            with patch.object(apply.os, "geteuid", return_value=0), \
                 patch.object(apply.pwd, "getpwnam", return_value=SimpleNamespace(pw_dir=str(home), pw_uid=1001)), \
                 patch.object(apply.Path, "is_file", return_value=True), \
                 patch.object(apply, "current_memory", return_value=apply.LIMIT), \
                 patch.object(apply, "checked_file") as write, \
                 patch.object(apply.subprocess, "run") as run:
                with self.assertRaisesRegex(RuntimeError, "drain it"):
                    apply.main({"revision": SHA, "lead_prompt": "test", "node_test_guard": (ROOT / "node_test_guard.py").read_text()})
                write.assert_not_called()
                run.assert_not_called()

    def test_lead_cannot_be_rethrottled_by_deployment(self):
        self.assertEqual(apply.budget_properties("agent-host-lead.service", 1001), ["MemoryHigh=infinity", "MemoryMax=8G"])
        self.assertEqual(apply.budget_properties("user-1001.slice", 1001), ["MemoryHigh=6G", "MemoryMax=8G"])
        self.assertIn("MemoryHigh=infinity", apply.LEAD_DROPIN)

    def test_unrelated_node_binary_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "node"
            path.write_bytes(b"\x7fELF\xff")
            with self.assertRaisesRegex(RuntimeError, "existing Node binary"):
                apply.validate_node_target(path)
            path.write_text("#!/bin/sh\nexec something-else\n")
            with self.assertRaisesRegex(RuntimeError, "unrelated Node"):
                apply.validate_node_target(path)

    def test_existing_reviewed_guard_can_be_updated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "node"
            apply.validate_node_target(path)
            path.write_text((ROOT / "node_test_guard.py").read_text())
            apply.validate_node_target(path)

    def test_role_has_no_broad_or_additional_write_capability(self):
        policy = json.loads((ROOT / "iam/deploy-policy.json").read_text())
        writes = []
        for statement in policy["Statement"]:
            actions = statement["Action"]
            actions = [actions] if isinstance(actions, str) else actions
            for action in actions:
                if action not in {"ec2:DescribeInstances", "ssm:DescribeInstanceInformation", "ssm:GetCommandInvocation"}:
                    writes.append((action, statement["Resource"]))
        self.assertEqual(set(writes), {
            ("ssm:SendCommand", "arn:aws:ssm:us-west-2::document/AWS-RunShellScript"),
            ("ssm:SendCommand", f"arn:aws:ec2:us-west-2:{deploy.ACCOUNT}:instance/{deploy.INSTANCE}"),
        })
        trust = json.loads((ROOT / "iam/trust.json").read_text())
        condition = trust["Statement"][0]["Condition"]
        self.assertEqual(set(condition), {"StringEquals"})
        subject = condition["StringEquals"]["token.actions.githubusercontent.com:sub"]
        self.assertEqual(subject, "repo:AgentWorkforce@252050005/relay-control@1450141592:ref:refs/heads/main")


if __name__ == "__main__":
    unittest.main()
