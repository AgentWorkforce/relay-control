import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("node_guard", Path(__file__).resolve().parents[1] / "node_test_guard.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class GuardTests(unittest.TestCase):
    def test_plain_run(self):
        self.assertEqual(guard.serial_test_args(["--test", "a.test.js"]),
                         (["--test-concurrency=1", "--test", "a.test.js"], True))

    def test_import_and_reporter(self):
        args = ["--import", "tsx", "--test", "--test-reporter=tap", "a.test.ts"]
        self.assertEqual(guard.serial_test_args(args), (["--test-concurrency=1", *args], True))

    def test_override_and_no_duplicate(self):
        for flag in [["--test-concurrency=8"], ["--test-concurrency", "8"], ["--test-concurrency=1"]]:
            with self.subTest(flag=flag):
                args, guarded = guard.serial_test_args([*flag, "--test", "a.test.js"])
                self.assertTrue(guarded)
                self.assertEqual(args, ["--test-concurrency=1", "--test", "a.test.js"])

    def test_application_options_are_untouched(self):
        for args in [["app.js", "--test"], ["npm-cli.js", "test"], ["--", "--test"],
                     ["--eval", "1", "--test"], ["--version"], ["--import=tsx", "app.js", "--test"]]:
            with self.subTest(args=args):
                self.assertEqual(guard.serial_test_args(args), (args, False))

    def test_double_dash_payload_is_not_rewritten(self):
        args, guarded = guard.serial_test_args(["--test", "--", "--test-concurrency=8"])
        self.assertTrue(guarded)
        self.assertEqual(args, ["--test-concurrency=1", "--test", "--", "--test-concurrency=8"])

    def test_test_job_has_separate_hard_memory_and_time_limits(self):
        command = guard.isolated_test_command(["--test-concurrency=1", "--test", "a.test.js"], 42)
        self.assertIn("--scope", command)
        self.assertIn("--unit=layered-node-test-42", command)
        self.assertIn("--property=MemoryMax=4G", command)
        self.assertIn("--property=MemoryHigh=infinity", command)
        self.assertIn("--property=RuntimeMaxSec=600", command)
        self.assertEqual(command[-4:], ["/usr/bin/node", "--test-concurrency=1", "--test", "a.test.js"])


if __name__ == "__main__":
    unittest.main()
