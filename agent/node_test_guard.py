#!/usr/bin/python3
"""Keep agent-owned PATH-based Node test runs serial; pass other commands through."""
import os
import pwd
import sys

VALUE_OPTIONS = {
    "--import", "--require", "-r", "--loader", "--experimental-loader",
    "--conditions", "-C", "--input-type", "--inspect-port", "--env-file",
    "--env-file-if-exists", "--test-reporter", "--test-reporter-destination",
    "--test-name-pattern", "--test-skip-pattern", "--test-timeout",
    "--test-concurrency",
}
EXECUTION_OPTIONS = {"--eval", "-e", "--print", "-p", "--run"}


def serial_test_args(args):
    index = 0
    is_test = False
    while index < len(args):
        arg = args[index]
        if arg == "--test":
            is_test = True
            break
        if arg == "--" or arg in EXECUTION_OPTIONS or not arg.startswith("-"):
            break
        index += 2 if arg in VALUE_OPTIONS else 1
    if not is_test:
        return args, False
    filtered = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            filtered.extend(args[index:])
            break
        if arg == "--test-concurrency":
            index += 2
            continue
        if not arg.startswith("--test-concurrency="):
            filtered.append(arg)
        index += 1
    return ["--test-concurrency=1", *filtered], True


def isolated_test_command(args, pid):
    return [
        "/usr/bin/systemd-run", "--user", "--scope", "--quiet", "--collect",
        "--unit=layered-node-test-" + str(pid),
        "--property=MemoryMax=4G", "--property=MemoryHigh=infinity",
        "--property=MemorySwapMax=0", "--property=RuntimeMaxSec=600",
        "/usr/bin/node", *args,
    ]


def main():
    args = sys.argv[1:]
    guarded = False
    if os.getuid() == pwd.getpwnam("agent").pw_uid:
        args, guarded = serial_test_args(args)
    if guarded:
        print("[layered-test-guard] serial Node tests in a separate 4 GiB scope (10 minute limit)", file=sys.stderr)
        os.environ.setdefault("XDG_RUNTIME_DIR", "/run/user/" + str(os.getuid()))
        os.environ.setdefault("DBUS_SESSION_BUS_ADDRESS", "unix:path=" + os.environ["XDG_RUNTIME_DIR"] + "/bus")
        command = isolated_test_command(args, os.getpid())
        os.execv(command[0], command)
    os.execv("/usr/bin/node", ["/usr/bin/node", *args])


if __name__ == "__main__":
    main()
