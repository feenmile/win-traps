"""Hook JSON in/out tests (Claude Code PreToolUse schema)."""

import json
import os
import subprocess
import sys
import unittest

from wintraps import hook
from wintraps.catalog import BLOCK, Trap
from tests.helpers import ctx

FORCE = {"WINTRAPS_FORCE": "1"}


def payload(command, tool="Bash", cwd="/work/project"):
    return json.dumps({
        "session_id": "abc123",
        "cwd": cwd,
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"command": command, "description": "test"},
        "tool_use_id": "toolu_test",
    })


def fake_ctx(shell, cwd):
    return ctx(shell=shell, cwd=cwd)


def run(command, tool="Bash", environ=FORCE, platform="linux", **kw):
    kw.setdefault("ctx_factory", fake_ctx)
    return hook.run(payload(command, tool), environ, platform, **kw)


class HookOutputTests(unittest.TestCase):
    def test_block_trap_denies_with_exact_schema(self):
        out, err, code = run('python -c "import os; os.kill(1, 0)"')
        self.assertEqual((err, code), ("", 0))
        data = json.loads(out)
        self.assertEqual(set(data), {"hookSpecificOutput"})
        hso = data["hookSpecificOutput"]
        self.assertEqual(set(hso), {"hookEventName", "permissionDecision", "permissionDecisionReason"})
        self.assertEqual(hso["hookEventName"], "PreToolUse")
        self.assertEqual(hso["permissionDecision"], "deny")
        self.assertIn("os-kill-zero", hso["permissionDecisionReason"])
        self.assertIn("psutil.pid_exists", hso["permissionDecisionReason"])

    def test_warn_trap_adds_context_without_a_decision(self):
        out, _, code = run("python -I tool.py")
        hso = json.loads(out)["hookSpecificOutput"]
        self.assertEqual(code, 0)
        self.assertEqual(set(hso), {"hookEventName", "additionalContext"})
        self.assertIn("python-isolated-encoding", hso["additionalContext"])

    def test_warn_trap_asks_when_configured(self):
        out, _, _ = run("python -I tool.py", environ={**FORCE, "WINTRAPS_WARN": "ask"})
        hso = json.loads(out)["hookSpecificOutput"]
        self.assertEqual(hso["permissionDecision"], "ask")
        self.assertIn("python-isolated-encoding", hso["permissionDecisionReason"])

    def test_block_and_warn_together_deny_and_mention_both(self):
        out, _, _ = run('python -I -c "import os; os.kill(1, 0)"')
        hso = json.loads(out)["hookSpecificOutput"]
        self.assertEqual(hso["permissionDecision"], "deny")
        self.assertIn("os-kill-zero", hso["permissionDecisionReason"])
        self.assertIn("python-isolated-encoding", hso["permissionDecisionReason"])

    def test_clean_command_prints_nothing(self):
        self.assertEqual(run("git status"), ("", "", 0))

    def test_inactive_off_windows_without_force(self):
        self.assertEqual(run('python -c "import os; os.kill(1, 0)"', environ={}, platform="linux"), ("", "", 0))

    def test_active_on_windows_without_force(self):
        out, _, _ = run('python -c "import os; os.kill(1, 0)"', environ={}, platform="win32")
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_other_tools_are_ignored(self):
        data = json.dumps({"tool_name": "Write", "tool_input": {"file_path": "x.py", "content": "os.kill(1, 0)"}})
        self.assertEqual(hook.run(data, FORCE, "linux"), ("", "", 0))

    def test_powershell_skips_bash_only_traps(self):
        self.assertEqual(run("cat <<EOF\n$HOME\nEOF", tool="PowerShell"), ("", "", 0))
        out, _, _ = run("cat <<EOF\n$HOME\nEOF", tool="Bash")
        self.assertIn("heredoc-unquoted", out)

    def test_powershell_checks_python_code(self):
        out, _, _ = run('python -c "import os; os.kill(1, 0)"', tool="PowerShell")
        self.assertIn('"deny"', out)

    def test_allow_marker(self):
        self.assertEqual(run('python -c "import os; os.kill(1, 0)"  # wintraps:allow=os-kill-zero'), ("", "", 0))


class HookNeverCrashesTests(unittest.TestCase):
    def test_invalid_json_allows_and_logs(self):
        out, err, code = hook.run("{not json", FORCE, "linux")
        self.assertEqual((out, code), ("", 0))
        self.assertIn("win-traps: internal error", err)

    def test_non_object_json_allows_and_logs(self):
        out, err, code = hook.run("[1, 2]", FORCE, "linux")
        self.assertEqual((out, code), ("", 0))
        self.assertTrue(err)

    def test_crashing_matcher_allows_and_logs(self):
        def boom(command, c):
            raise RuntimeError("matcher exploded")
        bad = Trap(id="boom", title="t", severity=BLOCK, applies_to=("any",), status="verified",
                   why="w", safe="s", sources=("https://example.com",), matcher=boom)
        out, err, code = run("anything", traps=[bad])
        self.assertEqual((out, code), ("", 0))
        self.assertIn("matcher exploded", err)

    def test_missing_command_prints_nothing(self):
        data = json.dumps({"tool_name": "Bash", "tool_input": {}})
        self.assertEqual(hook.run(data, FORCE, "linux"), ("", "", 0))


class HookProcessTests(unittest.TestCase):
    """End to end through `python -m wintraps.hook`, with raw UTF-8 bytes on stdin."""

    def _spawn(self, command, extra_env):
        env = {k: v for k, v in os.environ.items() if not k.startswith("WINTRAPS_")}
        env.update(extra_env)
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env["PYTHONPATH"] = root
        data = json.dumps({"tool_name": "Bash", "cwd": root, "tool_input": {"command": command}},
                          ensure_ascii=False).encode("utf-8")
        return subprocess.run([sys.executable, "-m", "wintraps.hook"], input=data, capture_output=True,
                              env=env, cwd=root, timeout=60)

    def test_process_denies_and_survives_non_ascii(self):
        proc = self._spawn('python -c "import os; os.kill(1, 0)"  # “smart” →', {"WINTRAPS_FORCE": "1"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout.decode("ascii"))
        self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_process_bad_input_exits_zero(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("WINTRAPS_")}
        env["WINTRAPS_FORCE"] = "1"
        env["PYTHONPATH"] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        proc = subprocess.run([sys.executable, "-m", "wintraps.hook"], input=b"\xff\xfe garbage",
                              capture_output=True, env=env, timeout=60)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b"")
        self.assertIn(b"win-traps", proc.stderr)


if __name__ == "__main__":
    unittest.main()
