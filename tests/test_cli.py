import contextlib
import io
import json
import os
import tempfile
import unittest

from wintraps import cli
from wintraps.catalog import TRAPS


def run_cli(*argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = cli.main(list(argv))
    return code, buf.getvalue()


class CliTests(unittest.TestCase):
    def test_check_block_exit_2(self):
        code, out = run_cli("check", 'python -c "import os; os.kill(1, 0)"')
        self.assertEqual(code, 2)
        self.assertIn("os-kill-zero", out)
        self.assertIn("Safe:", out)

    def test_check_warn_exit_1(self):
        code, out = run_cli("check", "python -I tool.py")
        self.assertEqual(code, 1)
        self.assertIn("python-isolated-encoding", out)

    def test_check_clean_exit_0(self):
        code, out = run_cli("check", "git status")
        self.assertEqual(code, 0)
        self.assertIn("No known Windows traps matched", out)

    def test_check_json(self):
        code, out = run_cli("check", "--json", "taskkill /F /IM node.exe")
        self.assertEqual(code, 2)
        self.assertEqual([m["id"] for m in json.loads(out)], ["msys-slash-flag"])

    def test_list_shows_every_trap(self):
        code, out = run_cli("list")
        self.assertEqual(code, 0)
        for t in TRAPS:
            self.assertIn(t.id, out)

    def test_install_hook_prints_snippet_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            old = os.getcwd()
            os.chdir(d)
            try:
                code, out = run_cli("install-hook", "--project")
            finally:
                os.chdir(old)
            self.assertEqual(os.listdir(d), [])
        self.assertEqual(code, 0)
        body = "\n".join(line for line in out.splitlines() if not line.startswith("#"))
        snippet = json.loads(body)
        entry = snippet["hooks"]["PreToolUse"][0]
        self.assertEqual(entry["matcher"], "Bash|PowerShell")
        self.assertEqual(entry["hooks"][0]["command"], "wintraps-hook")


if __name__ == "__main__":
    unittest.main()
