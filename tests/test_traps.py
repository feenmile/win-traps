"""Per-trap tests: commands that MUST match and near-miss commands that must NOT match.

Each case becomes its own test method named test_<trap_id>_match_<n> or test_<trap_id>_miss_<n>, so a
failure names the trap (scripts/sabotage.py relies on that).
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from wintraps.catalog import TRAPS, TRAPS_BY_ID, check, default_find_junctions
from tests.helpers import PROJ, SCRATCH, FakeFS, FakeGit, ctx

STORE_STUB = r"D:\apps\Microsoft\WindowsApps\python3.exe"
REAL_PY3 = r"D:\Python313\python3.exe"
WT = os.path.join(PROJ, "wt")
JUNCTION = os.path.join(WT, "node_modules")

CASES = {
    "os-kill-zero": {
        "match": [
            ('python -c "import os; os.kill(1234, 0)"', {}),
            ("python - <<'EOF'\nimport os\nalive = os.kill(int(pid), 0)\nEOF", {}),
            ('python -c "from os import getpid, kill; kill(pid, 0)"', {"shell": "powershell"}),
        ],
        "miss": [
            ('python -c "import os, signal; os.kill(pid, signal.SIGTERM)"', {}),
            ('python -c "import os; os.killpg(pgid, 0)"', {}),
            ('python -c "import psutil; print(psutil.pid_exists(pid))"', {}),
            ('python -c "import os; os.kill(pid, 10)"', {}),
        ],
    },
    "stash-noop-pop": {
        "match": [
            ("git stash push -- src/app.py", {"git_status": FakeGit("")}),
            ("git stash && git stash pop", {"git_status": FakeGit("")}),
            ("cd scratch && git stash push -m check src/a.py; git stash pop", {"git_status": FakeGit("")}),
        ],
        "miss": [
            ("git stash push -- src/app.py", {"git_status": FakeGit(" M src/app.py\n")}),
            ("git stash pop", {"git_status": FakeGit("")}),
            ("git stash list", {"git_status": FakeGit("")}),
            ("git stash push -- src/app.py", {"git_status": FakeGit(None)}),  # not a repo: git fails loudly
            ("git stash push --staged", {"git_status": FakeGit(" M only-unstaged.txt\n")}),  # git exits 1: loud
        ],
    },
    "heredoc-unquoted": {
        "match": [
            ("cat <<EOF > check.py\n" + r'PAT = "\\bword\\b"' + "\nEOF", {}),
            ("cat <<EOF > run.js\nconsole.log(`${name}`)\nEOF", {}),
            ("cat <<-EOF\n\techo $HOME\n\tEOF", {}),
        ],
        "miss": [
            ("cat <<'EOF' > check.py\n" + r'PAT = "\\bword\\b"' + "\nEOF", {}),
            ('cat <<"EOF"\necho $HOME\nEOF', {}),
            ("cat <<EOF > note.txt\n" + r"plain text, C:\project\file.txt" + "\nEOF", {}),
            ('cat <<<"$HOME"; echo $((1<<3))', {}),
            ("cat <<EOF\n" + r'PAT = "\\b"' + "\nEOF", {"shell": "powershell"}),
        ],
    },
    "msys-slash-flag": {
        "match": [
            ("taskkill /F /IM node.exe", {}),
            ("cmd /c dir", {}),
            ("robocopy src dst /MIR && echo done", {}),
            ("'taskkill.exe' '/PID' 1234", {}),
        ],
        "miss": [
            ("taskkill //F //IM node.exe", {}),
            ("MSYS_NO_PATHCONV=1 taskkill /F /IM node.exe", {}),
            ("export MSYS_NO_PATHCONV=1; taskkill /F /IM node.exe", {}),
            ("ls /usr/bin", {}),
            ("taskkill /F /IM node.exe", {"environ": {"MSYS_NO_PATHCONV": "1"}}),
            ("taskkill /F /IM node.exe", {"shell": "powershell"}),
        ],
    },
    "npm-walks-up": {
        "match": [
            ("npm install left-pad", {"cwd": SCRATCH, "exists": FakeFS(os.path.join(PROJ, "package.json"))}),
            ("cd scratch && npm i -D typescript", {"exists": FakeFS(os.path.join(PROJ, "package.json"))}),
            ("npm ci", {"cwd": SCRATCH, "exists": FakeFS(os.path.join(PROJ, "node_modules"))}),
        ],
        "miss": [
            ("npm install left-pad", {"cwd": SCRATCH, "exists": FakeFS(os.path.join(SCRATCH, "package.json"), os.path.join(PROJ, "package.json"))}),
            ("npm install --prefix . left-pad", {"cwd": SCRATCH, "exists": FakeFS(os.path.join(PROJ, "package.json"))}),
            ("npm install -g npm-check", {"cwd": SCRATCH, "exists": FakeFS(os.path.join(PROJ, "package.json"))}),
            ("npm run build", {"cwd": SCRATCH, "exists": FakeFS(os.path.join(PROJ, "package.json"))}),
            ("npm install left-pad", {"cwd": SCRATCH, "exists": FakeFS()}),
        ],
    },
    "python-isolated-encoding": {
        "match": [
            ("python -I script.py", {}),
            ('python3.12 -I -c "print(1)"', {}),
            ("py -3 -I tool.py", {"shell": "powershell"}),
            ("python -IB tool.py < in.json", {}),
        ],
        "miss": [
            ("python -I -X utf8 script.py", {}),
            ("python -X utf8 -I script.py", {}),
            ("python script.py -I", {}),
            ("pip install -I requests", {}),
        ],
    },
    "text-mode-write": {
        "match": [
            ("python -c \"from pathlib import Path; Path('o.txt').write_text(data)\"", {}),
            ("python -c \"open(p, 'w').write(s)\"", {}),
            ("python -c \"f = open('out.json', mode='a')\"", {"shell": "powershell"}),
            ("python -c \"from pathlib import Path; Path(p).open('w')\"", {}),
        ],
        "miss": [
            ("python -c \"from pathlib import Path; Path('o.txt').write_text(data, newline='')\"", {}),
            ("python -c \"open(p, 'wb').write(b)\"", {}),
            ("python -c \"open(p, 'w', newline='').write(s)\"", {}),
            ("python -c \"print(open('w.txt').read())\"", {}),
            ("python -c \"import codecs; codecs.open(p, 'w', 'utf-8')\"", {}),
        ],
    },
    "python3-store-alias": {
        "match": [
            ("python3 script.py > out.json", {"which": lambda n: STORE_STUB}),
            ("python3 --version", {"which": lambda n: None}),
            ("cd tools; python3 -m pip list", {"shell": "powershell", "which": lambda n: STORE_STUB}),
        ],
        "miss": [
            ("python3 script.py", {"which": lambda n: REAL_PY3}),
            ("python script.py", {"which": lambda n: STORE_STUB}),
            ("py -3 script.py", {"which": lambda n: STORE_STUB}),
            ("echo python3", {"which": lambda n: STORE_STUB}),
            ("/usr/bin/python3 script.py", {"which": lambda n: None}),
        ],
    },
    "worktree-junction": {
        "match": [
            ("git worktree remove --force wt", {"find_junctions": lambda p: ([JUNCTION], True)}),
            ("git -C . worktree remove wt", {"find_junctions": lambda p: ([JUNCTION], True)}),
            ("git worktree remove --force wt", {"find_junctions": lambda p: ([], False)}),
        ],
        "miss": [
            ("git worktree remove --force wt", {"find_junctions": lambda p: ([], True)}),
            ("git worktree list", {"find_junctions": lambda p: ([JUNCTION], True)}),
            ("git worktree add ../wt2", {"find_junctions": lambda p: ([JUNCTION], True)}),
            ("Remove-Item -Recurse -Force wt", {"shell": "powershell", "find_junctions": lambda p: ([JUNCTION], True)}),
        ],
    },
}


class TrapCaseTests(unittest.TestCase):
    def test_every_trap_has_cases(self):
        self.assertEqual(set(CASES), set(TRAPS_BY_ID))
        for trap_id, cases in CASES.items():
            self.assertGreaterEqual(len(cases["match"]), 2, trap_id)
            self.assertGreaterEqual(len(cases["miss"]), 2, trap_id)

    def test_catalog_fields_complete(self):
        for t in TRAPS:
            self.assertIn(t.severity, ("block", "warn"), t.id)
            self.assertIn(t.status, ("verified", "observed"), t.id)
            self.assertTrue(t.why and t.safe and t.sources and t.title, t.id)
            for s in t.sources:
                self.assertTrue(s.startswith("https://"), s)
            for a in t.applies_to:
                self.assertIn(a, ("bash", "powershell", "python-code", "any"))


def _make(trap_id, command, kwargs, expect):
    def test(self):
        trap = TRAPS_BY_ID[trap_id]
        matches = check(command, ctx(**kwargs), traps=[trap])
        if expect:
            self.assertEqual([m.trap.id for m in matches], [trap_id], "should match: %r" % command)
            self.assertTrue(matches[0].detail)
        else:
            self.assertEqual(matches, [], "should NOT match: %r" % command)
    return test


for _trap_id, _cases in CASES.items():
    for _kind, _expect in (("match", True), ("miss", False)):
        for _n, (_command, _kwargs) in enumerate(_cases[_kind], start=1):
            _name = "test_%s_%s_%d" % (_trap_id.replace("-", "_"), _kind, _n)
            setattr(TrapCaseTests, _name, _make(_trap_id, _command, _kwargs, _expect))


class ContextDetailTests(unittest.TestCase):
    def test_stash_checks_the_cd_directory_and_paths(self):
        git = FakeGit("")
        check("cd scratch && git stash push -- a.txt", ctx(git_status=git), traps=[TRAPS_BY_ID["stash-noop-pop"]])
        self.assertEqual(git.calls, [(SCRATCH, ["--untracked-files=no"], ["a.txt"])])

    def test_stash_include_untracked_asks_for_untracked(self):
        git = FakeGit("?? new.txt\n")
        matches = check("git stash -u", ctx(git_status=git), traps=[TRAPS_BY_ID["stash-noop-pop"]])
        self.assertEqual(matches, [])
        self.assertEqual(git.calls[0][1], ["--untracked-files=all"])

    def test_npm_detail_names_the_parent(self):
        m = check("npm install x", ctx(cwd=SCRATCH, exists=FakeFS(os.path.join(PROJ, "package.json"))),
                  traps=[TRAPS_BY_ID["npm-walks-up"]])
        self.assertIn(PROJ, m[0].detail)

    def test_worktree_scans_the_resolved_path(self):
        seen = []
        check("git worktree remove --force wt", ctx(find_junctions=lambda p: (seen.append(p), ([], True))[1]),
              traps=[TRAPS_BY_ID["worktree-junction"]])
        self.assertEqual(seen, [WT])

    def test_allow_marker_skips_only_that_trap(self):
        cmd = 'python -I -c "import os; os.kill(1, 0)"  # wintraps:allow=os-kill-zero'
        ids = [m.trap.id for m in check(cmd, ctx())]
        self.assertNotIn("os-kill-zero", ids)
        self.assertIn("python-isolated-encoding", ids)


GIT = shutil.which("git")


@unittest.skipUnless(GIT, "git not installed")
class RealGitStashTests(unittest.TestCase):
    """The default git_status against a real repository."""

    def setUp(self):
        self.repo = tempfile.mkdtemp(prefix="wintraps-git-")
        self.addCleanup(shutil.rmtree, self.repo, ignore_errors=True)
        run = lambda *a: subprocess.run(["git", "-C", self.repo, *a], check=True, capture_output=True)
        run("init", "-q")
        with open(os.path.join(self.repo, "a.txt"), "wb") as f:
            f.write(b"one\n")
        run("add", "a.txt")
        run("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", "init")

    def _check(self, command):
        from wintraps.catalog import Context
        return check(command, Context(shell="bash", cwd=self.repo), traps=[TRAPS_BY_ID["stash-noop-pop"]])

    def test_real_unmodified_file_matches(self):
        self.assertEqual(len(self._check("git stash push -- a.txt")), 1)

    def test_real_modified_file_does_not_match(self):
        with open(os.path.join(self.repo, "a.txt"), "wb") as f:
            f.write(b"two\n")
        self.assertEqual(self._check("git stash push -- a.txt"), [])

    def test_real_git_confirms_no_entry_is_created(self):
        proc = subprocess.run(["git", "-C", self.repo, "stash", "push", "--", "a.txt"], capture_output=True)
        self.assertEqual(proc.returncode, 0)
        listing = subprocess.run(["git", "-C", self.repo, "stash", "list"], capture_output=True, check=True)
        self.assertEqual(listing.stdout, b"")


@unittest.skipUnless(sys.platform == "win32", "junctions are Windows-only")
class RealJunctionTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="wintraps-jn-")
        self.addCleanup(self._cleanup)
        self.target = os.path.join(self.root, "target")
        self.wt = os.path.join(self.root, "wt")
        os.makedirs(os.path.join(self.wt, "pkg"))
        os.makedirs(self.target)
        with open(os.path.join(self.target, "keep.txt"), "wb") as f:
            f.write(b"keep\n")

    links = ()

    def _cleanup(self):
        # Unlink junctions first so cleanup can never delete through them.
        for link in self.links:
            os.rmdir(link)
        shutil.rmtree(self.root, ignore_errors=True)

    def _junction(self, link):
        subprocess.run(["cmd", "/c", "mklink", "/J", link, self.target], check=True, capture_output=True)
        self.links = self.links + (link,)

    def test_finds_a_nested_junction(self):
        link = os.path.join(self.wt, "pkg", "node_modules")
        self._junction(link)
        found, complete = default_find_junctions(self.wt)
        self.assertEqual(found, [link])
        self.assertTrue(complete)
        self.assertTrue(os.path.exists(os.path.join(self.target, "keep.txt")))

    def test_no_junction_found_in_plain_tree(self):
        self.assertEqual(default_find_junctions(self.wt), ([], True))

    def test_entry_budget_reports_incomplete(self):
        for i in range(5):
            os.makedirs(os.path.join(self.wt, "d%d" % i))
        self.assertEqual(default_find_junctions(self.wt, max_entries=3), ([], False))


if __name__ == "__main__":
    unittest.main()
