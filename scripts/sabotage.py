"""Sabotage check: prove the test suite notices when any one trap stops matching.

For each trap, copy the package and tests to a temp folder, make that trap's matcher return None as its
first statement, run the suite in the copy, and require that it FAILS with at least one failing test
named after that trap. The unmodified copy must pass first. The working tree is never modified.

Usage: python scripts/sabotage.py
"""

from __future__ import annotations

import ast
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from wintraps.catalog import TRAPS  # noqa: E402


def copy_tree(dest: str) -> None:
    for name in ("wintraps", "tests"):
        shutil.copytree(os.path.join(ROOT, name), os.path.join(dest, name),
                        ignore=shutil.ignore_patterns("__pycache__"))


def disable(catalog_path: str, func_name: str) -> None:
    with open(catalog_path, "rb") as f:
        source = f.read().decode("utf-8")
    tree = ast.parse(source)
    func = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == func_name)
    first = func.body[0]
    lines = source.split("\n")
    indent = " " * first.col_offset
    lines.insert(first.lineno - 1, indent + "return None  # SABOTAGED")
    patched = "\n".join(lines)
    ast.parse(patched)  # the sabotage must still be valid Python, or a "kill" would be fake
    with open(catalog_path, "wb") as f:
        f.write(patched.encode("utf-8"))


def run_suite(cwd: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.pop("WINTRAPS_FORCE", None)
    return subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", "."],
                          cwd=cwd, capture_output=True, env=env, timeout=600)


def failing_tests(output: str) -> list:
    return re.findall(r"^(?:FAIL|ERROR): (\w+)", output, re.M)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="wintraps-sabotage-") as tmp:
        base = os.path.join(tmp, "baseline")
        copy_tree(base)
        proc = run_suite(base)
        if proc.returncode != 0:
            print("Baseline copy FAILS; fix the suite before sabotaging it.")
            print(proc.stderr.decode("utf-8", "replace")[-3000:])
            return 1
        print("baseline: suite passes")
        caught = 0
        for trap in TRAPS:
            work = os.path.join(tmp, trap.id)
            copy_tree(work)
            disable(os.path.join(work, "wintraps", "catalog.py"), trap.matcher.__name__)
            proc = run_suite(work)
            output = proc.stderr.decode("utf-8", "replace")
            failed = failing_tests(output)
            named = [t for t in failed if t.startswith("test_" + trap.id.replace("-", "_"))]
            ok = proc.returncode != 0 and bool(named)
            caught += ok
            print("%-26s %s  (%d failing tests, %d named for this trap)" % (
                trap.id, "CAUGHT" if ok else "MISSED", len(failed), len(named)))
        print("sabotage: %d/%d traps caught" % (caught, len(TRAPS)))
        return 0 if caught == len(TRAPS) else 1


if __name__ == "__main__":
    sys.exit(main())
