"""wintraps command line: check a command, list the catalog, print the hook settings snippet."""

from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
from typing import List, Optional

from . import __version__
from .catalog import BLOCK, TRAPS, Context, check

HOOK_SNIPPET = {
    "hooks": {
        "PreToolUse": [
            {
                "matcher": "Bash|PowerShell",
                "hooks": [{"type": "command", "command": "wintraps-hook", "timeout": 30}],
            }
        ]
    }
}


def _print(text: str) -> None:
    # The console may be cp1252; never crash on output.
    sys.stdout.write(text.encode("ascii", "replace").decode("ascii") + "\n")


def cmd_check(args: argparse.Namespace) -> int:
    ctx = Context(shell=args.shell, cwd=args.cwd or os.getcwd())
    matches = check(args.command, ctx)
    if args.json:
        _print(json.dumps([
            {"id": m.trap.id, "severity": m.trap.severity, "detail": m.detail, "why": m.trap.why,
             "safe": m.trap.safe, "sources": list(m.trap.sources)}
            for m in matches
        ], indent=2))
    elif not matches:
        _print("No known Windows traps matched.")
    else:
        for m in matches:
            _print("%s  %s  (%s)" % (m.trap.severity.upper(), m.trap.title, m.trap.id))
            _print("  Found: " + m.detail)
            _print("  Why:   " + m.trap.why)
            _print("  Safe:  " + m.trap.safe)
            _print("  Source: " + m.trap.sources[0])
    if any(m.trap.severity == BLOCK for m in matches):
        return 2
    return 1 if matches else 0


def cmd_list(args: argparse.Namespace) -> int:
    rows = [("ID", "SEVERITY", "APPLIES TO", "STATUS", "TITLE")]
    for t in TRAPS:
        rows.append((t.id, t.severity, ",".join(t.applies_to), t.status, t.title))
    widths = [max(len(r[i]) for r in rows) for i in range(4)]
    for r in rows:
        _print("  ".join(r[i].ljust(widths[i]) for i in range(4)) + "  " + r[4])
    if args.verbose:
        for t in TRAPS:
            _print("")
            _print("%s: %s" % (t.id, t.title))
            for label, value in (("Why", t.why), ("Safe", t.safe)):
                _print(textwrap.fill(value, 100, initial_indent="  %s: " % label, subsequent_indent="        "))
            for s in t.sources:
                _print("  Source: " + s)
    return 0


def cmd_install_hook(args: argparse.Namespace) -> int:
    target = ".claude/settings.json in your project" if args.project else "~/.claude/settings.json"
    _print("# win-traps does not edit settings files. Merge this into %s:" % target)
    _print(json.dumps(HOOK_SNIPPET, indent=2))
    _print("# If `wintraps-hook` is not on PATH, use: \"command\": \"python -m wintraps.hook\"")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wintraps", description="Catch Windows silent-damage traps in agent shell commands.")
    parser.add_argument("--version", action="version", version="win-traps " + __version__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("check", help="check one command; exit 0 = clean, 1 = warn, 2 = block")
    p.add_argument("command")
    p.add_argument("--shell", choices=("bash", "powershell"), default="bash")
    p.add_argument("--cwd", help="directory the command would run in (default: current)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("list", help="show the trap catalog")
    p.add_argument("-v", "--verbose", action="store_true", help="include why, safe alternative and sources")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("install-hook", help="print the Claude Code settings snippet (does not modify files)")
    scope = p.add_mutually_exclusive_group()
    scope.add_argument("--project", action="store_true", help="snippet for .claude/settings.json")
    scope.add_argument("--user", action="store_true", help="snippet for ~/.claude/settings.json")
    p.set_defaults(func=cmd_install_hook)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
