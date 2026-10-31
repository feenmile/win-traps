"""Claude Code PreToolUse hook for the Bash and PowerShell tools.

Reads the hook JSON from stdin and, when a command matches a trap:

* block-severity traps -> ``permissionDecision: "deny"`` with the reason (Claude sees it and can rewrite);
* warn-severity traps  -> ``additionalContext`` only (the normal permission flow applies), or
  ``permissionDecision: "ask"`` when ``WINTRAPS_WARN=ask`` is set.

It is active only on Windows unless ``WINTRAPS_FORCE=1``. It never fails the tool call: on any internal
error it prints a note to stderr and exits 0 with no output, which lets the call proceed.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Mapping, Optional, Sequence, Tuple

from .catalog import BLOCK, TRAPS, Context, Match, Trap, check

TOOL_SHELLS = {"Bash": "bash", "PowerShell": "powershell"}


def _format(matches: Sequence[Match]) -> str:
    parts = []
    for m in matches:
        parts.append(
            "[win-traps:%s] %s. %s Why: %s Safe alternative: %s Source: %s"
            % (m.trap.id, m.trap.title, m.detail[:1].upper() + m.detail[1:] + ".", m.trap.why, m.trap.safe, m.trap.sources[0])
        )
    parts.append("If this is a false positive, add the comment `wintraps:allow=<trap-id>` to the command.")
    return "\n".join(parts)


def decide(
    payload: Mapping,
    environ: Mapping[str, str],
    platform: str,
    traps: Sequence[Trap] = TRAPS,
    ctx_factory=Context,
) -> Optional[dict]:
    """Return the hook output object, or None for "no opinion" (exit 0, print nothing)."""
    if platform != "win32" and environ.get("WINTRAPS_FORCE") != "1":
        return None
    shell = TOOL_SHELLS.get(payload.get("tool_name", ""))
    if shell is None:
        return None
    tool_input = payload.get("tool_input") or {}
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return None
    cwd = payload.get("cwd")
    ctx = ctx_factory(shell=shell, cwd=cwd if isinstance(cwd, str) else None)
    matches = check(command, ctx, traps)
    if not matches:
        return None
    blocking = [m for m in matches if m.trap.severity == BLOCK]
    out = {"hookEventName": "PreToolUse"}
    if blocking:
        out["permissionDecision"] = "deny"
        out["permissionDecisionReason"] = _format(blocking + [m for m in matches if m not in blocking])
    elif environ.get("WINTRAPS_WARN", "").lower() == "ask":
        out["permissionDecision"] = "ask"
        out["permissionDecisionReason"] = _format(matches)
    else:
        out["additionalContext"] = _format(matches)
    return {"hookSpecificOutput": out}


def run(stdin_text: str, environ: Mapping[str, str], platform: str, **kwargs) -> Tuple[str, str, int]:
    """Pure entry point: returns (stdout, stderr, exit_code). Never raises."""
    try:
        payload = json.loads(stdin_text)
        if not isinstance(payload, dict):
            raise ValueError("hook input is not a JSON object")
        result = decide(payload, environ, platform, **kwargs)
    except Exception as exc:  # never break the agent
        return "", "win-traps: internal error, allowing the command: %s: %s\n" % (type(exc).__name__, exc), 0
    if result is None:
        return "", "", 0
    return json.dumps(result, ensure_ascii=True), "", 0


def main() -> int:
    try:
        raw = sys.stdin.buffer.read().decode("utf-8", "replace")
    except Exception as exc:
        sys.stderr.write("win-traps: could not read stdin, allowing the command: %s\n" % exc)
        return 0
    out, err, code = run(raw, os.environ, sys.platform)
    if err:
        sys.stderr.write(err)
    if out:
        sys.stdout.write(out + "\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
