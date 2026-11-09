"""The win-traps catalog.

Each trap is a command that looks fine, often works on Linux, and silently does the wrong thing when an
AI coding agent runs it on Windows. A trap has a matcher that inspects a shell command *before* it runs.

Matchers are deliberately cheap: regular expressions over the command text, plus a few small context
checks (``git status`` for an unmodified path, a ``package.json`` lookup, a junction scan, a PATH lookup).
They are not a shell parser and can be bypassed; see the README for the limits.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import stat
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple

BLOCK = "block"
WARN = "warn"

ALLOW_MARKER = re.compile(r"wintraps:allow=([A-Za-z0-9_,-]+)")


# ---------------------------------------------------------------------------------------------------
# Context: everything a matcher may look at besides the command text. Tests replace these callables.
# ---------------------------------------------------------------------------------------------------


def default_git_status(directory: str, options: Sequence[str], paths: Sequence[str]) -> Optional[str]:
    """Return ``git status --porcelain`` output for ``paths`` in ``directory``, or None if unknown."""
    argv = ["git", "-C", directory, "status", "--porcelain", *options, "--", *paths]
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", "replace")


def is_junction_stat(st: os.stat_result) -> bool:
    tag = getattr(st, "st_reparse_tag", 0)
    mount_point = getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", None)
    return mount_point is not None and tag == mount_point


def default_find_junctions(root: str, max_depth: int = 64, max_entries: int = 50000) -> Tuple[List[str], bool]:
    """Find directory junctions under ``root``. Returns (junction paths, scan_complete).

    Junctions are not descended into. ``.git`` is skipped. If the entry budget runs out, or a
    directory is left unscanned because it sits at ``max_depth``, the scan is reported incomplete,
    so the caller can refuse rather than guess.
    """
    if os.name != "nt" or not os.path.isdir(root):
        return [], True
    try:
        if is_junction_stat(os.stat(root, follow_symlinks=False)):
            return [root], True
    except OSError:
        return [], False
    found: List[str] = []
    seen = 0
    stack = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError:
            return found, False
        for entry in entries:
            seen += 1
            if seen > max_entries:
                return found, False
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                return found, False
            if is_junction_stat(st):
                found.append(entry.path)
                continue
            if entry.name == ".git":
                continue
            if stat.S_ISDIR(st.st_mode):
                if depth + 1 >= max_depth:
                    return found, False
                stack.append((entry.path, depth + 1))
    return found, True


@dataclass
class Context:
    """What a matcher may consult besides the command text."""

    shell: str = "bash"  # "bash" or "powershell"
    cwd: Optional[str] = None
    git_status: Callable[[str, Sequence[str], Sequence[str]], Optional[str]] = default_git_status
    which: Callable[[str], Optional[str]] = shutil.which
    exists: Callable[[str], bool] = os.path.exists
    find_junctions: Callable[[str], Tuple[List[str], bool]] = default_find_junctions
    environ: Mapping[str, str] = field(default_factory=lambda: dict(os.environ))


# ---------------------------------------------------------------------------------------------------
# Small command parser: split into segments, tokenize, track `cd`.
# ---------------------------------------------------------------------------------------------------


@dataclass
class Segment:
    raw: str
    argv: List[str]
    env: Dict[str, str]
    cwd: Optional[str]


def split_segments(command: str, shell: str) -> List[str]:
    """Split on ``&&``, ``||``, ``;``, ``|``, newlines (and ``&`` in bash), outside quotes."""
    escape = "\\" if shell == "bash" else "`"
    segments: List[str] = []
    buf: List[str] = []
    quote: Optional[str] = None
    i, n = 0, len(command)
    while i < n:
        ch = command[i]
        if quote:
            buf.append(ch)
            if ch == escape and quote == '"' and i + 1 < n:
                buf.append(command[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch == escape and i + 1 < n:
            buf.append(ch)
            buf.append(command[i + 1])
            i += 2
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if command.startswith("&&", i) or command.startswith("||", i):
            segments.append("".join(buf))
            buf = []
            i += 2
            continue
        if ch in ";|\n" or (ch == "&" and shell == "bash"):
            prev = command[i - 1] if i else ""
            nxt = command[i + 1] if i + 1 < n else ""
            if ch == "&" and (prev in "<>" or nxt == ">"):
                buf.append(ch)  # 2>&1, &> file
                i += 1
                continue
            segments.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    segments.append("".join(buf))
    return [s for s in segments if s.strip()]


def tokenize(segment: str, shell: str) -> List[str]:
    lexer = shlex.shlex(segment, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = "#"
    if shell != "bash":
        lexer.escape = ""  # PowerShell does not use backslash escapes
    try:
        return list(lexer)
    except ValueError:
        return segment.split()


def command_name(token: str) -> str:
    name = re.split(r"[\\/]", token)[-1].lower()
    for suffix in (".exe", ".cmd", ".bat"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    return name


def resolve_path(base: Optional[str], path: str) -> Optional[str]:
    path = os.path.expanduser(path)
    if os.name == "nt":
        msys = re.fullmatch(r"/([A-Za-z])(/.*)?", path)
        if msys:
            path = msys.group(1).upper() + ":" + (msys.group(2) or "/")
    if os.path.isabs(path) or re.match(r"^[A-Za-z]:[\\/]", path):
        return os.path.normpath(path)
    if base is None:
        return None
    return os.path.normpath(os.path.join(base, path))


_CD_COMMANDS = {"cd", "chdir", "pushd", "set-location", "sl", "push-location"}
_ENV_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.S)


def parse_command(command: str, ctx: Context) -> List[Segment]:
    cwd = ctx.cwd
    out: List[Segment] = []
    for raw in split_segments(command, ctx.shell):
        tokens = tokenize(raw, ctx.shell)
        env: Dict[str, str] = {}
        while tokens and _ENV_ASSIGN.match(tokens[0]):
            key, value = _ENV_ASSIGN.match(tokens[0]).groups()  # type: ignore[union-attr]
            env[key] = value
            tokens = tokens[1:]
        if tokens and tokens[0] in ("&", ".", "command", "exec", "time"):
            tokens = tokens[1:]
        out.append(Segment(raw=raw, argv=tokens, env=env, cwd=cwd))
        if tokens and command_name(tokens[0]) in _CD_COMMANDS:
            args = [t for t in tokens[1:] if not t.startswith("-")]
            if args:
                cwd = resolve_path(cwd, args[0])
    return out


def git_subcommand(seg: Segment) -> Tuple[Optional[str], int]:
    """For a ``git`` segment, return (directory git runs in, index of the subcommand) or (None, -1)."""
    argv = seg.argv
    if not argv or command_name(argv[0]) != "git":
        return None, -1
    directory = seg.cwd
    i = 1
    while i < len(argv) and argv[i].startswith("-"):
        if argv[i] == "-C" and i + 1 < len(argv):
            directory = resolve_path(directory, argv[i + 1])
            i += 2
            continue
        if argv[i] in ("-c", "--git-dir", "--work-tree", "--namespace", "--exec-path") and i + 1 < len(argv):
            i += 2
            continue
        i += 1
    if i >= len(argv):
        return None, -1
    return directory, i  # directory may be None when the cwd is unknown


def call_args(text: str, open_paren: int) -> str:
    """Return the text between ``text[open_paren]`` == '(' and its matching ')', quote-aware."""
    depth = 0
    quote: Optional[str] = None
    i = open_paren
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1 : i]
        i += 1
    return text[open_paren + 1 :]


# ---------------------------------------------------------------------------------------------------
# Matchers. Each returns None (no match) or a one-line detail naming what it found.
# ---------------------------------------------------------------------------------------------------

_KILL_ARG = r"\s*(?:[^,()]|\([^()]*\))+,\s*0\s*\)"
_OS_KILL_ZERO = re.compile(r"\bos\.kill\s*\(" + _KILL_ARG)
_FROM_OS_IMPORT_KILL = re.compile(r"\bfrom\s+os\s+import\s+[^\n;]*\bkill\b")
_BARE_KILL_ZERO = re.compile(r"(?<![\w.])kill\s*\(" + _KILL_ARG)


def match_os_kill_zero(command: str, ctx: Context) -> Optional[str]:
    m = _OS_KILL_ZERO.search(command)
    if m:
        return "found `%s`" % m.group(0).strip()
    if _FROM_OS_IMPORT_KILL.search(command):
        m = _BARE_KILL_ZERO.search(command)
        if m:
            return "found `%s` (imported from os)" % m.group(0).strip()
    return None


def match_stash_noop(command: str, ctx: Context) -> Optional[str]:
    for seg in parse_command(command, ctx):
        directory, i = git_subcommand(seg)
        if i < 0 or directory is None or seg.argv[i] != "stash":
            continue
        rest = seg.argv[i + 1 :]
        action = "push"
        if rest and not rest[0].startswith("-"):
            if rest[0] not in ("push", "save"):
                continue
            action, rest = rest[0], rest[1:]
        # --staged with nothing staged exits 1 ("No staged changes"): loud, so not this trap.
        untracked, paths, after_dashdash, unknowable = "no", [], False, False
        j = 0
        while j < len(rest):
            tok = rest[j]
            if after_dashdash:
                paths.append(tok)
            elif tok == "--":
                after_dashdash = True
            elif tok in ("-m", "--message"):
                j += 1
            elif tok in ("-u", "--include-untracked"):
                untracked = "all"
            elif tok in ("-a", "--all", "-S", "--staged") or tok.startswith("--pathspec-from-file"):
                unknowable = True
            elif tok.startswith("-"):
                pass
            elif action == "push":
                paths.append(tok)
            j += 1
        if unknowable:
            continue
        status = ctx.git_status(directory, ["--untracked-files=" + untracked], paths)
        if status is None:
            continue
        lines = [ln for ln in status.splitlines() if ln.strip()]
        if not lines:
            where = " ".join(paths) if paths else "the working tree"
            return "nothing to stash in %s (git status --porcelain is empty), so no stash entry is created" % where
    return None


_HEREDOC = re.compile(r"(?<![<\w])<<(-?)[ \t]*(\\?)(['\"]?)([A-Za-z_][A-Za-z0-9_.-]*)(['\"]?)")


def match_heredoc_unquoted(command: str, ctx: Context) -> Optional[str]:
    for m in _HEREDOC.finditer(command):
        dash, backslash, q1, delim, q2 = m.groups()
        if backslash or q1 or q2:
            continue  # quoted delimiter: body is literal
        line_end = command.find("\n", m.end())
        if line_end < 0:
            continue
        body_lines: List[str] = []
        for line in command[line_end + 1 :].split("\n"):
            if (line.lstrip("\t") if dash else line).rstrip("\r") == delim:
                break
            body_lines.append(line)
        body = "\n".join(body_lines)
        problems = []
        if re.search(r"\\[\\$`]", body):
            problems.append(r"`\\`, `\$` or `\`` lose their backslash")
        if re.search(r"\\\r?$", body, re.M):
            problems.append("a trailing `\\` joins the next line")
        if re.search(r"(?<!\\)\$[A-Za-z_{(0-9@*#?!$-]", body):
            problems.append("`$...` is expanded")
        if re.search(r"(?<!\\)`", body):
            problems.append("backticks run as command substitution")
        if problems:
            return "unquoted heredoc `<<%s%s`: %s" % (dash, delim, "; ".join(problems))
    return None


WINDOWS_SLASH_TOOLS = {
    "attrib", "bcdedit", "cacls", "certutil", "choice", "cmd", "dism", "forfiles", "gpupdate", "icacls",
    "ipconfig", "msiexec", "netsh", "reg", "robocopy", "runas", "sc", "schtasks", "setx", "sfc", "shutdown",
    "subst", "systeminfo", "takeown", "taskkill", "tasklist", "timeout", "where", "whoami", "wmic", "xcopy",
    "findstr", "explorer", "net",
}
_SLASH_FLAG = re.compile(r"/[A-Za-z?][A-Za-z0-9?:._-]*")
_EXPORT_NO_CONV = re.compile(r"\bexport\s+(?:MSYS_NO_PATHCONV=|MSYS2_ARG_CONV_EXCL=)")


def match_msys_slash_flag(command: str, ctx: Context) -> Optional[str]:
    if ctx.environ.get("MSYS_NO_PATHCONV") or ctx.environ.get("MSYS2_ARG_CONV_EXCL"):
        return None
    if _EXPORT_NO_CONV.search(command):
        return None
    for seg in parse_command(command, ctx):
        if not seg.argv or "MSYS_NO_PATHCONV" in seg.env or "MSYS2_ARG_CONV_EXCL" in seg.env:
            continue
        name = command_name(seg.argv[0])
        if name not in WINDOWS_SLASH_TOOLS:
            continue
        flags = [t for t in seg.argv[1:] if _SLASH_FLAG.fullmatch(t)]
        if flags:
            return "`%s` gets %s rewritten into Windows paths" % (name, ", ".join(flags[:4]))
    return None


_NPM_WRITE_COMMANDS = {
    "install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall", "add",
    "ci", "clean-install", "ic", "install-clean", "isntall-clean", "install-test", "it", "install-ci-test",
    "cit", "uninstall", "un", "unlink", "remove", "rm", "r", "update", "up", "upgrade", "udpate", "link",
    "ln", "prune", "dedupe", "ddp",
}
_NPM_ELSEWHERE = re.compile(r"^(?:-g|--global|--location(?:=global)?|--prefix(?:=.*)?|-C)$")


def match_npm_walks_up(command: str, ctx: Context) -> Optional[str]:
    for seg in parse_command(command, ctx):
        argv = seg.argv
        if not argv or command_name(argv[0]) != "npm":
            continue
        sub = next((t for t in argv[1:] if not t.startswith("-")), None)
        if sub not in _NPM_WRITE_COMMANDS:
            continue
        if any(_NPM_ELSEWHERE.match(t) for t in argv[1:]):
            continue
        if seg.cwd is None:
            continue
        here = os.path.normpath(seg.cwd)
        if ctx.exists(os.path.join(here, "package.json")) or ctx.exists(os.path.join(here, "node_modules")):
            continue
        child, parent = here, os.path.dirname(here)
        while parent and parent != child:
            for marker in ("package.json", "node_modules"):
                if ctx.exists(os.path.join(parent, marker)):
                    return "no package.json in %s; npm %s would use the project at %s (has %s)" % (
                        here, sub, parent, marker)
            child, parent = parent, os.path.dirname(parent)
    return None


_PYTHON_NAMES = re.compile(r"^(?:python(?:\d+(?:\.\d+)?)?|pythonw|py)$")


def _python_options(argv: Sequence[str]) -> Tuple[bool, List[str]]:
    """Return (isolated, -X values) from a python command line's interpreter options."""
    isolated, xopts = False, []
    i = 1
    while i < len(argv):
        tok = argv[i]
        if not tok.startswith("-") or tok in ("-", "--"):
            break
        if re.fullmatch(r"-\d+(?:\.\d+)?(?:-\d+)?", tok) or tok.startswith("-V:"):
            i += 1  # py launcher version selector
            continue
        if tok.startswith("--"):
            i += 1
            continue
        stop = False
        for k, ch in enumerate(tok[1:], start=1):
            if ch == "I":
                isolated = True
            elif ch in "XW":
                value = tok[k + 1 :]
                if not value and i + 1 < len(argv):
                    i += 1
                    value = argv[i]
                if ch == "X":
                    xopts.append(value)
                break
            elif ch in "cm":
                stop = True
                break
        if stop:
            break
        i += 1
    return isolated, xopts


def match_python_isolated_encoding(command: str, ctx: Context) -> Optional[str]:
    for seg in parse_command(command, ctx):
        if not seg.argv or not _PYTHON_NAMES.match(command_name(seg.argv[0])):
            continue
        isolated, xopts = _python_options(seg.argv)
        if not isolated:
            continue
        if any(x in ("utf8", "utf8=1") for x in xopts):
            continue
        return "`%s -I` ignores PYTHONIOENCODING and PYTHONUTF8" % command_name(seg.argv[0])
    return None


_WRITE_TEXT = re.compile(r"\.write_text\s*\(")
_OPEN_CALL = re.compile(r"(\.|\b)open\s*\(")
_STRING_LITERAL = re.compile(r"""(['"])([^'"\\]*)\1""")
_MODE = re.compile(r"[rwxabt+]{1,3}")


def match_text_mode_write(command: str, ctx: Context) -> Optional[str]:
    for m in _WRITE_TEXT.finditer(command):
        args = call_args(command, m.end() - 1)
        if not re.search(r"\bnewline\s*=", args):
            return "`.write_text(...)` without `newline=`"
    for m in _OPEN_CALL.finditer(command):
        start = m.start()
        if command[: start + 1].endswith("codecs."):
            continue  # codecs.open always opens in binary mode
        args = call_args(command, m.end() - 1).replace('\\"', '"').replace("\\'", "'")
        if re.search(r"\bnewline\s*=", args):
            continue
        is_method = m.group(1) == "."
        literals = [(lm.start(), lm.group(2)) for lm in _STRING_LITERAL.finditer(args)]
        for pos, value in literals:
            if not is_method and pos == len(args) - len(args.lstrip()):
                continue  # builtin open(): first argument is the file name
            if _MODE.fullmatch(value) and "b" not in value and set(value) & set("wax+"):
                return "`%sopen(..., %r)` writes in text mode without `newline=`" % ("." if is_method else "", value)
    return None


def match_python3_store_alias(command: str, ctx: Context) -> Optional[str]:
    for seg in parse_command(command, ctx):
        if not seg.argv:
            continue
        tok = seg.argv[0]
        if re.search(r"[\\/]", tok) or command_name(tok) != "python3":
            continue
        resolved = ctx.which("python3")
        if resolved is None:
            return "`python3` is not on PATH"
        if "\\windowsapps\\" in resolved.replace("/", "\\").lower():
            return "`python3` resolves to %s, an App Execution Alias (the Store stub unless the Store Python is installed)" % resolved
    return None


def match_worktree_junction(command: str, ctx: Context) -> Optional[str]:
    for seg in parse_command(command, ctx):
        directory, i = git_subcommand(seg)
        if i < 0 or seg.argv[i] != "worktree":
            continue
        rest = seg.argv[i + 1 :]
        if not rest or rest[0] != "remove":
            continue
        paths = [t for t in rest[1:] if not t.startswith("-")]
        if not paths:
            continue
        target = resolve_path(directory, paths[0])
        if target is None:
            continue
        found, complete = ctx.find_junctions(target)
        if found:
            shown = ", ".join(found[:3]) + (" ..." if len(found) > 3 else "")
            return "worktree %s contains junction(s): %s" % (target, shown)
        if not complete:
            return "could not finish scanning %s for junctions" % target
    return None


# ---------------------------------------------------------------------------------------------------
# The catalog.
# ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Trap:
    id: str
    title: str
    severity: str  # BLOCK or WARN
    applies_to: Tuple[str, ...]  # "bash", "powershell", "python-code", "any"
    status: str  # "verified" (official docs or reliable source) or "observed" (reproduced, no official doc)
    why: str
    safe: str
    sources: Tuple[str, ...]
    matcher: Callable[[str, Context], Optional[str]] = field(compare=False, repr=False)

    def applies(self, shell: str) -> bool:
        return "any" in self.applies_to or "python-code" in self.applies_to or shell in self.applies_to


TRAPS: Tuple[Trap, ...] = (
    Trap(
        id="os-kill-zero",
        title="Python os.kill(pid, 0) as a liveness probe",
        severity=BLOCK,
        applies_to=("python-code",),
        status="verified",
        why=(
            "On Windows signal 0 is CTRL_C_EVENT, so os.kill(pid, 0) calls GenerateConsoleCtrlEvent instead of "
            "probing: it returns None for live and dead pids alike (or raises OSError for both when there is no "
            "console). Other signal values call TerminateProcess and kill the target."
        ),
        safe="psutil.pid_exists(pid), or OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) + GetExitCodeProcess == STILL_ACTIVE (259).",
        sources=(
            "https://docs.python.org/3/library/os.html#os.kill",
            "https://github.com/python/cpython/blob/main/Modules/posixmodule.c (os_kill_impl)",
            "https://learn.microsoft.com/en-us/windows/console/generateconsolectrlevent",
        ),
        matcher=match_os_kill_zero,
    ),
    Trap(
        id="stash-noop-pop",
        title="git stash on unmodified files, then git stash pop",
        severity=BLOCK,
        applies_to=("any",),
        status="verified",
        why=(
            "When nothing matches, git stash prints 'No local changes to save', exits 0 and creates no entry. "
            "A later git stash pop then applies stash@{0}, which is someone else's older stash."
        ),
        safe="Check `git status --porcelain -- <path>` first, use `git diff -- <path>` to inspect, or `git stash create` + `git stash store` with an explicit ref.",
        sources=("https://git-scm.com/docs/git-stash",),
        matcher=match_stash_noop,
    ),
    Trap(
        id="heredoc-unquoted",
        title="Unquoted heredoc (<<EOF) rewrites backslashes and $",
        severity=BLOCK,
        applies_to=("bash",),
        status="verified",
        why=(
            "An unquoted heredoc body is expanded like a double-quoted string: $VAR, $(...) and backticks run, "
            "and \\\\, \\$ and \\` lose their backslash, so regexes, JSON and scripts are silently changed."
        ),
        safe="Quote the delimiter (`<<'EOF'`), or write the file with an editor/Write tool instead of the shell.",
        sources=("https://www.gnu.org/software/bash/manual/html_node/Redirections.html#Here-Documents",),
        matcher=match_heredoc_unquoted,
    ),
    Trap(
        id="msys-slash-flag",
        title="Git Bash converts /flags into paths",
        severity=BLOCK,
        applies_to=("bash",),
        status="verified",
        why=(
            "Git Bash (MSYS2) rewrites arguments that look like POSIX paths before running a Windows program: "
            "`taskkill /F /IM x.exe` receives `F:/` and `C:/Program Files/Git/IM`."
        ),
        safe="Prefix `MSYS_NO_PATHCONV=1`, double the slash (`//F`), or run the command from PowerShell.",
        sources=(
            "https://github.com/git-for-windows/build-extra/blob/main/ReleaseNotes.md (Known issues)",
            "https://www.msys2.org/docs/filesystem-paths/",
        ),
        matcher=match_msys_slash_flag,
    ),
    Trap(
        id="npm-walks-up",
        title="npm install with no package.json installs into a parent project",
        severity=BLOCK,
        applies_to=("any",),
        status="verified",
        why=(
            "npm walks up from the current folder to the nearest folder with a package.json or node_modules and "
            "installs there, so a scratch install changes an unrelated parent project and its lock file."
        ),
        safe="Create a package.json first (`npm init -y`), or pass `--prefix <folder>`.",
        sources=("https://docs.npmjs.com/cli/v11/configuring-npm/folders",),
        matcher=match_npm_walks_up,
    ),
    Trap(
        id="python-isolated-encoding",
        title="python -I ignores PYTHONIOENCODING and PYTHONUTF8",
        severity=WARN,
        applies_to=("any",),
        status="verified",
        why=(
            "Isolated mode ignores every PYTHON* variable, so piped stdin/stdout fall back to the ANSI code page "
            "(often cp1252) and non-ASCII text crashes or turns into mojibake. Python 3.15+ defaults to UTF-8 mode."
        ),
        safe="Add `-X utf8` (a command-line option, so -I keeps it), or decode stdin bytes and reconfigure stdout in code.",
        sources=(
            "https://docs.python.org/3/using/cmdline.html#cmdoption-I",
            "https://peps.python.org/pep-0686/",
        ),
        matcher=match_python_isolated_encoding,
    ),
    Trap(
        id="text-mode-write",
        title="Python text-mode writes produce CRLF on Windows",
        severity=WARN,
        applies_to=("python-code",),
        status="verified",
        why=(
            "Text-mode writes translate every \\n to os.linesep (\\r\\n on Windows), which breaks byte-exact "
            "files, hashes, LF-pinned repos and source-text checks."
        ),
        safe='Use `write_bytes`, or pass `newline="\\n"` (or `newline=""`) to `open()` / `write_text()` (Python 3.10+).',
        sources=(
            "https://docs.python.org/3/library/functions.html#open",
            "https://docs.python.org/3/library/pathlib.html#pathlib.Path.write_text",
        ),
        matcher=match_text_mode_write,
    ),
    Trap(
        id="python3-store-alias",
        title="python3 runs the Microsoft Store alias stub",
        severity=WARN,
        applies_to=("any",),
        status="verified",
        why=(
            "On many Windows machines python3 is an App Execution Alias stub that prints 'Python was not found' "
            "and exits 9009 (49 in Git Bash), so redirected output files end up empty."
        ),
        safe="Use `python` or `py -3`, or turn off the python3 alias in Settings > Apps > Advanced app settings > App execution aliases.",
        sources=("https://docs.python.org/3/using/windows.html",),
        matcher=match_python3_store_alias,
    ),
    Trap(
        id="worktree-junction",
        title="git worktree remove deletes through a junction",
        severity=BLOCK,
        applies_to=("any",),
        status="observed",
        why=(
            "Observed with Git for Windows 2.51.0: `git worktree remove` (with --force, or without it when the "
            "junction is gitignored) deleted the files inside a junction's TARGET, e.g. a shared node_modules."
        ),
        safe="Remove each junction itself first (`cmd /c rmdir <junction>`, no /s), confirm it is gone, then remove the worktree.",
        sources=(
            "https://git-scm.com/docs/git-worktree",
            "https://docs.python.org/3/library/shutil.html#shutil.rmtree (same hazard, fixed in Python 3.8)",
        ),
        matcher=match_worktree_junction,
    ),
)

TRAPS_BY_ID: Dict[str, Trap] = {t.id: t for t in TRAPS}


@dataclass(frozen=True)
class Match:
    trap: Trap
    detail: str


def allowed_ids(command: str) -> set:
    ids = set()
    for m in ALLOW_MARKER.finditer(command):
        ids.update(x for x in m.group(1).split(",") if x)
    return ids


def check(command: str, ctx: Optional[Context] = None, traps: Sequence[Trap] = TRAPS) -> List[Match]:
    """Run every applicable trap's matcher over ``command``. Matcher exceptions propagate."""
    ctx = ctx or Context()
    skip = allowed_ids(command)
    matches = []
    for trap in traps:
        if trap.id in skip or not trap.applies(ctx.shell):
            continue
        detail = trap.matcher(command, ctx)
        if detail:
            matches.append(Match(trap, detail))
    return matches
