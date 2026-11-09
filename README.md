# win-traps

**Catch the Windows commands that quietly do the wrong thing, before your AI coding agent runs them.**

AI coding agents learn their shell habits on Linux. On Windows, a handful of those habits do not fail: they
succeed and do something else. `os.kill(pid, 0)` says every process is alive. `git stash pop` restores
someone else's work. `npm install` edits a project two folders up. Nothing errors, so nobody notices.

win-traps is a small catalog of these traps plus a [Claude Code](https://code.claude.com/docs/en/hooks)
`PreToolUse` hook for the Bash and PowerShell tools. When a command matches, the hook explains why the command
bites and what to run instead, before it runs. Standard library only, Python 3.10+.

It is not a destructive-command guard. Tools like that block `rm -rf /` and data exfiltration; these traps are
the ones that look harmless.

## The catalog

Status **verified** means the behavior is documented by an official or reliable source (and was also reproduced
on Windows 11 while writing it). **observed** means it was reproduced but no official documentation was found.

| Trap (id) | Severity | Why it bites | Safe alternative | Source |
|---|---|---|---|---|
| Python `os.kill(pid, 0)` as a liveness probe (`os-kill-zero`) | block | On Windows signal 0 is `CTRL_C_EVENT`, so `os.kill(pid, 0)` calls `GenerateConsoleCtrlEvent` instead of probing. It returns `None` for live and dead pids alike (or raises `OSError` for both when there is no console). Other signal values call `TerminateProcess` and kill the target. | `psutil.pid_exists(pid)`, or `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `GetExitCodeProcess == STILL_ACTIVE` (259) | [Python os.kill](https://docs.python.org/3/library/os.html#os.kill), [CPython os_kill_impl](https://github.com/python/cpython/blob/main/Modules/posixmodule.c), [GenerateConsoleCtrlEvent](https://learn.microsoft.com/en-us/windows/console/generateconsolectrlevent) |
| `git stash` on unmodified files, then `git stash pop` (`stash-noop-pop`) | block | With nothing to stash, git prints "No local changes to save", exits 0 and creates no entry. The next `git stash pop` applies `stash@{0}`, which is someone else's older stash. | Check `git status --porcelain -- <path>` first, inspect with `git diff`, or use `git stash create` + `git stash store` with an explicit ref | [git-stash](https://git-scm.com/docs/git-stash) |
| Unquoted heredoc `<<EOF` (`heredoc-unquoted`, Bash tool only) | block | The body is expanded like a double-quoted string: `$VAR`, `$(...)` and backticks run, and `\\`, `\$`, `` \` `` lose their backslash. Regexes, JSON and generated scripts change silently. | Quote the delimiter: `<<'EOF'`. Or write the file with an editor tool | [Bash manual: Here Documents](https://www.gnu.org/software/bash/manual/html_node/Redirections.html#Here-Documents) |
| Git Bash converts `/flags` into paths (`msys-slash-flag`, Bash tool only) | block | MSYS2 rewrites arguments that look like POSIX paths before starting a Windows program: `taskkill /F /IM x.exe` receives `F:/` and `C:/Program Files/Git/IM`. | `MSYS_NO_PATHCONV=1 taskkill /F ...`, double the slash (`//F`), or use PowerShell | [Git for Windows release notes, Known issues](https://github.com/git-for-windows/build-extra/blob/main/ReleaseNotes.md), [MSYS2 paths](https://www.msys2.org/docs/filesystem-paths/) |
| `npm install` with no `package.json` (`npm-walks-up`) | block | npm walks up to the nearest folder with a `package.json` or `node_modules` and installs there, changing an unrelated parent project and its lock file. | `npm init -y` first, or `--prefix <folder>` | [npm folders](https://docs.npmjs.com/cli/v11/configuring-npm/folders) |
| `python -I` and encodings (`python-isolated-encoding`) | warn | Isolated mode ignores every `PYTHON*` variable, including `PYTHONIOENCODING` and `PYTHONUTF8`, so piped stdin/stdout use the ANSI code page (often cp1252) and non-ASCII text crashes or becomes mojibake. Python 3.15+ defaults to UTF-8 mode. | Add `-X utf8` (a command-line option, which `-I` keeps), or decode stdin bytes and reconfigure stdout in code | [Python -I](https://docs.python.org/3/using/cmdline.html#cmdoption-I), [PEP 686](https://peps.python.org/pep-0686/) |
| Python text-mode writes (`text-mode-write`) | warn | `open(p, "w")` and `Path.write_text()` translate `\n` to `\r\n` on Windows, breaking byte-exact files, hashes and LF-pinned repositories. | `write_bytes`, or `newline="\n"` / `newline=""` (`write_text` accepts it from Python 3.10) | [open()](https://docs.python.org/3/library/functions.html#open), [Path.write_text](https://docs.python.org/3/library/pathlib.html#pathlib.Path.write_text) |
| `python3` is the Store alias stub (`python3-store-alias`) | warn | On many machines `python3` is an App Execution Alias that prints "Python was not found" and exits 9009 (49 in Git Bash), so `python3 x.py > out.json` leaves an empty file. Only flagged when `python3` is missing from PATH or resolves into `WindowsApps`. | `python` or `py -3`, or turn the alias off in Settings > Apps > Advanced app settings > App execution aliases | [Using Python on Windows](https://docs.python.org/3/using/windows.html) |
| `git worktree remove` through a junction (`worktree-junction`) | block | **Observed** with Git for Windows 2.51.0: removing a worktree that contains a directory junction (for example a junctioned `node_modules`) deleted the files inside the junction's **target**. It happened with `--force`, and without it when the junction was gitignored. | Remove each junction itself first (`cmd /c rmdir <junction>`, no `/s`), confirm it is gone, then remove the worktree | [git-worktree](https://git-scm.com/docs/git-worktree); same hazard in [shutil.rmtree before Python 3.8](https://docs.python.org/3/library/shutil.html#shutil.rmtree) |

`wintraps list -v` prints the same catalog in the terminal.

### What was checked and is *not* in the catalog

Recursive deletes over a folder containing a junction did **not** delete the junction target on Windows 11 in
our test: `Remove-Item -Recurse -Force` (Windows PowerShell 5.1 and PowerShell 7.6), `cmd /c rmdir /s /q`,
Git Bash `rm -rf`, `git clean -ffdx` and Python 3.13 `shutil.rmtree`. They are left out rather than flagged on
rumor. Older tools behaved differently (Python before 3.8 deleted junction contents), so be careful with old
runtimes. `npx` is not flagged either: it installs missing packages into the npm cache, not the parent project
(it does run binaries from a parent project's `node_modules/.bin` if one exists).

## Install

From a clone:

```
pip install .
```

That gives you two commands: `wintraps` and `wintraps-hook`.

Print the Claude Code settings snippet (it does **not** edit any file):

```
wintraps install-hook --project
```

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell",
        "hooks": [{ "type": "command", "command": "wintraps-hook", "timeout": 30 }]
      }
    ]
  }
}
```

Merge it into `.claude/settings.json` (project) or `~/.claude/settings.json` (`--user`) yourself. If
`wintraps-hook` is not on PATH, use `"command": "python -m wintraps.hook"`.

## Use

```
wintraps check "taskkill /F /IM node.exe"
wintraps check --shell powershell --cwd C:\project "npm install left-pad"
wintraps check --json "python -I tool.py"
wintraps list -v
```

`check` exits 0 when nothing matched, 1 for warnings only, 2 when a block trap matched.

### What the hook returns

It follows the [PreToolUse decision format](https://code.claude.com/docs/en/hooks):

* **block** traps: `permissionDecision: "deny"` with a `permissionDecisionReason` naming the trap, why it bites,
  the safe alternative and a source. Claude reads the reason and can rewrite the command.
* **warn** traps: `additionalContext` only, so the normal permission flow applies. Set `WINTRAPS_WARN=ask` to get
  `permissionDecision: "ask"` (a prompt for you) instead.
* No match: no output, exit 0.

It is active only on Windows (`sys.platform == "win32"`). Set `WINTRAPS_FORCE=1` to run it elsewhere, for
testing. It never breaks the agent: on bad input or an internal error it writes a note to stderr, prints nothing
and exits 0, so the command proceeds.

For a false positive, add the comment `wintraps:allow=<trap-id>` to the command, for example
`cat <<EOF > env.sh  # wintraps:allow=heredoc-unquoted` when you really want the expansion.

## Honest limits

* **Pattern matching, not a shell.** Commands are split on `&&`, `||`, `;`, `|` and newlines and tokenized with
  `shlex`. Variables, aliases, functions, `eval`, scripts on disk and generated commands are not followed. Anyone
  (or any agent) can write the same trap in a form the patterns miss, and the allow comment is a deliberate bypass.
* **Context checks are cheap and partial.** The stash check runs `git status --porcelain` (5 second timeout) and
  stays silent when git cannot answer. The npm check looks for `package.json`/`node_modules` on disk. The
  junction check scans the worktree to depth 64 and at most 50,000 entries; if it cannot finish (a budget runs out or a folder sits past the depth limit) it blocks and says so.
  The `python3` check trusts PATH as the hook process sees it.
* **Python-code traps only see code inside the command** (`python -c`, a heredoc piped to Python). Code written to
  a `.py` file with an editor tool is not inspected.
* **Windows only by default.** Several traps (heredocs, `npm`, `git stash`) also exist elsewhere, but the catalog
  and its wording target AI agents on Windows.
* **Behavior changes.** Python 3.15 makes UTF-8 mode the default; future Git for Windows releases may fix the
  junction behavior. Each entry cites what it was checked against.

## Tests

```
python -m unittest discover -s tests -t .
python scripts/sabotage.py
```

Every trap has commands that must match and near-misses that must not (`<<'EOF'`, `//F`, `newline=""`,
`--prefix`, `-X utf8`). `scripts/sabotage.py` disables each trap's matcher in a temporary copy and requires the
suite to fail with a test named after that trap. CI runs both on Windows and Ubuntu with Python 3.10 and 3.13.

See [docs/CONTRIBUTING-TRAPS.md](docs/CONTRIBUTING-TRAPS.md) to add a trap.

## License

MIT. Built by Feenmile. Mascot inspection by Mile.
