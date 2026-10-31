# Adding a trap

A trap belongs in win-traps when a command an AI agent is likely to run on Windows **succeeds, or seems to, while
doing damage nobody sees**. Loud failures (a clear error message and a non-zero exit) usually do not qualify.
Destructive commands that are dangerous on every OS belong in a general command guard.

## 1. Verify it

* Find an official or reliable source (vendor docs, the project's own docs or source code) and read the exact
  wording. Cite the URL in `sources`.
* Reproduce it on Windows and write down the exact symptom: what ran, what you expected, what happened.
* If you can reproduce it but find no source, set `status="observed"` and say "Observed with <tool and version>"
  in `why`. Never state more than you saw.
* Check the near-misses too. If the obvious variants do not bite, say so in the README instead of flagging them.

## 2. Write the matcher

In `wintraps/catalog.py`, add a function `match_<name>(command: str, ctx: Context) -> Optional[str]`. Return
`None` for no match, or a one-line detail naming what was found.

* Prefer `parse_command(command, ctx)`, which gives you segments with `argv`, leading `VAR=value` assignments
  and the effective `cwd` after any `cd`.
* Anything that touches the machine goes through `Context` (`git_status`, `which`, `exists`, `find_junctions`,
  `environ`), so tests can replace it. Keep checks fast (the hook runs before every command) and bounded.
* When a check cannot get an answer, decide explicitly. Stay silent when the command would then fail loudly
  anyway; block with a "could not verify" detail when silence could hide the damage.

## 3. Add the catalog entry

Append a `Trap(...)` to `TRAPS` with:

| Field | Meaning |
|---|---|
| `id` | short kebab-case id, also used in `wintraps:allow=<id>` |
| `title` | one line |
| `severity` | `block` (deny, Claude rewrites) or `warn` (context only, or a prompt with `WINTRAPS_WARN=ask`) |
| `applies_to` | `("bash",)`, `("powershell",)`, `("python-code",)` or `("any",)` |
| `status` | `verified` or `observed` |
| `why` | plain English, 1-2 sentences, precise about what happens |
| `safe` | the command or code to use instead |
| `sources` | one or more `https://` URLs |
| `matcher` | your function |

## 4. Test it

In `tests/test_traps.py`, add an entry to `CASES` with at least **two commands that must match** and **two
near-misses that must not** (the safe alternative is usually a good near-miss). Each case becomes its own test
named `test_<id>_match_<n>` / `test_<id>_miss_<n>`.

Then run:

```
python -m unittest discover -s tests -t .
python scripts/sabotage.py
```

The sabotage script disables your matcher in a temporary copy and must report your trap as `CAUGHT`. If it
reports `MISSED`, your tests do not actually depend on the matcher.

Use generic example paths such as `C:\project` in tests and docs.
