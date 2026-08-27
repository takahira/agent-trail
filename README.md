# agent-trail

**A local, offline audit log for AI coding agents — `git diff` for everything git can't see.**

Records what your Claude Code agent actually did — opaque `Bash` effects, the
secrets it *read*, what it was *asked*, and per-turn token cost — using nothing
but hooks and an NDJSON log of **salted content digests + metadata** (file
contents are never stored). No cloud, no daemon, no dependencies.

[![CI](https://github.com/takahira/agent-trail/actions/workflows/ci.yml/badge.svg)](https://github.com/takahira/agent-trail/actions/workflows/ci.yml)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg)](https://github.com/takahira/agent-trail)

---

## The four questions `git diff` can't answer

You let an agent loose on your repo. Afterwards, `git diff` tells you which
*tracked* files changed. It cannot tell you:

1. **What an opaque `Bash` command actually changed.** When the agent runs
   `sh ./gen.sh` — a command string that names no file — `git diff` shows the
   result but not the cause. agent-trail snapshots the work-tree's content
   digests *before* and *after* each tool via `PreToolUse`/`PostToolUse`, so it
   detects and attributes the added / modified / deleted files even though the
   command never named them.

2. **Which secrets the agent merely read.** If the agent `Read`s your `.env`,
   git leaves **no trace at all** — reading a file changes nothing. The hook
   records the *access*, so `alog audit` shows you the secret was read, after
   the fact, offline.

3. **What the agent was asked to do.** `UserPromptSubmit` records your prompts
   (inline secrets masked before storage). git never sees a prompt.

4. **What each turn cost.** The `Stop` hook reads the session transcript and
   records per-message input / output / cache tokens and the model, so `alog
   cost` gives you token usage and an estimated dollar cost per turn.

The headline case, in one screen — the agent read a secret and git is blind to it:

```text
=== alog audit ===
=== sensitive access audit ===
  [#05] read READ .env
  [#06] bash CMD-REF ~/.ssh/id_rsa  (cat ~/.ssh/id_rsa | head -1)
  [#07] bash CMD-REF config/service.env  (grep API config/service.env)
  [#12] read READ-ATTEMPT (absent) .env.production

4 sensitive access(es). NOTE: a plain `git diff` shows NONE of
the read-only accesses above -- reading a secret leaves no git trace.

=== what plain git shows about the .env READ ===
  git diff -- .env : <empty>  (git cannot see that the agent read it)
```

---

## Install

Zero third-party dependencies — the Python 3.9+ standard library is all you need.

```sh
git clone https://github.com/takahira/agent-trail.git
cd agent-trail
# nothing to build; run it in place
python3 alog.py --help
```

`pipx` can also put just the `alog` **reader** CLI on your PATH:

```sh
pipx install git+https://github.com/takahira/agent-trail.git   # gives you `alog`
```

> `pipx` installs the `alog` **reader** only — the wheel deliberately does **not**
> ship `hook.py` (a top-level module named `hook` would collide in a shared env, and
> the hook is wired by absolute path, never imported). So **`git clone` the repo to
> get `hook.py`** and point your settings at `<clone>/hook.py` even if you also
> `pipx install` the reader.
> PyPI publishing is planned under the distribution name **`alog-trail`**
> (`pipx install alog-trail`). Note that the PyPI project named `agent-trail`
> is an unrelated package by a different author and is **not** this project --
> do not install it.

## Wire the hook

The one `hook.py` handles every event (it dispatches on `hook_event_name`). Merge
[`settings-snippet.json`](settings-snippet.json) into `~/.claude/settings.json`
(global) or `.claude/settings.json` (per project), replacing
`/ABSOLUTE/PATH/TO/hook.py` with the absolute path to `hook.py` in your clone.
The snippet uses the **exec form** (`"command": "python3"` plus an `args`
array) on purpose: the shell form word-splits a clone path containing spaces,
which would silently stop every audit hook from running.

| Event | What it records |
| --- | --- |
| `PreToolUse` / `PostToolUse` | before/after snapshot around `Write`/`Edit`/`Read`/`NotebookEdit`/`MultiEdit` (single-file) and `Bash` (whole work-tree) |
| `PostToolUseFailure` | same after-snapshot as `PostToolUse`, recorded as failed, when a tool errors — **strongly recommended**: without it, partial writes left behind by a failed command are never captured (omit only if your Claude Code version predates this event) |
| `UserPromptSubmit` | your prompt, with inline secrets redacted |
| `Stop` / `SubagentStop` | per-turn token usage read from the transcript |

Environment:

- `ALOG_DATA` — store location (default: `<cwd>/.alog`)
- `ALOG_DEBUG=1` — print the hook's internal log to stderr
- `ALOG_MAX_TREE_FILES` — file-count ceiling for one whole-tree `Bash` snapshot
  (default `20000`; `0` disables)
- `ALOG_MAX_TREE_SECONDS` — elapsed-time budget for one whole-tree `Bash`
  snapshot (default `3`; `0` disables)

> **Wiring globally? Mind large trees.** The whole-tree `Bash` snapshot re-walks
> the tree on every `Bash` call, and each *new* session's first call is a cold
> full read + hash. In a very large directory the snapshot hits the ceilings
> above and is **skipped** — recorded as a `tree_snapshot_skipped` event, so the
> gap is visible but that command's tree changes are not captured. Prefer
> per-project wiring for big workspaces (see Limitations).

## Usage

```sh
python3 alog.py sessions                 # list recorded sessions
python3 alog.py show                     # git-status-like timeline of the session
python3 alog.py diff                     # change detection (status/size/mode) per change
python3 alog.py diff src/app.py          # one file
python3 alog.py audit                    # ONLY the sensitive-file accesses
python3 alog.py audit --fail-on-hit      # exit 2 = secret accessed, 3 = audit incomplete
python3 alog.py cost                     # per-turn token usage + estimated cost
```

Common flags (before or after the subcommand):

- `--session <id>` — restrict to one session (default: all)
- `--data <dir>` — store location (default: `$ALOG_DATA` or `./.alog`)
- `--time` — show timestamps (HH:MM:SS, UTC)
- `--fail-on-hit` (`audit` only) — exit `2` when a sensitive access is found, and
  `3` when the log records a GAP (a skipped snapshot or dropped events). The two
  are separate because they need different responses: `2` means a secret was
  touched, `3` means the audit cannot tell you whether one was. `diff` and
  `audit` both print any recorded gap before their results, so a "nothing here"
  line is never mistaken for a clean bill of health.

## What you see

```text
=== alog show ===
[#01] write   src/app.py
          A src/app.py
[#03] bash    $ sh ./gen.sh
          A generated/report.txt
          D src/old.tmp
[#04] bash    $ sh ./mutate.sh
          M src/app.py
[#05] read    .env
          R .env  ⚠ sensitive
[#06] bash    $ cat ~/.ssh/id_rsa | head -1
          ⚠ command references sensitive path: ~/.ssh/id_rsa

summary: 13 events, 7 file change(s), 3 sensitive access(es)
```

`alog diff` detects what changed — status, size delta, mode change — even for a
change made by an opaque script. Content hunks are deliberately not available
(file contents are never stored); for tracked files, `git diff` has the content
story:

```text
diff --alog [#04 Bash] src/app.py
modified: src/app.py  (23 -> 33 bytes, +10)

note: file content is never stored (salted digests + metadata only);
      for tracked files, `git diff` / `git log -p` has the content story.
```

Prompts and token/cost events are woven into the same `seq`-ordered timeline, and
`alog cost` aggregates per model:

```text
=== alog cost ===
  model             turns     input    output  cache_read     cache_wr  est. cost
  opus-4-8              1         4       500      20,000       40,000  ~$0.8176
  haiku-4-5             1       800       120       2,000            0  ~$0.0016

  TOTAL: 2 turn(s), 63,424 tokens, est. cost ~$0.8192
  NOTE: cost is a rough estimate from MODEL_PRICING in alog.py (update rates there);
        tokens are the recorded ground truth.
```

---

## How it works

- **`PreToolUse` pushes a before-snapshot; `PostToolUse` pops it and writes one
  NDJSON event.** Pre and Post are correlated by Claude Code's **`tool_use_id`**
  (`toolu_…`), which rides on both — so **parallel / interleaved** tool calls
  never cross-attribute their diffs. (A naive tool-name + file-path match works
  for sequential calls and silently breaks under concurrency; the `tool_use_id`
  key is what makes it correct.)
- **Single-file tools** snapshot just the one path; **`Bash`** snapshots the
  whole work-tree by content digest (reusing an mtime manifest so it stays cheap),
  which is how it detects changes a command string never named.
- **Digests + metadata only.** Every file is recorded as a **salted, truncated
  digest** plus size / mode / timestamps — file bytes are never written anywhere.
  Digests are only ever compared for before/after equality, which is all change
  detection needs. Nothing leaves your machine.

## Security posture — the audit tool must not become the leak

The store's security story is one sentence:

- **File contents are never stored, period.** Every file — secret or not — is
  recorded as a *keyed* (HMAC-SHA256), truncated digest plus metadata. The
  per-store random key means a digest seen **without** the store — a log line
  pasted elsewhere, a cross-store rainbow table — cannot be matched back to
  guessed content. It is **not** a defence once someone has the whole `.alog/`:
  the key lives in it beside the digests, so treat the store as sensitive.
  Sensitive files additionally record **no size**, so a secret's byte length
  isn't disclosed either. (Before v0.2 an object store held non-sensitive file
  bytes for content diffs; that entire storage tier — and the class of at-rest
  risk that came with it — was removed. A legacy `.alog/objects/` directory is
  dead weight and can be deleted.)

What still lands in the log, and its guardrails:

- **`Bash` command strings and your prompts ARE stored** — that is the audit's
  job. Inline secrets in commands (`API_KEY=…`, Bearer tokens, `sk-…`,
  `user:pass@host`, `--password …`, `sshpass -p …`) and prompts (PEM blocks,
  vendor tokens, JWTs, URL credentials) are masked before storage — best-effort
  (short/novel credential flags and free-form prose can slip).
- **A secret embedded in a filename / path** is recorded as part of the path
  (paths are needed for change correlation); symlink *targets* are additionally
  passed through the command redactor.
- **The store is created `0700`/`0600` and drops its own `.gitignore(*)`**, so it
  can't be accidentally committed or read by other local users. Treat `.alog/`
  as sensitive anyway — it holds your command history and prompts.

## Limitations

Honest scope — this records a lot, but not everything:

- **No content view.** `alog diff` shows change detection (status, size delta,
  mode change), not content hunks — file bytes are never stored. For a
  git-tracked file, `git diff` has the content; for untracked/ignored files the
  *fact and attribution* of the change is recorded, but the bytes are gone.
- **Read-only tools other than `Read` are not audited.** `Grep` / `Glob` /
  `WebFetch` are out of scope; only `Write` / `Edit` / `Read` / `NotebookEdit` /
  `MultiEdit` and `Bash` are recorded.
- **Sensitive classification is name/path-based and best-effort.** The "agent
  read `.env`" headline relies on a precise-but-not-exhaustive name heuristic;
  a secret in an unusually-named file is still recorded as an access, just not
  flagged sensitive. (Nothing is at risk at rest either way — contents are never
  stored.)
- **Symlinked-ancestor classification is best-effort under concurrent renames.**
  A file whose parent directory is a symlink into a sensitive location is
  caught by resolving the path (`realpath`). Whole-tree snapshots memoize that
  resolution per parent directory and revalidate every reuse against the
  parent's device/inode fingerprint, so a directory swapped mid-snapshot is
  re-resolved at the next file under it — the stale window is per-file, not
  per-snapshot. A swap that lands between that check and the file's open
  remains theoretically raceable (classic TOCTOU), the same window as
  resolving without the cache.
- **Prompt redaction is best-effort.** It masks known secret *shapes*; a secret
  with no recognizable shape in free text can slip through — an effort, not a
  guarantee.
- **Cost is an estimate.** Raw tokens are the ground truth; dollars are derived
  at display time from the `MODEL_PRICING` table in `alog.py` (update it
  yourself). Models not in the table show tokens with `price n/a` — never a
  fabricated figure.
- **Reads through an opaque script can't be detected.** `sh ./leak.sh` that
  reads a secret without naming it leaves zero content diff, so the *read* is
  invisible (a structural limit without syscall tracing; writes are still caught
  by the tree diff).
- **`Bash` attribution with concurrent tools is best-effort.** Because `Bash`
  snapshots the whole tree, a change another tool made inside the Pre→Post
  window can't be separated by content alone. Concurrency is *detected* for
  overlapping tool calls in the same session and marked rather than falsely
  attributed: a concurrent single-file `Write`/`Edit` (which has a definite target)
  claims its path (`claimed_by_concurrent`); a concurrent `Bash` — whose whole-tree
  diff can't *prove* it authored any path — only downgrades the overlap to
  `ambiguous`, never disowning the real author.
- **Concurrency detection is per-session and per-cwd.** Overlap is only tracked
  within one `session_id`, and attribution compares paths relative to each tool's
  reported `cwd`; two tools in one session running under *different* working
  directories can mis-attribute a change (best-effort). Claude Code sends a stable
  session cwd, so this is a limitation for other Pre/PostToolUse agents. Two Claude Code sessions (e.g. two terminal tabs) working the
  same tree get independent sessions with no cross-session lock, so a change made
  by session B can be attributed `exclusive` in session A's log. Run one session
  per work tree if you need exact attribution.
- **`Bash` changes under build/VCS dirs aren't detected.** The whole-tree
  snapshot skips `.git`, `node_modules`, `dist`, `build`, `target`, `.venv`, … for
  speed, so a `Bash` write to e.g. `.git/hooks/pre-commit` or `dist/bundle.js`
  produces no file-change record (the *command string* is still captured and
  secret-scanned). A `Write`/`Edit` to the same path **is** recorded, since
  single-file tools snapshot the named path directly.
- **Very large work trees degrade to a recorded gap.** `Bash` snapshots the
  whole tree, and the reuse manifest is **per-session**, so every *new* session's
  first `Bash` command pays a cold full-tree read + hash. The snapshot is
  ceiling-bounded: more than `ALOG_MAX_TREE_FILES` files (default 20,000) or
  `ALOG_MAX_TREE_SECONDS` elapsed (default 3) skips the tree snapshot for that
  event and writes a `tree_snapshot_skipped` event instead — the command string
  is still captured and secret-scanned, but tree changes made by that command are
  **not** captured (the gap is recorded, never a silent all-clear; a warning is
  also printed to stderr under `ALOG_DEBUG=1`). Set either variable to `0` to
  disable that ceiling. **Wiring the hook globally (`~/.claude/settings.json`)
  means it runs wherever you start Claude Code — in a very large directory
  (a home directory, a monorepo root) expect skipped tree snapshots or, with the
  ceilings disabled, slow `Bash` calls.** Prefer per-project wiring, or point
  `ALOG_DATA` at a scoped store and start sessions in the project root.
- **A session-lock timeout drops the event, and the drop is recorded.** If the
  per-session lock cannot be acquired within 10s (a wedged holder), the hook
  fails open and that one event is lost; the next successful write appends an
  `events_dropped` marker with the count, so the gap is visible in the log
  (best-effort: the counter itself is written without a lock).
- **Retention / GC is not implemented.** Command strings, prompts, and turn
  events accumulate without bound (the pending stack alone is TTL- and
  length-capped). With no content storage the growth is text-sized, not
  workspace-sized.
- **Claude Code only, for now.** The hook understands Claude Code's
  Pre/PostToolUse / UserPromptSubmit / Stop payloads and transcript format;
  other agents' formats are not yet supported.
- **`fcntl.flock` concurrency protection is macOS / Linux only.** Windows is out
  of scope.

## Development

Two test layers, both standard-library only:

```sh
# Unit tests (function-level, frozen clock, throwaway temp stores)
python3 -m unittest discover -s tests -p "test_*.py" -t .

# Integration demo + assertions (synthesizes hook payloads into a throwaway
# /tmp git repo and asserts the recorded audit log end-to-end)
bash demo.sh
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the invariants a change must preserve.

## License

[MIT](LICENSE) © Takayoshi Hirano
