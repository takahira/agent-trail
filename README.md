# agent-trail

**A local, offline audit log for AI coding agents — `git diff` for everything git can't see.**

Records what your Claude Code agent actually did — opaque `Bash` effects, the
secrets it *read*, what it was *asked*, and per-turn token cost — using nothing
but hooks, NDJSON, and a content-addressed store. No cloud, no daemon, no
dependencies.

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
   hashes *before* and *after* each tool via `PreToolUse`/`PostToolUse`, so it
   reconstructs the added / modified / deleted files even though the command
   never named them.

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
> PyPI publishing (`pipx install agent-trail`) is planned.

## Wire the hook

The one `hook.py` handles every event (it dispatches on `hook_event_name`). Merge
[`settings-snippet.json`](settings-snippet.json) into `~/.claude/settings.json`
(global) or `.claude/settings.json` (per project), replacing
`/ABSOLUTE/PATH/TO/hook.py` with the absolute path to `hook.py` in your clone:

| Event | What it records |
| --- | --- |
| `PreToolUse` / `PostToolUse` | before/after snapshot around `Write`/`Edit`/`Read`/`NotebookEdit`/`MultiEdit` (single-file) and `Bash` (whole work-tree) |
| `UserPromptSubmit` | your prompt, with inline secrets redacted |
| `Stop` / `SubagentStop` | per-turn token usage read from the transcript |

Environment:

- `ALOG_DATA` — store location (default: `<cwd>/.alog`)
- `ALOG_DEBUG=1` — print the hook's internal log to stderr

## Usage

```sh
python3 alog.py sessions                 # list recorded sessions
python3 alog.py show                     # git-status-like timeline of the session
python3 alog.py diff                     # git-diff-like before/after for every change
python3 alog.py diff src/app.py          # one file
python3 alog.py audit                    # ONLY the sensitive-file accesses
python3 alog.py audit --fail-on-hit      # exit 2 if any secret was accessed (CI / pre-commit)
python3 alog.py cost                     # per-turn token usage + estimated cost
```

Common flags (before or after the subcommand):

- `--session <id>` — restrict to one session (default: all)
- `--data <dir>` — store location (default: `$ALOG_DATA` or `./.alog`)
- `--time` — show timestamps (HH:MM:SS, UTC)
- `--fail-on-hit` (`audit` only) — exit `2` when a sensitive access is found

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

`alog diff` reconstructs the actual before/after even for a change made by an
opaque script:

```text
diff --alog [#04 Bash] src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -1,2 +1,3 @@
-value = 'foo'
+value = 'bar'
 print(value)
+# touched
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
  whole work-tree by content hash (reusing an mtime manifest so it stays cheap),
  which is how it reconstructs changes a command string never named.
- **The store is content-addressed.** File contents are keyed by hash so `diff`
  can rebuild any before/after state offline. Nothing leaves your machine.

## Security posture — the audit tool must not become the leak

The whole point collapses if the store itself becomes a plaintext secret dump. Two
things are worth being precise about — **a hard guarantee** and **a best-effort
one** — because secret *detection* is heuristic and no regex can prove arbitrary
file content secret-free:

- **Hard guarantee — a *detected* secret is never stored as cleartext.** Anything
  classified sensitive — by name (`.env`, `*.pem`, `.ssh/…`, `*.tfvars`,
  `serviceAccountKey.json`, …) **or** by a content sniff of the **whole stored
  content** (private-key headers; cloud-credential shapes; vendor tokens incl.
  GitHub `gh*_`, Google `AIza`, Slack `xox*`/`xapp-`; quoted **and** unquoted config
  secrets; `scheme://user:pass@host` connection strings — every byte that would be
  persisted, not just a head window) — is recorded as a **salted digest** only, its
  bytes never written to the object store. Only *structurally public* content (a
  `*.pub` / public-cert name **whose bytes actually start as** `ssh-…` /
  `-----BEGIN CERTIFICATE-----`) skips the broad sniff; env/vars **templates**
  (`.env.example`, …) keep it, so a real secret left in a template is withheld while
  a clean placeholder template still stores its bytes so the diff stays viewable.
- **Best-effort — an *undetected* secret can be stored.** The classifiers are
  precise, not exhaustive: a secret in an unusual shape, a novel vendor prefix, or
  a value the sniff doesn't recognise **can** be written into `.alog/objects` as
  part of an otherwise-innocuous file's content. So treat the store as sensitive:
- **The store is created `0700`/`0600` and drops its own `.gitignore(*)`**, so it
  can't be accidentally committed or read by other local users. That defense-in-depth
  is what backstops the best-effort detection above — **do not** copy `.alog/`
  elsewhere, relax its permissions, or treat it as safe to share.
- **Inline secrets in `Bash` command strings** (`API_KEY=…`, Bearer tokens, `sk-…`,
  `user:pass@host`, `--password …`, `sshpass -p …`) are masked before storage —
  again best-effort (short/novel credential flags and free-form prose can slip).
- **Prompt redaction** masks known shapes (PEM private-key blocks, `API_KEY=`,
  Bearer, `sk-`, Stripe `sk_live_`, JWTs, URL credentials) before writing — an
  effort, not a guarantee (see Limitations).

## Limitations

Honest scope — this records a lot, but not everything:

- **Read-only tools other than `Read` are not audited.** `Grep` / `Glob` /
  `WebFetch` are out of scope; only `Write` / `Edit` / `Read` / `NotebookEdit` /
  `MultiEdit` and `Bash` are recorded.
- **Secret *detection* is best-effort (see Security posture).** A DETECTED secret
  is digest-only (hard guarantee), but the classifiers are precise, not exhaustive:
  an unrecognised shape/prefix, an unusual config value, or a secret embedded in a
  **filename / path / symlink target** (paths are recorded verbatim for change
  correlation) can end up stored in the log or CAS. The `0700`/`.gitignore` store is
  the backstop — treat `.alog/` as sensitive.
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
- **`Bash` changes under build/VCS dirs aren't reconstructed.** The whole-tree
  snapshot skips `.git`, `node_modules`, `dist`, `build`, `target`, `.venv`, … for
  speed, so a `Bash` write to e.g. `.git/hooks/pre-commit` or `dist/bundle.js`
  produces no file-change record (the *command string* is still captured and
  secret-scanned). A `Write`/`Edit` to the same path **is** recorded, since
  single-file tools snapshot the named path directly.
- **Retention / GC is not implemented.** Non-sensitive blobs, command strings,
  prompts, and turn events accumulate without bound (the pending stack alone is
  TTL- and length-capped).
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
# /tmp git repo and asserts the reconstructed audit log end-to-end)
bash demo.sh
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the invariants a change must preserve.

## License

[MIT](LICENSE) © Takayoshi Hirano
