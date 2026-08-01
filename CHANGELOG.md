# Changelog

## Unreleased

Follow-up fixes from the round-8 audit (#8). No format or CLI break: an existing
store keeps working, and the one on-disk change (below) costs at most a single
re-hash the first time a sensitive file is seen again.

### An audit gap no longer renders as a clean bill of health

`alog audit --fail-on-hit` and `alog diff` printed their normal "(none)" result
over a session whose snapshot had been **skipped** for exceeding a ceiling. Wired
into CI that is a green light over an audit that could not see. Both commands now
print any `tree_snapshot_skipped` / `events_dropped` before their results, and
`--fail-on-hit` exits **3** when the audit is incomplete -- kept distinct from the
existing 2, because "a secret was touched" and "we cannot say whether one was"
need different responses.

### The tree walk actually enforces its ceilings

`os.walk` materialises a directory's entire `scandir` result before yielding, so a
single directory holding millions of entries blew past both ceilings -- and could
exhaust memory -- before any check ran. Replaced with an explicit `os.scandir`
traversal that tests the ceilings while consuming each entry. Traversal and stat
errors are no longer swallowed: an unreadable subtree is recorded as a
`walk_error` gap instead of reading as "nothing changed".

### Store integrity

- A `.alog` that is a **symlink** is refused rather than followed, for the store
  root and every fixed subdirectory. Previously `makedirs(exist_ok=True)` accepted
  it, `chmod` followed it, and the salt-healing path could overwrite a file named
  `salt` in someone else's directory.
- The transcript cursor is keyed by `st_dev`/`st_ino` **and a digest of the
  file's first bytes**, not just the path, so a transcript replaced at the same
  name no longer resumes at a stale offset. dev/ino alone was not enough: a
  filesystem may hand the replacement the inode the old file released (Linux
  ext4/overlayfs does so routinely), and CI caught exactly that. The hashed
  window is recorded with the cursor rather than recomputed, so an ordinary
  append to a short transcript does not invalidate its own cursor.
- The elapsed-time ceiling is re-checked after the final hash, so a one-file tree
  can no longer overrun the budget and still return as a complete snapshot.

### Redaction and classification

- Quoted secret keys are masked: `{"password": "..."}` and `{"client_secret":"..."}`
  in a prompt or command were written to the log verbatim.
- `secret/`, `.secret/` and `.secrets/` are classified as sensitive directory
  segments (the standalone filenames already were).
- **Sensitive files no longer record a byte length anywhere.** `alog diff` already
  suppressed it, but the raw size survived in the two artifacts the reader never
  renders -- an orphaned pending Pre, and the Bash manifest's cached record *and*
  its stat reuse key -- leaking a side channel on key type and token shape. Stored
  as a salted digest instead; every consumer compares sizes for equality only, so
  change detection is unaffected.

### Cost estimate

`MODEL_PRICING` was keyed by model **family**, which priced every modern Opus at
the deprecated $15/$75 -- a 3x over-estimate on Opus 4.5 through Opus 5, all of
which are $5/$25. The table is now keyed by version, transcribed from the official
pricing page, and a model that is not listed there reports `price n/a` rather than
borrowing a neighbour's rate.

### Reader robustness (#3 Tier 2)

- A tampered event with an **unhashable** `status` (`{}` / `[]`) raised TypeError
  inside a dict lookup and aborted the whole command -- including
  `audit --fail-on-hit`, whose exit code is what CI keys on. Status is coerced to
  a string, so one junk line renders as unknown and the audit still runs.
- `alog diff` no longer claims "file content is never stored" when reading a
  **legacy v0.1 store**: v0.2 stopped writing `objects/` but never deletes an
  existing one, so an upgraded store still holds the bytes. It now warns instead.
- A **symlink retarget** (`ln -sf /etc/shadow link`) rendered as
  `modified: link (0 -> 0 bytes, +0)`, because a non-regular record carries a
  hardcoded size 0. Change records now carry `kind`/`link_changed` and the reader
  names the repoint.
- The large-file notice stringified `before_size`/`after_size` directly, bypassing
  the tampered-log guard the rest of the renderer applies.

### Tests and demo (#3 Tier 3)

- New coverage for gaps that were promised but untested: rendering a v0.1
  plain-hex event, Slack `xoxb`/`xoxp`/`xapp`/`xoxe` redaction, and the size
  fields on ordinary added/modified/deleted changes.
- Three demo assertions were vacuous and are now anchored to what they claim:
  `S4` matched a bare `"bytes"` (present in any multi-file diff), the binary-file
  check only asserted the created line and never looked for the bytes, and
  `G4`'s `-line1` refutation could never fire since v0.2 emits no content hunks.

### Wiring

`settings-snippet.json` uses the exec form (`"command": "python3"` plus an `args`
array). The shell form word-split on a clone path containing spaces, which
silently disabled **every** audit hook.

## v0.2.1 (2026-08-01)

Bug-fix release. No format or CLI changes — v0.2.0 stores keep working.

### The whole-tree Bash snapshot is now bounded (#5, #7)

Wired globally at a very large directory, the `Bash` whole-tree snapshot re-walked
and re-hashed everything on **every** command, and the per-session manifest meant
each new session paid a cold full scan. In practice this froze `Bash` outright.

- Two ceilings, both configurable and both defaulting to something safe:
  `ALOG_MAX_TREE_FILES` (20000) and `ALOG_MAX_TREE_SECONDS` (3). Set either to `0`
  to disable it.
- Exceeding a ceiling **skips that snapshot and says so**: a distinct
  `tree_snapshot_skipped` event is written with the reason, files seen, elapsed
  time and the limits in force. An audit must never render a gap as a silent
  all-clear.
- Per-file cost cut: `path_is_sensitive` no longer calls `os.path.realpath()` for
  every file on every snapshot (it memoises per parent directory, revalidating
  each hit against the parent's dev/ino fingerprint so the stale window stays
  per-file). The walk re-checks its deadline every 64 entries; the hashing loop
  checks on every file, because one file can cost a full `MAX_HASH_BYTES` read.

Measured on the workspace that triggered the original freeze: 0.64s cold / 0.19s
warm, ceiling hit and recorded, instead of hanging.

### Redaction

- Quoted DB/redis passwords are masked in recorded commands
  (`mysql -p"..."`, `redis-cli -a '...'`).
- Masking keeps the command name instead of swallowing it, so the log still shows
  *what ran*.

### Other

- The transcript cursor resets when the file identity changes, so a rotated or
  replaced transcript no longer resumes from a stale offset.
- README documents `PostToolUseFailure` in the hook wiring table.
- `.wrangler/` is git-ignored: a stray `wrangler` invocation writes a cache
  containing a Cloudflare account id and account name into whatever directory it
  runs from, and this is a public repo.

## v0.2.0 (2026-07-21)

### Breaking: file-content storage (the CAS) removed — digests + metadata only

The `.alog/objects/` content-addressed store is gone (#2). The hook now records
a **salted, truncated digest** plus metadata (size / mode / timestamps) for
every file; file bytes are never written anywhere. The audit's job narrows from
"reconstruct what changed" to "detect and attribute what changed / what was
read" — the part users actually need, and the part git cannot provide.

- **`alog diff` no longer shows content hunks.** It reports change detection:
  path, created/modified/deleted, size delta, and mode change. For git-tracked
  files, `git diff` / `git log -p` has the content story.
- **ALL digests are keyed now** (HMAC-SHA256 with a per-store random key), not
  just sensitive ones. Events only compare digests for before/after equality, so
  a keyed hash carries everything the audit needs while a digest seen without the
  store can't be matched to guessed content. HMAC (not `sha256(key+content)`)
  avoids a concatenation-boundary ambiguity, and the key is enforced to exactly
  16 bytes — together these close a salt-extension trick that could have hidden a
  real edit as an unchanged "read". Same key across one store's sessions, so
  equality still works.
- **Sensitive files record no size.** A redacted change omits `before_size`/
  `after_size` so a secret's byte length isn't left in the log as a side channel.
- **Manifest reuse is format- and context-checked**: a cached digest is reused
  only if it is a v0.2 `D:`/`S:` (or content-less) record whose sensitivity
  matches the current path — a carried-over v0.1 plain-hex entry is re-hashed
  rather than copied into new events.
- **The at-rest secret machinery is deleted** — the content sniff
  (`SECRET_CONTENT_*`), sniff exemptions, public-material verification,
  hardlink withholding — because it existed only to guard stored content. The
  security story simplifies to one sentence: **file contents are never stored,
  period.**
- **Kept:** name-based sensitive classification (the "agent read `.env`"
  headline), command/prompt redaction (those strings are still stored in the
  NDJSON log), symlink/non-regular handling, Pre/Post correlation and
  concurrency attribution, the per-session manifest reuse, and the too-large
  stat-only records.
- **Store migration:** existing `.alog` stores keep working for reading
  events; a legacy `objects/` directory is dead weight and can be deleted.
- Fixes the 1.8 GB store-growth failure mode structurally (see #1 for the
  oversized-tree guards, which remain necessary and orthogonal).

## v0.1.0

Initial release: content-addressed audit store, `alog show/diff/audit/cost/
sessions`, prompt + token capture, secret-at-rest guards.
