# Changelog

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
