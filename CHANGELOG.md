# Changelog

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
