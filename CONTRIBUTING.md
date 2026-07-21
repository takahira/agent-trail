# Contributing

## Run the tests

Two layers, both standard-library only — nothing to `pip install`.

```bash
# Unit tests (function-level, frozen clock, throwaway temp stores)
python3 -m unittest discover -s tests -p "test_*.py" -t .

# Integration demo + assertions (synthesizes hook payloads into a throwaway
# /tmp git repo and asserts on the recorded audit log end-to-end)
bash demo.sh
```

Both must pass before opening a PR. The demo never touches a real repo — all
activity happens in a `mktemp` directory that is removed on exit.

## Adding detection logic

- Add a regression test for any new case (a new sensitive-path shape, a new
  redaction pattern, a new attribution edge). The existing tests each target one
  behaviour or one previously-fixed bug — follow that convention.
- Confirm no existing test changes outcome. Detection is token/structure-based;
  changes to the sensitive-name list or a redaction regex must come with a test
  that exercises the new path.
- Watch the redaction regexes for catastrophic backtracking (ReDoS) — bound
  quantifiers explicitly and add a large-input test if you touch them.

## Zero third-party dependencies

`alog.py` and `hook.py` use the Python standard library only, and target
Python 3.9+. Do not add an `import` that requires a `pip install`.

## Single-file hook by design

`hook.py` is intentionally one self-contained file, not a package: Claude Code
wires it by an absolute path to that single script, so keeping it unsplit makes
the install "point your settings at one file" and the audit guarantees readable in
one place. It exceeds the usual file-size guidance on purpose — please don't split
it into a package (which would break path-based wiring) without also solving
single-file distribution. Prefer adding a focused function over a new module.

## The store must never become a leak source

The core invariant: **file contents are never stored, period** (v0.2+). Every
file is recorded as a salted, truncated digest plus metadata; the store is
created `0700/0600` and drops its own `.gitignore`. Command strings and prompts
ARE stored (redacted best-effort). Any change near snapshotting must keep
`demo.sh`'s no-bytes-at-rest assertions passing — never reintroduce a code path
that writes file bytes into the store.
