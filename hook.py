#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Agent audit-log capture hook.

A single hook that Claude Code (and other agents with a Pre/PostToolUse hook
contract) calls *around* every tool invocation. It reads the hook payload on
stdin and records what the agent touched -- salted content digests + metadata,
never file bytes -- into a local audit log with zero cloud dependency.

Why a hook instead of `git diff` after the fact?
------------------------------------------------
`git diff` answers "which *tracked* files changed", but an audit of an AI agent
needs three things git cannot give you from the working tree:

1. **What a Bash command actually changed.** The command *string* (`sed -i ...`,
   `rm ...`, a script that writes files) does not tell you which files moved.
   We snapshot the work tree's content hashes immediately *before* and *after*
   the command, so the change is detected from observed state.
2. **Files the agent only READ.** Reading `.env` leaves no trace in git. We log
   the access, so a read of a secret is visible even though nothing changed.
3. **A faithful before/after even for untracked / .gitignore'd files.**

Secret-safety of the store itself (this is an audit tool, not a leak)
---------------------------------------------------------------------
**File contents are never stored, period.** Every file is recorded as a keyed
(HMAC-SHA256), truncated digest plus metadata (size / mode / timestamps); the key
is per-store random, so a digest seen WITHOUT the store cannot be matched to
guessed content (no cross-store rainbow table). This is NOT a defence once someone
has the whole store -- the key lives in it beside the digests -- so treat the
store as sensitive. Sensitive files record no size (byte length is withheld too).
What CAN still land in the log, best-effort guarded:
- Bash command strings and user prompts ARE stored (that is the audit's job);
  they pass through ``redact_command`` / ``redact_prompt`` first, which mask
  recognisable inline tokens. A freeform secret with no recognisable shape is
  not caught.
- A secret embedded in a filename / path / symlink target is recorded as part
  of the path (symlink targets are additionally redacted).
- DEFENSE-IN-DEPTH: the whole store is created 0700 with 0600 files, and an
  ``.alog/.gitignore`` (``*``) is dropped in so it can't be committed or read
  by other local users. Treat ``.alog/`` as sensitive.

Event model
-----------
PreToolUse       -> snapshot "before" digests of the files of interest; push onto
                    a per-session pending stack.
PostToolUse      -> snapshot "after" digests, pop the matching "before" (matched
                    by tool AND file_path for single-file tools), and write ONE
                    consolidated NDJSON event. A Post with no matching Pre
                    degrades to "before unknown" rather than fabricating changes.
UserPromptSubmit -> write a ``kind:"prompt"`` event with the (redacted) prompt --
                    what the agent was ASKED, which git never sees.
Stop/SubagentStop-> read the session transcript and write one ``kind:"turn"``
                    event per new assistant message with its token usage + model.
                    Cost is NOT stored (alog derives it from the tokens), and
                    turns are deduped by message.id so a repeated Stop over a
                    growing transcript never double-counts.

All events share one per-session NDJSON file and a monotonic ``seq``; the tool
events carry no ``kind`` (implicitly "tool") so the reader stays backward-compat.

Python 3.9 compatible; standard library only. Never raises into the agent.

Structure note: this is intentionally ONE self-contained file. Claude Code wires
the hook by an absolute path to this single script (see settings-snippet.json), so
it is deliberately NOT split into an importable package -- that keeps the "point
your settings at one file" install trivial and the audit guarantees reviewable in
one place. This is a conscious exception to the usual file-size guidance; if
distribution ever moves to a package, the natural split is by concern (secrets /
store / worktree / session log / events / transcript).
"""
from __future__ import annotations

import contextlib
import errno
import fcntl
import fnmatch
import hashlib
import hmac
import json
import math
import os
import re
import stat
import sys
import time
from typing import Dict, List, Optional, Set, Tuple

# ---- configuration -------------------------------------------------------

SINGLE_FILE_TOOLS = {"Write", "Edit", "Read", "NotebookEdit", "MultiEdit"}
# Read is single-file but READ-ONLY: it can never author a change, so a concurrent
# Read overlapping a Bash command must not be credited with the command's write
# (attribution=claimed_by_concurrent) -- that would disown the Bash command's real
# modification and pin it on a tool that cannot write. Only these tools can author
# a change and thus legitimately "claim" a path from a concurrent Bash.
READ_ONLY_TOOLS = {"Read"}
WRITE_TOOLS = SINGLE_FILE_TOOLS - READ_ONLY_TOOLS

# Directories the WHOLE-TREE Bash snapshot never descends (for speed, and to avoid
# hashing build noise). KNOWN LIMITATION / NON-GOAL: a change a Bash command makes
# to a file UNDER one of these dirs (e.g. `.git/hooks/pre-commit`, `dist/bundle.js`)
# is therefore not reconstructed from the tree diff -- though the Bash COMMAND STRING
# is still captured and secret-scanned. A single-file Write/Edit tool targeting the
# same path IS recorded (it snapshots the named path directly, bypassing this skip).
# This blind spot is documented in the README security posture, not silently assumed.
TREE_SKIP_DIRS = {".git", ".alog", "node_modules", ".venv", "venv",
                  "__pycache__", ".mypy_cache", ".pytest_cache", "dist",
                  "build", ".next", "target"}

# A file larger than this is never read/hashed -- it is recorded stat-only
# (size + mtime + ctime), which still detects changes. Bounds hook I/O & memory.
MAX_HASH_BYTES = 10 * 1024 * 1024

# Whole-tree snapshot ceilings (issue #5). MAX_HASH_BYTES bounds one FILE, but the
# Bash tree walk itself was unbounded: wired at a huge directory root it re-walked
# and re-hashed the whole tree on EVERY Bash command (the 2026-07-21 unwiring
# incident), and the per-session manifest means every NEW session pays the cold
# scan again. When either ceiling is exceeded the tree snapshot for that event is
# SKIPPED and the gap is recorded loudly: a distinct ``tree_snapshot_skipped``
# event line lands in the log (the audit must never show a silent all-clear) and a
# one-line warning goes to stderr under ALOG_DEBUG. Both are configurable via env
# vars; a value <= 0 disables that ceiling.
DEFAULT_MAX_TREE_FILES = 20000       # ALOG_MAX_TREE_FILES
DEFAULT_MAX_TREE_SECONDS = 3.0       # ALOG_MAX_TREE_SECONDS
# During the WALK the deadline is re-checked every N enumerated entries (on top
# of the per-directory check), keeping a huge single directory bounded while the
# per-entry cost stays one cheap comparison. The HASHING loop checks the deadline
# on EVERY file instead: time.monotonic() costs tens of nanoseconds while one
# file can cost a full MAX_HASH_BYTES read on a slow mount, so a per-chunk check
# there let the final chunk overrun the time budget many times over.
_TREE_DEADLINE_CHECK_EVERY = 64


def tree_max_files() -> int:
    """File-count ceiling for one whole-tree snapshot (0 = disabled)."""
    raw = os.environ.get("ALOG_MAX_TREE_FILES")
    if raw is None:
        return DEFAULT_MAX_TREE_FILES
    try:
        val = int(raw)
    except ValueError:
        return DEFAULT_MAX_TREE_FILES
    return max(0, val)


def tree_max_seconds() -> float:
    """Elapsed-time budget for one whole-tree snapshot (0 = disabled)."""
    raw = os.environ.get("ALOG_MAX_TREE_SECONDS")
    if raw is None:
        return DEFAULT_MAX_TREE_SECONDS
    try:
        val = float(raw)
    except ValueError:
        return DEFAULT_MAX_TREE_SECONDS
    if not math.isfinite(val):
        return DEFAULT_MAX_TREE_SECONDS
    return max(0.0, val)


class TreeCeilingExceeded(Exception):
    """The whole-tree snapshot hit a ceiling; the snapshot for this event is
    skipped and the gap is recorded (never silently hidden)."""

    def __init__(self, reason: str, files_seen: int, elapsed: float,
                 detail: str = ""):
        super().__init__("tree snapshot ceiling: {0} ({1} files, {2:.3f}s){3}".format(
            reason, files_seen, elapsed, (" " + detail) if detail else ""))
        # "file_count" | "time_budget" | "walk_error"
        #
        # walk_error is NOT a ceiling in the resource sense: it means part of the
        # tree could not be enumerated (an unreadable directory, a vanished
        # entry we could not stat). It travels the same path on purpose --
        # an incomplete snapshot must be recorded as a gap, never rendered as
        # "nothing changed". Silently skipping the subtree is how a change inside
        # a mode-000 directory became an all-clear.
        self.reason = reason
        self.files_seen = files_seen
        self.elapsed = elapsed
        self.detail = detail

# Sensitive-file matching. Bias: PRECISE (few false positives) over exhaustive.
# Detection here is non-blocking -- a missed file is still logged as an access
# when read via the Read tool; the point is the secret-content-at-rest guard and
# the "read of a secret" headline, not a perfect classifier.
SENSITIVE_EXACT_NAMES = {
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "credentials", ".npmrc", ".netrc", ".pgpass", ".htpasswd",
    "kubeconfig", ".dockercfg", ".pypirc",
    "terraform.tfstate", "terraform.tfstate.backup",
    ".dev.vars", ".git-credentials",  # Wrangler/CF local secrets; git stored creds
    "secret", "secrets", ".secret", ".secrets",  # bare, no extension (glob needs a dot)
    ".vault-token", ".envrc",         # Vault CLI token; direnv (often `export SECRET=`)
}
SENSITIVE_GLOBS = [
    ".env", ".env.*", "*.env",
    "*.pem", "*.key", "*.p12", "*.pfx", "*.ppk", "*.keystore", "*.jks",
    "*.tfstate", "*.kubeconfig",
    "*.tfvars", "*.tfvars.json",      # Terraform var files often hold secrets
    ".dev.vars", ".dev.vars.*",       # Wrangler/Cloudflare local secret bindings
    "*.ovpn", "*.enc",
    "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*",
    "credentials*.json", "*-credentials.json", "*_credentials.json",
    "*service-account*.json", "*serviceaccount*.json", "*service_account*.json",
    "secret.*", "secrets.*", "*.secret",
]
# Exact path SEGMENTS (never substring-of-whole-path -- that false-flags e.g.
# "wisshful.txt" for ".ssh"). A path is sensitive if any of these is a full dir
# component. Two tiers by ambiguity:
#   ABS: unambiguous config dot-dirs, checked against the ABSOLUTE path so an agent
#        running UNDER ~/.ssh (display path just "config") is still classified. These
#        names essentially never occur as an ordinary project ancestor.
#   REL: generic nouns, checked only against the cwd-RELATIVE path -- a repo merely
#        CLONED under ~/projects/secrets/ or ~/code/gcloud/ must NOT have every file
#        wholesale-flagged (which would drown `alog audit` in false positives).
SENSITIVE_DIR_SEGMENTS_ABS = {".ssh", ".aws", ".gnupg", ".kube", ".docker"}
SENSITIVE_DIR_SEGMENTS_REL = {"gcloud", "secrets"}
SENSITIVE_PATH_SEGMENTS = SENSITIVE_DIR_SEGMENTS_ABS | SENSITIVE_DIR_SEGMENTS_REL
# Allowlist, checked FIRST: public / template artifacts are NEVER secret, so
# they don't pollute `alog audit` with false "secret access" lines. Without it,
# ".env.example" / "id_rsa.pub" / public certs were mis-flagged as secret.
SENSITIVE_ALLOW_EXACT = {
    "fullchain.pem", "chain.pem", "cert.pem", "ca.pem", "ca-cert.pem",
    "cacert.pem", "dhparam.pem", "public.pem",
}
SENSITIVE_ALLOW_RE = re.compile(
    r"(?i)(?:\.env|\.dev\.vars)(\.[^.]+)*\.(example|sample|template|tmpl|dist|default|spec)$")
# NOTE on sc-2 (Secret.md / Secrets/ false-positives): a doc-extension carve-out
# was tried and REVERTED. Over-flagging an innocent doc (audit noise) is the
# fail-safe price; a file genuinely named secrets.md that holds real secrets
# must keep its sensitive classification.

# "Bearer <cred>" is handled separately from the token-shape list because it is
# prose-aware: a shell COMMAND with "Bearer x" is almost always an auth header, so
# it is masked greedily (\S+); a PROMPT is prose where "the ring Bearer carried it"
# must survive, so there we require a TOKEN-shaped credential (>=16 token chars).
# "Authorization: Bearer <cred>" is caught by AUTH_HEADER_RE regardless of either.
BEARER_LOOSE_RE = re.compile(r"(?i)\bBearer\s+\S+")
BEARER_STRICT_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/\-]{16,}=*")
# Standalone high-signal token SHAPES; the WHOLE match is replaced by <redacted>.
TOKEN_SHAPE_RES = [
    re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}"),           # OpenAI-style
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}"),  # Stripe secret key
    re.compile(r"\brk_(?:live|test)_[A-Za-z0-9]{16,}"),  # Stripe restricted key
    re.compile(r"\bgh[opsru]_[A-Za-z0-9]{20,}"),     # ghp_/gho_/ghs_/ghr_/ghu_ family
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}"),       # GitLab personal access token
    re.compile(r"\bhvs\.[A-Za-z0-9_\-]{20,}"),        # HashiCorp Vault service token
    re.compile(r"\bAKIA[0-9A-Z]{12,}"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}"),         # Google API key
    re.compile(r"\bxox[baeprs]-[A-Za-z0-9\-]+"),     # Slack (incl. xoxe config token)
    re.compile(r"\bxapp-[0-9]-[A-Za-z0-9\-]{8,}"),   # Slack app-level token
    # JWT: header.payload.signature, both first segments base64url of a JSON '{"…'.
    re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}"),
]
# key=value / key:value INCLUDING compound env names. The surrounding [\w-]
# absorbs the prefix/suffix (so DB_PASSWORD=, AWS_SECRET_ACCESS_KEY=, PGPASSWORD=
# are caught -- the old leading \b left every underscore-compound name unmasked).
# The {0,40} BOUND on those runs is load-bearing: an unbounded [\w-]* around an
# alternation backtracks catastrophically (ReDoS) on a long token with no '='.
# Group 1 = name+delimiter (kept verbatim); group 2 = the value (masked); a
# quoted value is swallowed whole so "k=a b c" doesn't leak the tail.
KV_SECRET_RE = re.compile(
    r"(?i)([\w-]{0,40}(?:api[_-]?key|secret|passw(?:or)?d|passphrase|pwd|"
    r"pgpass(?:word)?|session[_-]?token|token|auth|access[_-]?key|"
    r"client[_-]?secret|private[_-]?key)[\w-]{0,40}\s*[=:]\s*)"
    r"(\"[^\"]*\"|'[^']*'|[^\s;|&]+)")
# user:pass@host embedded in a URL (group 2 = password, masked). The user part is
# OPTIONAL so redis://:pass@host (empty user) is still caught. The scheme run is
# BOUNDED ({0,15}); an unbounded [a-z0-9+.\-]* before '://' backtracks
# quadratically on long '://'-free text (ReDoS), which matters now that redaction
# runs on the UNtruncated string (see redact_command/redact_prompt).
# The password run is [^/\s]+ (allows '@' and ':' INSIDE the credential) and group 3
# anchors the LAST '@host' -- a greedy password that backtracks to that final '@'
# masks a whole password containing '@'/':' (e.g. 'MyP@ss:w0rd'), which the old
# [^/\s:@]+ leaked the tail of. The host class excludes '@'/':'/'/' so the port/path
# stay outside the mask; one greedy group + an anchored tail stays linear (no ReDoS).
URL_CRED_RE = re.compile(
    r"(?i)([a-z][a-z0-9+.\-]{0,15}://[^/\s:@]*:)([^/\s]+)(@[^/\s@:]+)")
# --password VALUE / --token=VALUE long flags (group 1 = flag+delim, kept).
# --password VALUE / --token=VALUE. The delimiter is (?:=\s*|\s+) so MULTIPLE spaces
# between the flag and the value (`--password   hunter2`) are consumed -- the old
# single [=\s] left the value unmasked after extra spacing.
FLAG_SECRET_RE = re.compile(
    r"(?i)(--(?:password|passwd|passphrase|token|secret|api[_-]?key|auth|"
    r"private[_-]?key)(?:=\s*|\s+))"
    r"(\"[^\"]*\"|'[^']*'|[^\s;|&]+)")
# High-confidence SHORT credential flags where the meaning is unambiguous:
#   sshpass -p<pass> / -p <pass>   (always a password)
#   curl -u user:pass              (basic-auth userinfo; require the ':' shape so a
#                                   bare -u/-p in another tool isn't over-masked)
SSHPASS_RE = re.compile(r"(?i)(\bsshpass\s+-p\s*)(\"[^\"]*\"|'[^']*'|[^\s;|&]+)")
# Short DB password flags, SCOPED to tools where `-p`/`-a` is unambiguously a password
# (mysql/mariadb/mongosh -p; redis-cli -a). Deliberately NOT `docker -p` (port) or
# `psql -p` (port). The value is either a QUOTED string ('...' / "...") or a bare run
# that must start alnum so a bare `-p -e ...` (prompt form) does not mask the next
# flag. The quoted alternatives (cf. SSHPASS_RE) matter: `-p'Hunter2'` passed through
# UNmasked before they were added, because the bare form rejects a leading quote.
# The tool-to-flag gap is bounded ({0,300}) to stay linear.
#
# The span from the tool name to the flag is CAPTURED (group 1) and re-emitted by the
# substitution. It used to be left uncaptured, so the sub -- which rebuilds from the
# flag group onward -- silently dropped everything the match had consumed before it:
# `mysql -uroot -pHunter2 db` became ` -p<redacted> db`, losing the tool name and the
# connection target. That is a correctness bug for an AUDIT log, and it hit exactly the
# commands that carry credentials. Keep the prefix captured (cf. SSHPASS_RE below).
DB_P_PASS_RE = re.compile(
    r"(?i)(\b(?:mysql|mysqldump|mariadb|mongosh)\b[^\n]{0,300}?)(\s-p)\s*"
    r"('[^']*'|\"[^\"]*\"|[A-Za-z0-9][^\s;|&]*)")
REDIS_A_PASS_RE = re.compile(
    r"(?i)(\bredis-cli\b[^\n]{0,300}?)(\s-a)\s*"
    r"('[^']*'|\"[^\"]*\"|[A-Za-z0-9][^\s;|&]*)")
# curl basic-auth: `-u user:pass`, attached `-uuser:pass`, `--user user:pass`,
# `--user=user:pass`. Require the `user:pass` colon shape so a bare -u/--user in
# another tool isn't over-masked. Group 1 = flag+user:, group 2 = the password.
CURL_USERPASS_RE = re.compile(
    r"(?i)((?<![\w-])(?:-u\s*|--user[=\s]\s*)[^\s:;|&]+:)([^\s;|&]+)")
# Authorization: <scheme> <credential> -- mask the credential, keep the scheme.
# (KV_SECRET_RE alone masked only the scheme word 'token'/'basic', leaking the
# credential after it.) Group 1 = "Authorization: scheme ", group 2 = the cred.
AUTH_HEADER_RE = re.compile(
    r"(?i)(authorization\s*:\s*(?:bearer|token|basic|digest)\s+)(\"[^\"]*\"|'[^']*'|[^\s;|&]+)")
# Cloud-CLI credentials passed as a SPACE-delimited positional arg, e.g.
# `aws configure set aws_secret_access_key VALUE` -- no =/: so the other rules miss
# it. Group 1 = the key name + space, kept; group 2 = the value, masked.
ARG_SECRET_RE = re.compile(
    r"(?i)\b(aws_secret_access_key|aws_access_key_id|aws_session_token)(\s+)"
    r"(\"[^\"]*\"|'[^']*'|[^\s;|&]+)")

# PEM private-key block masking for STRINGS (commands/prompts): a pasted key in a
# prompt/command needs masking before it lands in the log.
# Masked by a LINEAR scanner (mask_pem_blocks), NOT a `HDR.*?FTR` regex: a lazy
# `.*?` between header and footer retries from EVERY header on input with many
# headers and no footer, which is quadratic (ReDoS) -- and redaction runs on the
# UNtruncated command/prompt, so a large crafted paste could stall the hook.
_PEM_HDR_RE = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")
_PEM_FTR_RE = re.compile(r"-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")


def mask_pem_blocks(text: str) -> str:
    """Replace each PEM PRIVATE KEY block with a marker, in O(n).

    For each BEGIN header, mask through the matching END (or to end-of-text if the
    footer is absent -- a key truncated by the length cap; the body after an
    unterminated header is exactly the secret). Each search advances the cursor, so
    the whole pass is linear regardless of how many headers appear."""
    if "-----BEGIN " not in text:            # cheap fast-path: no PEM header at all
        return text
    out = []
    i = 0
    n = len(text)
    while i < n:
        m = _PEM_HDR_RE.search(text, i)
        if not m:
            out.append(text[i:])
            break
        out.append(text[i:m.start()])
        out.append("<redacted: private key>")
        ftr = _PEM_FTR_RE.search(text, m.end())
        if ftr:
            i = ftr.end()
        else:
            # Dangling header (no END): mask only the following PEM-BODY run
            # (base64 / whitespace / dashes), NOT the entire rest of the string --
            # else `echo "-----BEGIN PRIVATE KEY-----"; rm -rf /` would swallow the
            # `rm` and hide it from the audit. Stop at the first non-body char (a
            # shell metacharacter, a quote, a word), preserving what follows.
            j = m.end()
            # PEM base64 body chars only (NO space/tab/dash): a real key body is
            # line-wrapped base64. Including space let `-----BEGIN PRIVATE KEY----- rm
            # file` swallow the trailing `rm file` command tokens into the mask.
            while j < n and (text[j].isalnum() or text[j] in "+/=\r\n"):
                j += 1
            i = j
    return "".join(out)

# A command longer than this is truncated for STORAGE (after redaction) so the log
# stays bounded. Redaction runs on the full string first (so a secret near the cap
# keeps its mask); the regexes are individually bounded to stay linear regardless.
MAX_COMMAND_CHARS = 8192
# A recorded user prompt is bounded the same way: the audit wants "what was
# asked", not a whole pasted file, and a huge paste should not bloat the log.
# Redaction (redact_prompt) still masks inline secrets before this is stored.
MAX_PROMPT_CHARS = 4096
# Per-Stop cap on how many transcript bytes are read into memory at once, so a huge
# (or maliciously swapped) transcript can't OOM the hook. The cursor advances by the
# complete lines consumed; any remainder is read on the next Stop.
MAX_TRANSCRIPT_READ = 64 * 1024 * 1024
# Cap on the hook's stdin payload, so a huge Write content (or a malicious payload)
# can't OOM the process before the fail-open guards run. Generous for a real Write.
MAX_PAYLOAD_BYTES = 32 * 1024 * 1024
# Extra flags for FIXED-PATH store files (lock/salt/session-log/cursor): O_NOFOLLOW
# refuses a symlinked store file; O_NONBLOCK makes an O_WRONLY open of a FIFO (that a
# malicious agent swapped in, since .alog lives under cwd) fail with ENXIO instead of
# blocking the hook forever. On a regular file these are no-ops.
_SAFE_STORE_OPEN = os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)


@contextlib.contextmanager
def safe_store_read(path, mode="rb", encoding=None, errors=None):
    """Open a FIXED-PATH store file (salt/session-log/manifest/pending/cursor) for
    READING without the two failure modes a plain open() has when a malicious agent
    swaps the node (``.alog`` lives under cwd): O_NONBLOCK returns immediately for a
    writer-less FIFO instead of parking the hook forever, O_NOFOLLOW refuses a
    symlinked store file, and the post-open ``fstat`` rejects any non-regular fd.

    This is the READ mirror of ``_SAFE_STORE_OPEN`` (which hardened only the store
    WRITE opens) and of ``parse_transcript_turns`` (which already does this for the
    transcript). Raises ``OSError`` -- which every caller already catches -- when the
    path is missing, a symlink, a FIFO/device, or otherwise not a regular file.
    """
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
                 | getattr(os, "O_NOFOLLOW", 0))
    try:
        fh = os.fdopen(fd, mode, encoding=encoding, errors=errors)
    except OSError:
        os.close(fd)
        raise
    try:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise OSError(errno.EINVAL, "not a regular store file", path)
        yield fh
    finally:
        fh.close()

# Hook events that carry NO tool_name but still feed the audit log: the user's
# prompt (what the agent was asked) and end-of-turn token/cost (read from the
# session transcript). Kept separate from the tool-gated Pre/PostToolUse path.
NONTOOL_EVENTS = {"UserPromptSubmit", "Stop", "SubagentStop"}

# Pending-stack bounds: orphan Pres (denied/aborted tools that never get a Post)
# must not accumulate without bound. TTL is wall-clock (skipped under a frozen
# test clock); the length cap is always enforced.
MAX_PENDING = 512
PENDING_TTL_SECONDS = 6 * 3600

# Tokens are split out of a command on shell separators to be classified.
CMD_SPLIT_RE = re.compile(r"[\s;|&><()\"'`]+")


# ---- helpers -------------------------------------------------------------

def log_internal(msg: str) -> None:
    if os.environ.get("ALOG_DEBUG"):
        sys.stderr.write("alog-hook: {0}\n".format(msg))


def data_dir(cwd: str) -> str:
    return os.environ.get("ALOG_DATA") or os.path.join(cwd, ".alog")


def ensure_dirs(base: str) -> None:
    """Create the store 0700, with a 0600 .gitignore (*) so it never commits."""
    os.makedirs(base, mode=0o700, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(base, 0o700)
    # NOTE: no "objects" dir -- file contents are never stored (v0.2+). A legacy
    # v0.1 store's objects/ is dead weight and can be deleted by the user.
    for sub in ("sessions", "pending", "locks", "manifests", "cursors"):
        d = os.path.join(base, sub)
        os.makedirs(d, mode=0o700, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chmod(d, 0o700)
    gi = os.path.join(base, ".gitignore")
    if not os.path.exists(gi):
        with open(gi, "w", encoding="utf-8") as fh:
            fh.write("# audit store may hold sensitive material -- never commit\n*\n")
        with contextlib.suppress(OSError):
            os.chmod(gi, 0o600)


def get_salt(base: str) -> bytes:
    """Per-store random HMAC key for ALL content digests (0600). Created once,
    exactly 16 bytes (a wrong length is healed, never honoured).

    The key means a recorded digest is not a plain ``sha256(content)``, so a digest
    seen WITHOUT the store (a log line pasted elsewhere, a cross-store rainbow
    table) cannot be matched to guessed content. It is NOT a defence against an
    attacker who has the whole ``.alog/`` -- the key lives there beside the digests,
    so treat the store as sensitive (it also holds command strings and prompts).
    One key per store keeps digest equality working across that store's sessions.
    """
    path = os.path.join(base, "salt")
    for _ in range(100):
        # Reader path: only trust an EXACTLY-16-byte salt. A racing creator may
        # have made the file but not yet written it (short read -> wait/retry).
        # A read of >16 bytes means the salt was TRUNCATED-then-extended (a hostile
        # agent can append to .alog/salt, which is excluded from Bash snapshots):
        # digests use HMAC now so length no longer creates a concatenation oracle,
        # but a variable-length salt still lets an attacker perturb only some files'
        # keys. Enforce a fixed 16 bytes -- read one past it and reject anything but
        # exactly 16 (heal below), so no oversized salt is ever honoured.
        if os.path.exists(path):
            try:
                with safe_store_read(path, "rb") as fh:
                    data = fh.read(17)
            except OSError:
                data = b""
            if len(data) == 16:
                return data
            if len(data) > 16:
                break                 # oversized/tampered -> heal to exactly 16
            time.sleep(0.005)
            continue
        # Writer path: O_EXCL means exactly one process wins the create; the
        # loser gets FileExistsError and falls back to the reader path. (No
        # exists()->create gap: the old TOCTOU dropped the loser's whole event
        # and an empty-salt read degraded the digest to an unsalted oracle.)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _SAFE_STORE_OPEN, 0o600)
        except FileExistsError:
            continue
        salt = os.urandom(16)
        with os.fdopen(fd, "wb") as fh:
            fh.write(salt)
        return salt
    # The file is present but NOT exactly 16 bytes: either TRUNCATED (creator died
    # between the O_EXCL create and the write -- SIGKILL on a hook timeout, or
    # ENOSPC) or EXTENDED past 16 (a hostile append). Either way it is untrusted --
    # a wrong-length salt lets an attacker weaken/perturb the per-store key. Heal it
    # under a store-wide lock so CONCURRENT healers converge on ONE salt instead of
    # each os.replace'ing its own (which would hand a session's Pre and Post
    # DIFFERENT keys -> incomparable digests -> a false 'modified'). NEVER return a
    # salt that is not exactly 16 bytes.
    return _heal_salt(base, path)


# Bound the wait for the store-wide salt-heal lock, mirroring the session lock: a
# wedged healer must not park the hook forever (main()'s try/except can't fail open
# on a thread blocked in flock). On timeout we degrade to an unlocked heal -- rare
# (real contention is sub-second), and the pre-write re-read still converges most
# racers on the holder's value.
SALT_LOCK_TIMEOUT = 10.0


def _heal_salt(base: str, path: str) -> bytes:
    """Write a fresh exactly-16-byte salt, serialized by a store-wide lock.

    Under the lock we RE-READ first: a prior healer may already have persisted a
    good salt, in which case every waiter returns THAT one value (convergence). Only
    when the salt is still bad do we os.replace our own. If the lock can't be taken
    (wedged holder) or persistence fails (disk full), we fall back best-effort to an
    in-memory salt so digests stay keyed rather than degrading to an unkeyed oracle.
    """
    def _read16() -> Optional[bytes]:
        with contextlib.suppress(OSError):
            with safe_store_read(path, "rb") as fh:
                data = fh.read(17)
            if len(data) == 16:
                return data
        return None

    def _write_fresh() -> bytes:
        salt = os.urandom(16)
        tmp = "{0}.{1}.{2}.tmp".format(path, os.getpid(), os.urandom(6).hex())
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(salt)
            os.replace(tmp, path)
            return _read16() or salt
        except OSError:
            with contextlib.suppress(OSError):
                if os.path.exists(tmp):
                    os.remove(tmp)
            return _read16() or salt

    try:
        lfd = os.open(os.path.join(base, "salt.lock"),
                      os.O_WRONLY | os.O_CREAT | _SAFE_STORE_OPEN, 0o600)
    except OSError:
        lfd = None
    if lfd is None:                       # cannot lock -> best-effort unlocked heal
        return _read16() or _write_fresh()
    try:
        acquired = False
        deadline = time.monotonic() + SALT_LOCK_TIMEOUT
        while True:
            try:
                fcntl.flock(lfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.02)
        # Re-read whether or not we got the lock: a holder that just finished has
        # persisted the winning salt, so a waiter (even one that timed out) returns
        # that shared value instead of minting a divergent one.
        healed = _read16()
        if healed is not None:
            return healed
        return _write_fresh()
    finally:
        if acquired:
            with contextlib.suppress(OSError):
                fcntl.flock(lfd, fcntl.LOCK_UN)
        os.close(lfd)


def now_ts(base: str) -> float:
    """Wall-clock epoch, unless ALOG_FROZEN_CLOCK pins a constant (for tests).

    When frozen the value is constant; events are ordered by ``seq`` (a
    per-session monotonic counter), not by this timestamp.
    """
    frozen = os.environ.get("ALOG_FROZEN_CLOCK")
    if frozen:
        return float(frozen)
    return time.time()


def is_allowlisted(path: str) -> bool:
    """NAME-based classification only: public / template artifacts that is_sensitive
    treats as NOT secret (public keys, public certs, env/vars templates), so they
    don't add audit noise. Classification only -- no content is ever stored for
    ANY file, allowlisted or not."""
    lname = os.path.basename(path.replace("\\", "/")).lower()
    if lname.endswith(".pub"):
        return True
    if lname in SENSITIVE_ALLOW_EXACT:
        return True
    if SENSITIVE_ALLOW_RE.search(lname):
        return True
    return False


def is_sensitive(path: str) -> bool:
    """Precise filename/path heuristic for 'this is probably a secret'.

    Order matters: a sensitive DIRECTORY SEGMENT (.ssh, .aws, secrets, ...) is
    checked FIRST and wins over the public/template allowlist -- so
    `secrets/.env.example` is flagged even though the basename is allowlisted (a
    template that lives inside a secrets dir is not safe to store). Then the
    allowlist, exact names, and globs. Callers pass the cwd-RELATIVE display path
    (so a generic 'secrets'/'gcloud' segment only matches WITHIN the repo, not a
    coincidental ancestor); the abspath dot-folder case is handled separately by
    abspath_has_sensitive_dir. All matching is case-insensitive.
    """
    norm = path.replace("\\", "/")
    name = os.path.basename(norm)
    lname = name.lower()
    # 1) sensitive directory segments FIRST (an exact dir component, never a
    # substring of the whole path so "wisshful.txt" isn't flagged for ".ssh").
    # This precedes the allowlist so an allowlisted basename can't override a
    # secrets/.ssh/.aws directory.
    dir_parts = [p.lower() for p in norm.split("/")[:-1] if p]
    for seg in SENSITIVE_PATH_SEGMENTS:
        if seg in dir_parts:
            return True
    # 2) allowlist -- public keys, public certs, env templates are not secrets.
    if is_allowlisted(path):
        return False
    # 3) exact names (the literals are already lowercase).
    if lname in SENSITIVE_EXACT_NAMES:
        return True
    # 4) globs (case-insensitive via the lowercased name).
    for glob in SENSITIVE_GLOBS:
        if fnmatch.fnmatch(lname, glob):
            return True
    return False


def abspath_has_sensitive_dir(abs_path: str) -> bool:
    """True if any dir component of the ABSOLUTE path is an unambiguous sensitive
    config dot-dir (.ssh/.aws/...). Handles the case where the agent's cwd is INSIDE
    such a dir (so the relative display path lost the segment). Generic nouns
    (secrets/gcloud) are deliberately NOT checked here -- an ancestor named 'secrets'
    is a common project location and must not wholesale-flag the repo."""
    parts = [p.lower() for p in abs_path.replace("\\", "/").split("/")[:-1] if p]
    return any(seg in parts for seg in SENSITIVE_DIR_SEGMENTS_ABS)


def _realpath_cached(ap: str, cache: Optional[Dict[str, Tuple[str, int, int]]]) -> str:
    """``os.path.realpath(ap)`` with per-PARENT-DIRECTORY memoization.

    ``realpath`` walks every path component with an ``lstat``-class syscall, so
    calling it per file made the whole-tree snapshot pay path-depth syscalls x
    every file x twice per Bash command (issue #7) -- the dominant cost on a
    manifest-warm tree, where nothing is re-hashed. Files share parents, so
    resolving each DIRECTORY once and joining the basename is equivalent for a
    non-symlink final component (realpath resolves the parent, then appends a
    non-link basename verbatim). A final component that IS a symlink -- or an
    odd ''/'.'/'..' basename -- falls back to the full resolution, so the
    classification verdict never changes, only the syscall count.

    Every cache HIT is revalidated against the parent's (st_dev, st_ino)
    fingerprint taken at resolution time: a bare memo would keep serving a
    stale resolution for the rest of the snapshot after the parent is swapped
    (e.g. renamed away and replaced by a symlink into ~/.ssh), widening the
    documented realpath race from per-file to per-snapshot. One ``lstat`` per
    file still beats the path-depth walk that motivated the memo, and on a
    mismatch (or lstat failure) the parent is re-resolved in full. The
    fingerprint is taken BEFORE resolving, so a swap in between at worst
    invalidates the fresh entry (a spurious re-resolve), never validates a
    stale one. What remains is the same per-file window as the uncached path:
    a swap between this check and the file's open is still raceable (see
    path_is_sensitive)."""
    if cache is None:
        return os.path.realpath(ap)
    parent, name = os.path.split(ap)
    if not parent or not name or name in (".", ".."):
        return os.path.realpath(ap)
    entry = cache.get(parent)
    if entry is not None:
        try:
            st = os.lstat(parent)
            if (st.st_dev, st.st_ino) != (entry[1], entry[2]):
                entry = None            # parent swapped -> re-resolve
        except OSError:
            entry = None                # parent gone/unreadable -> re-resolve
    if entry is None:
        try:
            fp = os.lstat(parent)
        except OSError:
            fp = None
        rparent = os.path.realpath(parent)
        if fp is not None:
            cache[parent] = (rparent, fp.st_dev, fp.st_ino)
        else:
            cache.pop(parent, None)     # unfingerprintable -> never serve stale
    else:
        rparent = entry[0]
    if os.path.islink(ap):          # rare: resolve the link itself in full
        return os.path.realpath(os.path.join(rparent, name))
    return os.path.join(rparent, name)


def path_is_sensitive(ap: str, disp: str, cwd: str,
                      rcwd: Optional[str] = None,
                      rp_cache: Optional[Dict[str, Tuple[str, int, int]]] = None
                      ) -> bool:
    """Full sensitivity classification for a snapshot: the display name/segments, an
    unambiguous ancestor dot-dir, OR -- resolving SYMLINKED ANCESTORS -- the real
    target's location. A symlinked parent (alias -> secrets/) makes the LEXICAL path
    non-sensitive while the bytes actually live under a sensitive dir; O_NOFOLLOW only
    guards the FINAL component, so os.open still follows the parent and would store the
    target. (realpath is best-effort: a concurrent swap of the ancestor is raceable.)

    ``rcwd``/``rp_cache`` let a whole-tree caller (snapshot_tree) resolve the cwd
    ONCE per snapshot and memoize ancestor resolution per parent directory,
    instead of paying path-depth lstat calls x2 for every file (issue #7)."""
    if is_sensitive(disp):
        return True
    if abspath_has_sensitive_dir(os.path.abspath(ap)):
        return True
    # Resolve SYMLINKED ANCESTORS. Relativize against the RESOLVED cwd so a system
    # symlink prefix (/var->/private/var, /tmp->/private/tmp) doesn't expose an
    # ancestor segment -- only a symlink WITHIN the path (alias -> secrets/) then
    # surfaces a sensitive segment in the relative form.
    try:
        rp = _realpath_cached(ap, rp_cache)
        if rcwd is None:
            rcwd = os.path.realpath(cwd)
    except OSError:
        return False
    if abspath_has_sensitive_dir(rp) or is_sensitive(rel_to_cwd(rcwd, rp)):
        return True
    return False


def _truncate(text: str, limit: int) -> str:
    """Cap a string, appending how many bytes were dropped (bounds stored size).

    Applied AFTER redaction (see redact_command/redact_prompt), so it never
    shears a secret out of its mask; the redaction regexes are individually
    bounded/anchored (e.g. URL_CRED_RE's {0,15} scheme run) to stay linear on the
    untruncated input."""
    if len(text) > limit:
        return text[:limit] + "…[+{0}B truncated]".format(len(text) - limit)
    return text


def _value_looks_secretish(value: str) -> bool:
    """Heuristic for the PROMPT path only: does a key=value's value look like real
    key material rather than an ordinary prose word? A secret value tends to be
    long, or mix letters+digits, or carry symbols; plain words ('yes', 'economics')
    do not. Used to stop 'auth: yes' / 'token: economics' being mangled while still
    masking 'api_key: aB3xK9...'. Fail-safe: on doubt for shell COMMANDS we never
    apply this (commands legitimately carry KEY=secret and are not prose)."""
    # Strip surrounding quotes AND trailing sentence punctuation: 'auth: yes.' /
    # 'token: economics,' are prose, but a trailing '.'/',' used to trip the symbol
    # test below and over-mask them. Real key material still qualifies via length or
    # an internal letter+digit mix; only a purely-trailing punctuation mark is dropped.
    v = value.strip("\"'").rstrip(".,!?;:")
    if len(v) >= 16:
        return True
    if any(c.isdigit() for c in v) and any(c.isalpha() for c in v):
        return True
    if any((not c.isalnum()) and c not in "-_" for c in v):
        return True
    return False


# Unambiguous credential key names: their value is a secret regardless of how it
# looks, so it is masked even in PROSE (where the entropy heuristic would otherwise
# spare a short dictionary-word value like `password: swordfish`).
_HIGH_CONF_KV_RE = re.compile(
    r"(?i)\b(?:password|passwd|passphrase|pgpassword|client[_-]?secret|"
    r"private[_-]?key|secret[_-]?access[_-]?key)\b")


def _kv_sub(match, prose: bool) -> str:
    # High-confidence key -> always mask (even a short prose value). Otherwise, in
    # prose, only mask a value that looks like real key material so ordinary phrasing
    # ('auth: yes') survives.
    if prose and not _HIGH_CONF_KV_RE.search(match.group(1)) \
            and not _value_looks_secretish(match.group(2)):
        return match.group(0)          # ordinary prose 'word: word' -- leave intact
    return match.group(1) + "<redacted>"


def _apply_secret_subs(text: str, prose: bool = False) -> str:
    """Run every inline-secret masking rule over a string.

    Order matters: a PEM private-key block is masked first (highest value, and
    masking the whole block avoids the KV/token rules nibbling its interior); then
    the Authorization-header rule runs before KV so the credential -- not just the
    scheme word 'token'/'basic' -- is masked. With ``prose=True`` (prompts) the KV
    rule only fires when the value looks like real key material, so ordinary prose
    ('auth: yes') is preserved.
    """
    out = text
    out = mask_pem_blocks(out)               # linear PEM masking (no ReDoS)
    out = AUTH_HEADER_RE.sub(lambda m: m.group(1) + "<redacted>", out)
    out = ARG_SECRET_RE.sub(lambda m: m.group(1) + m.group(2) + "<redacted>", out)
    out = SSHPASS_RE.sub(lambda m: m.group(1) + "<redacted>", out)
    out = DB_P_PASS_RE.sub(lambda m: m.group(1) + m.group(2) + "<redacted>", out)
    out = REDIS_A_PASS_RE.sub(lambda m: m.group(1) + m.group(2) + "<redacted>", out)
    out = CURL_USERPASS_RE.sub(lambda m: m.group(1) + "<redacted>", out)
    out = KV_SECRET_RE.sub(lambda m: _kv_sub(m, prose), out)
    out = URL_CRED_RE.sub(lambda m: m.group(1) + "<redacted>" + m.group(3), out)
    out = FLAG_SECRET_RE.sub(lambda m: m.group(1) + "<redacted>", out)
    out = (BEARER_STRICT_RE if prose else BEARER_LOOSE_RE).sub("<redacted>", out)
    for rx in TOKEN_SHAPE_RES:
        out = rx.sub("<redacted>", out)
    return out


# How much MORE than the stored cap to run redaction over: enough to mask a secret
# that straddles the cap boundary, without scanning a possibly-multi-MB command in
# full (which would make every redaction regex traverse the whole text and stall the
# hook). Bytes past (cap + margin) are truncated away, so they are never stored.
_REDACT_MARGIN = 4096


def _redact_bounded(text: str, cap: int, prose: bool) -> str:
    """Redact a prefix of the text, then truncate to `cap`. Redaction runs over only
    (cap + margin) chars so it stays fast on a huge input; the tail beyond that is
    truncated away (never stored). Redact-before-truncate keeps a secret straddling
    the cap from being sheared out of its own mask."""
    red = _apply_secret_subs(text[:cap + _REDACT_MARGIN], prose)
    if len(text) > cap:
        return red[:cap] + "…[+{0}B truncated]".format(len(text) - cap)
    return red


def redact_command(command: str) -> str:
    """Best-effort masking of inline secrets before a command is stored."""
    return _redact_bounded(command, MAX_COMMAND_CHARS, prose=False)


def redact_prompt(text: str) -> str:
    """Best-effort masking of inline secrets in a user prompt before it is stored.

    A prompt is prose, not a shell line, but a pasted `API_KEY=...`, Bearer token,
    `user:pass@host` URL, or PEM private key leaks the same way, so the same masks
    apply (with `prose=True` so ordinary `word: word` phrasing is not mangled).
    This is a backstop, not a guarantee: freeform secrets with no recognisable
    shape are not caught -- the audit records what was asked, and keeping the store
    from being a cleartext secret sink is a best-effort property here (unlike file
    content, which is never persisted at all).

    Redact before truncating (see redact_command) so a secret near the length cap
    can't be split out of its own mask by the truncation boundary."""
    return _redact_bounded(text, MAX_PROMPT_CHARS, prose=True)


def _normalize_cmd_path(tok: str, cwd: str) -> str:
    """Render a command-line path token into the SAME display form a change path
    uses, but ONLY for a token that resolves INSIDE cwd: './.env' -> '.env'.

    Without this the reader's de-dup ('marker in change-paths') never matches a
    non-normalized in-tree token against its own changed file, so one sensitive
    file is counted twice -- once as a change and once as a command-ref. A '~/...',
    an absolute path, or an out-of-tree '../x' is left verbatim: it never collides
    with an under-cwd change path, and keeping it as written stays readable."""
    if tok.startswith("~") or os.path.isabs(tok):
        return tok
    disp = rel_to_cwd(cwd, os.path.join(cwd, tok))
    # rel_to_cwd returns an ABSOLUTE path when the token escaped cwd ('../x'); in
    # that case keep the original token rather than rewrite it to an absolute path.
    return disp if not os.path.isabs(disp) else tok


def scan_cmd_for_secrets(command: str, cwd: str) -> List[str]:
    """Sensitive paths referenced by a Bash command (tokenized + classified).

    Returned paths are normalized to the change-path display form so the reader
    can de-dup a command-ref against the same file's recorded change."""
    found: List[str] = []
    for raw in CMD_SPLIT_RE.split(command):
        raw = raw.strip()
        if not raw:
            continue
        candidates = []
        if "=" in raw:               # --kubeconfig=/p, FOO=/p -- classify the RHS
            candidates.append(raw.split("=", 1)[1])
        elif not raw.startswith("-"):  # plain path token (elif: don't double-count
            candidates.append(raw)     # a 'NAME=/path' as both RHS and whole token)
        for tok in candidates:
            if not tok:
                continue
            probe = tok[2:] if tok.startswith("~/") else tok
            hit = is_sensitive(probe)
            if not hit:
                # A symlink whose target is sensitive: `cat alias.txt` (-> .env) would
                # otherwise not be flagged, since the token's own name isn't sensitive.
                with contextlib.suppress(OSError):
                    resolved = probe if os.path.isabs(probe) else os.path.join(cwd, probe)
                    if os.path.islink(resolved) and is_sensitive(os.path.realpath(resolved)):
                        hit = True
            if hit:
                disp = _normalize_cmd_path(tok, cwd)
                if disp not in found:
                    found.append(disp)
    return found


def salted_digest(salt: bytes, content: bytes, sensitive: bool = False) -> str:
    """Keyed, truncated digest -- the ONLY thing ever recorded about a file's
    content. File bytes are never written anywhere (no CAS / object store).

    Uses HMAC-SHA256 (salt as the key), NOT ``sha256(salt + content)``: a plain
    concatenation is ambiguous (``sha256(A + B)`` where the split is unknown), so
    an attacker who can extend ``.alog/salt`` by a file's own prefix could make a
    real change hash-collide with the pre-change state and hide it as an unchanged
    'read'. HMAC's fixed block/keying removes that boundary ambiguity; get_salt's
    exact-16-byte enforcement backs it up. Events only compare digests for
    before/after EQUALITY, so a truncated keyed hash carries all the audit needs.
    The ``S:`` prefix marks a sensitive file (name/path heuristic) purely for
    readability; ``D:`` is everything else."""
    prefix = "S:" if sensitive else "D:"
    return prefix + hmac.new(salt, content, hashlib.sha256).hexdigest()[:16]


def sensitive_digest(salt: bytes, content: bytes) -> str:
    """Salted, truncated digest for a sensitive file (compat wrapper)."""
    return salted_digest(salt, content, sensitive=True)


def _toolarge_rec(st, sensitive: bool) -> Dict:
    """Record for a file too big to hash: carry size+mtime+ctime so a change is
    still detectable (a rewrite bumps ctime even if mtime is forged), and keep the
    redacted flag for a sensitive large file so it isn't shown as plain content."""
    return {"sha": None, "size": st.st_size, "toolarge": True,
            "mtime": st.st_mtime_ns, "ctime": st.st_ctime_ns,
            "redacted": bool(sensitive)}


def _nonregular_rec(abs_path: str) -> Dict:
    """Record for a non-regular path (symlink / fifo / socket / device).

    Carry the symlink TARGET plus the link's own lstat mtime/ctime so a symlink
    REPOINTED in place (its target swapped while it stays a symlink) is detectable:
    without them, before/after are two identical ``sha=None`` stubs that tie in
    build_changes and a retarget (e.g. ``ln -sf /etc/shadow link``) hides as an
    unchanged 'read'."""
    rec: Dict = {"sha": None, "size": 0, "kind": "non-regular"}
    with contextlib.suppress(OSError):
        lst = os.lstat(abs_path)
        rec["mtime"] = lst.st_mtime_ns
        rec["ctime"] = lst.st_ctime_ns
        if stat.S_ISLNK(lst.st_mode):
            with contextlib.suppress(OSError):
                # Redact the target before storing: a symlink can point AT a secret
                # (e.g. `ln -s 'postgres://u:pw@host' link`), and the raw readlink()
                # text would otherwise land in the pending/manifest/event log in
                # cleartext. It is only compared for equality (repoint detection), so
                # the redacted form is sufficient.
                rec["link_target"] = redact_command(os.readlink(abs_path))
            with contextlib.suppress(OSError):
                # A symlink whose RESOLVED target is sensitive (alias.txt -> .env) is
                # a secret access under an innocuous name; O_NOFOLLOW won't read it and
                # the link's own name isn't sensitive, so flag it here for the audit.
                if is_sensitive(os.path.realpath(abs_path)):
                    rec["target_sensitive"] = True
    return rec


def snapshot_file(abs_path: str, salt: bytes, sensitive: bool) -> Optional[Dict]:
    """Digest one regular file (salted hash + metadata). None if it does not exist.

    No file bytes are ever persisted -- every file is recorded as a salted,
    truncated digest plus size/mode; ``sensitive`` only switches the digest
    prefix and sets the ``redacted`` flag for the audit view. Symlinks are never
    followed (opened O_NOFOLLOW so a swap after any check can't reach the
    target); other non-regular paths are recorded as kind='non-regular'.
    """
    if not os.path.lexists(abs_path):
        return None
    # Open with O_NOFOLLOW so a symlink -- including one swapped in AFTER an earlier
    # stat (the classify->read TOCTOU) -- is rejected (ELOOP) rather than followed
    # to its target's bytes. O_NONBLOCK keeps a FIFO/device from blocking the open;
    # we fstat the real fd and only read regular files.
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(abs_path, flags)
    except OSError as exc:
        if getattr(exc, "errno", None) == errno.ELOOP:
            return _nonregular_rec(abs_path)
        try:
            st = os.lstat(abs_path)
        except OSError:
            return {"sha": None, "size": 0, "unreadable": True,
                    "redacted": bool(sensitive)}
        if not stat.S_ISREG(st.st_mode):
            return _nonregular_rec(abs_path)
        return {"sha": None, "size": st.st_size, "unreadable": True,
                "mtime": st.st_mtime_ns, "ctime": st.st_ctime_ns,
                "redacted": bool(sensitive)}
    try:
        with os.fdopen(fd, "rb") as fh:
            st = os.fstat(fh.fileno())
            if not stat.S_ISREG(st.st_mode):   # FIFO/socket/device -- not content
                return _nonregular_rec(abs_path)
            if st.st_size > MAX_HASH_BYTES:
                return _toolarge_rec(st, sensitive)
            # Read one past the cap: if the file GREW past the limit, treat it as
            # too-large rather than slurping unbounded bytes.
            content = fh.read(MAX_HASH_BYTES + 1)
    except OSError as exc:
        log_internal("unreadable {0}: {1}".format(abs_path, exc))
        # Carry size/mtime so a later change to a still-unreadable file is not
        # mistaken for an unchanged 'read' (both-None sha would otherwise tie).
        try:
            est = os.lstat(abs_path)
            return {"sha": None, "size": est.st_size, "unreadable": True,
                    "mtime": est.st_mtime_ns, "ctime": est.st_ctime_ns,
                    "redacted": bool(sensitive)}
        except OSError:
            return {"sha": None, "size": 0, "unreadable": True,
                    "redacted": bool(sensitive)}
    if len(content) > MAX_HASH_BYTES:
        return _toolarge_rec(st, sensitive)
    mode = stat.S_IMODE(st.st_mode)          # permission bits, for chmod detection
    rec = {"sha": salted_digest(salt, content, sensitive),
           "size": len(content), "mode": mode}
    if sensitive:
        rec["redacted"] = True   # sensitive access -- surfaced by `alog audit`
    return rec


def rel_to_cwd(cwd: str, abs_path: str) -> str:
    try:
        common = os.path.commonpath([os.path.abspath(abs_path), cwd])
    except ValueError:
        return abs_path
    if common == cwd:
        return os.path.relpath(abs_path, cwd)
    return abs_path


def walk_worktree(cwd: str, store_base: Optional[str] = None,
                  max_files: Optional[int] = None,
                  deadline: Optional[float] = None) -> List[str]:
    # ``store_base`` is the audit store's own directory (data_dir()); it is pruned
    # from the walk by ABSOLUTE PATH, not by the hardcoded name '.alog'. With
    # ALOG_DATA pointing at an in-repo dir under any other name, the old name-only
    # skip walked (and re-hashed) the growing store itself on every Bash --
    # quadratic growth, plus digesting the salt file with itself.
    #
    # ``max_files`` / ``deadline`` (time.monotonic epoch) are the issue-#5 ceilings:
    # the walk STOPS as soon as either is exceeded (raising TreeCeilingExceeded, so
    # the caller can skip the snapshot loudly) instead of grinding through an
    # arbitrarily large tree. Both default to None (unbounded) for direct callers;
    # snapshot_tree passes the ALOG_MAX_TREE_* values.
    # os.walk is NOT usable here: CPython materialises the WHOLE scandir result
    # into dirs/files before yielding the first tuple, so a directory holding
    # millions of entries in ONE level blows past both ceilings (and can OOM the
    # hook) before any check can run. We drive os.scandir ourselves and test the
    # ceilings while consuming each DirEntry, before accumulating it.
    #
    # ``seen`` counts EVERY enumerated entry -- directories and fifos/sockets too,
    # not just the files we keep. The cost being bounded is the enumeration, so
    # that is what the ceiling has to measure.
    skip_abs = os.path.abspath(store_base) if store_base else None
    start = time.monotonic()
    out: List[str] = []
    seen = 0
    stack = [cwd]

    def _check(where: str = "") -> None:
        if max_files is not None and seen > max_files:
            raise TreeCeilingExceeded("file_count", seen, time.monotonic() - start)
        if (deadline is not None
                and seen % _TREE_DEADLINE_CHECK_EVERY == 0
                and time.monotonic() > deadline):
            raise TreeCeilingExceeded("time_budget", seen, time.monotonic() - start)

    while stack:
        current = stack.pop()
        try:
            it = os.scandir(current)
        except OSError as exc:
            # An unreadable directory used to be swallowed by os.walk's default
            # error handling, so a change inside a mode-000 subtree produced
            # "zero changes, no gap" -- a false all-clear. Refuse to pretend.
            raise TreeCeilingExceeded(
                "walk_error", seen, time.monotonic() - start,
                "{0}: {1}".format(rel_to_cwd(cwd, current), exc.strerror or exc))
        with it:
            while True:
                try:
                    entry = next(it)
                except StopIteration:
                    break
                except OSError as exc:
                    raise TreeCeilingExceeded(
                        "walk_error", seen, time.monotonic() - start,
                        "{0}: {1}".format(rel_to_cwd(cwd, current),
                                          exc.strerror or exc))
                seen += 1
                _check()
                try:
                    is_link = entry.is_symlink()
                    is_dir = (not is_link) and entry.is_dir(follow_symlinks=False)
                    is_reg = (not is_link) and entry.is_file(follow_symlinks=False)
                except OSError as exc:
                    # The entry vanished or cannot be stat'ed. Treating it as
                    # absent would silently drop it from both snapshots and hide
                    # a real change, so this is a gap too.
                    raise TreeCeilingExceeded(
                        "walk_error", seen, time.monotonic() - start,
                        "{0}: {1}".format(rel_to_cwd(cwd, entry.path),
                                          exc.strerror or exc))
                if is_dir:
                    if entry.name in TREE_SKIP_DIRS:
                        continue
                    if skip_abs is not None and os.path.abspath(entry.path) == skip_abs:
                        continue           # the audit store itself -- never walk it
                    stack.append(entry.path)
                    continue
                # Record symlinks too -- snapshot_file classifies them non-regular
                # (via O_NOFOLLOW), so a Bash-created or -replaced symlink is not
                # invisible to the tree diff. A symlink to a directory is recorded
                # and never descended. Other non-regular entries (fifo/socket/
                # device) are counted above but not recorded.
                if is_link or is_reg:
                    out.append(entry.path)
    return out


def named_file_path(tool: str, tool_input: Dict, cwd: str) -> Optional[str]:
    if tool not in SINGLE_FILE_TOOLS:
        return None
    fp = tool_input.get("file_path") or tool_input.get("notebook_path")
    if not fp or not isinstance(fp, str):
        return None
    return fp if os.path.isabs(fp) else os.path.join(cwd, fp)


def files_of_interest(tool: str, tool_input: Dict, cwd: str) -> List[str]:
    # Only single-file tools reach here: the Bash whole-tree path goes through
    # snapshot_tree (see _snapshot), so there is no Bash branch to maintain.
    if tool in SINGLE_FILE_TOOLS:
        fp = named_file_path(tool, tool_input, cwd)
        return [fp] if fp else []
    return []


def snapshot_set(abs_paths: List[str], cwd: str,
                 salt: bytes) -> Dict[str, Optional[Dict]]:
    snap: Dict[str, Optional[Dict]] = {}
    for ap in abs_paths:
        disp = rel_to_cwd(cwd, ap)
        # Classify by the ABSOLUTE path so a sensitive segment ABOVE cwd (e.g. the
        # agent runs under ~/.ssh, making disp just "config") is still seen.
        snap[disp] = snapshot_file(ap, salt, path_is_sensitive(ap, disp, cwd))
    return snap


# ---- whole-tree snapshot with a persistent reuse manifest (Bash) ----------

def manifest_path(base: str, session: str) -> str:
    return os.path.join(base, "manifests", _safe_session(session) + ".json")


def load_manifest(base: str, session: str) -> Dict[str, Dict]:
    path = manifest_path(base, session)
    if not os.path.exists(path):
        return {}
    try:
        with safe_store_read(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_manifest(base: str, session: str, manifest: Dict[str, Dict]) -> None:
    path = manifest_path(base, session)
    tmp = "{0}.{1}.{2}.tmp".format(path, os.getpid(), os.urandom(6).hex())
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)
        os.replace(tmp, path)
    finally:
        with contextlib.suppress(OSError):
            if os.path.exists(tmp):
                os.remove(tmp)


def _reusable_rec(rec: Optional[Dict], cur_sensitive: bool) -> bool:
    """Whether a manifest-cached rec may be reused for an unchanged file.

    Two gates beyond the stat-key match the caller already did:

    1. DIGEST FORMAT. Only a v0.2 keyed digest (``D:``/``S:`` prefix) or a
       content-less rec (``sha`` is None: too-large / unreadable / non-regular)
       may be reused. A v0.1 store's plain 64-hex ``sha256(content)`` shares the
       exact same ``{key, rec}`` manifest schema, so without this check an
       upgraded store would copy those UNSALTED hashes verbatim into new v0.2
       events -- re-introducing the offline oracle the keyed digest removed.
    2. CLASSIFICATION CONTEXT. path_is_sensitive depends on the cwd-relative
       display path, so one abspath can be sensitive under cwd A (``secrets/x``)
       and not under cwd B (``x``). Reusing a rec whose sensitivity no longer
       matches would emit a stale ``S:``/redacted (or ``D:``) record in the wrong
       context. Require the cached rec's sensitivity to equal the current one.
    """
    if not isinstance(rec, dict) or "sha" not in rec:
        return False
    sha = rec.get("sha")
    if sha is not None and not (isinstance(sha, str) and sha[:2] in ("D:", "S:")):
        return False                    # v0.1 plain-hex / corrupt -> re-read
    cached_sensitive = (isinstance(sha, str) and sha.startswith("S:")) \
        or bool(rec.get("redacted"))
    return cached_sensitive == cur_sensitive


def snapshot_tree(base: str, cwd: str, salt: bytes,
                  session: str) -> Dict[str, Optional[Dict]]:
    """Whole-worktree snapshot, but reuse the prior snapshot's record for any file
    whose (mtime_ns, ctime_ns, size) is unchanged -- so unchanged files are NOT
    re-read or re-hashed. The first call is cold (O(N) read); later calls are
    O(N stat + changed-files read), which is the realistic case across the many
    Bash commands of a session.

    Why ctime in the key (not just mtime+size): a content rewrite that forges
    mtime (touch -r / cp -p) still bumps ctime, so a stale record can't be reused
    for a changed file -- the reuse stays as safe as a full re-hash for any real
    write. The cache only ever SAVES a read; every entry is re-validated by stat.

    CEILINGS (issue #5): raises TreeCeilingExceeded when the ALOG_MAX_TREE_FILES /
    ALOG_MAX_TREE_SECONDS budget is exceeded (in the walk OR in the hashing loop
    below -- on a cold manifest the hashing dominates). The caller skips the tree
    snapshot for this event and records the gap; the manifest on disk is left
    UNTOUCHED, so an aborted snapshot never evicts the warm cache. The file-count
    ceiling also naturally bounds the manifest's entry count (issue #7).
    """
    max_files = tree_max_files()
    max_seconds = tree_max_seconds()
    start = time.monotonic()
    deadline = start + max_seconds if max_seconds > 0 else None
    manifest = load_manifest(base, session)
    snap: Dict[str, Optional[Dict]] = {}
    new_manifest: Dict[str, Dict] = {}
    # Resolve cwd ONCE and memoize ancestor realpath per parent dir (issue #7):
    # per-file realpath cost path-depth lstat x2 per file per snapshot, which
    # dominated manifest-warm snapshots. Cache hits are fingerprint-revalidated
    # (see _realpath_cached), so a parent swapped mid-snapshot is re-resolved.
    # OSError here mirrors the old per-file guard: leave rcwd unresolved and
    # path_is_sensitive degrades the same way.
    rp_cache: Dict[str, Tuple[str, int, int]] = {}
    try:
        rcwd: Optional[str] = os.path.realpath(cwd)
    except OSError:
        rcwd = None
    processed = 0
    for ap in walk_worktree(cwd, base, max_files=max_files or None,
                            deadline=deadline):
        processed += 1
        # Check the deadline EVERY file: a per-chunk (modulo) check let the
        # final chunk -- or a whole tree smaller than the chunk -- overrun the
        # time budget by up to chunk-size MAX_HASH_BYTES reads on a slow mount.
        if deadline is not None and time.monotonic() > deadline:
            raise TreeCeilingExceeded("time_budget", processed,
                                      time.monotonic() - start)
        disp = rel_to_cwd(cwd, ap)
        # Key the cache by ABSOLUTE path, not the cwd-relative display path: one
        # session can span multiple cwds with a shared store, and two distinct
        # files at the same relative path (projA/VERSION vs projB/VERSION) would
        # otherwise collide and reuse the wrong file's hash on a stat tie.
        mkey = os.path.abspath(ap)
        try:
            st = os.lstat(ap)
        except OSError:
            continue
        key = [st.st_mtime_ns, st.st_ctime_ns, st.st_size]
        cached = manifest.get(mkey)
        # RACY-CLEAN guard (git's mitigation): on a COARSE-granularity filesystem
        # (whole-second mtime/ctime -- legacy ext4 128-byte inodes, many NFS/SMB/FAT
        # mounts), a same-size write that lands in the same tick as the prior snapshot
        # leaves (mtime, ctime, size) unchanged, so the stat key wrongly says
        # "unchanged" and a real modification (and any secret it wrote) is dropped as
        # 'read'. The signal is a timestamp with NO sub-second component; when we see
        # it, don't trust the key -- re-hash. On a nanosecond-resolution FS this is
        # virtually never set, so the reuse cache stays fully effective.
        racy = (st.st_mtime_ns % 1_000_000_000 == 0
                or st.st_ctime_ns % 1_000_000_000 == 0)
        cur_sensitive = path_is_sensitive(ap, disp, cwd, rcwd, rp_cache)
        cached_rec = cached.get("rec") if isinstance(cached, dict) else None
        if (not racy and isinstance(cached, dict) and cached.get("key") == key
                and _reusable_rec(cached_rec, cur_sensitive)):
            rec = cached_rec                          # unchanged -> reuse, no read
        else:
            rec = snapshot_file(ap, salt, cur_sensitive)
        snap[disp] = rec
        new_manifest[mkey] = {"key": key, "rec": rec}
    # Skip the O(N) JSON dump + atomic replace when nothing changed since the last
    # snapshot (the common warm case: a Bash command that wrote nothing). Reused
    # entries keep the loaded dict identity, so equality is cheap and exact; this
    # halves the manifest dumps of an idle Pre/Post pair (issue #7).
    if new_manifest != manifest:
        save_manifest(base, session, new_manifest)
    return snap


# ---- per-session lock (serialize a session's hook events) ----------------

def _safe_session(session) -> str:
    """Filesystem-safe, INJECTIVE session name. Replacing '/'->'_' alone collided
    ('a/b' and 'a_b' mapped to one file and shared state); we append a short hash
    whenever any character is rewritten (or the result is empty/dot) so distinct
    sessions never share a pending stack / ndjson. Pure [A-Za-z0-9_.-] names (e.g.
    UUID session ids) are left untouched for readable filenames.

    Tolerant of a malformed session_id: a non-string (int/list) is coerced via str()
    -- re.sub would otherwise raise TypeError -- and the hash encodes with
    'surrogatepass' so a lone-surrogate id (which survives json.loads, e.g.
    "\\ud800abc") doesn't raise UnicodeEncodeError. Either failure would be swallowed
    by main()'s fail-open guard and silently drop EVERY event for that session, since
    this name is on the lock/pending/ndjson/manifest/cursor path.

    A coerced non-string ALWAYS takes the disambiguating-hash branch, so int 1 and
    str "1" (both stringify to "1") never collide onto one session file -- the
    injectivity the hash exists to guarantee."""
    coerced = not isinstance(session, str)
    if coerced:
        session = str(session) if session is not None else "default"
    s = session or "default"
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", s)
    if coerced or safe != s or safe in ("", ".", ".."):
        base_name = safe if safe not in ("", ".", "..") else "s"
        digest = hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest()[:8]
        safe = base_name + "-" + digest
    return safe


# Bound the wait for the per-session lock. A blocking flock(LOCK_EX) would park the
# hook forever if a same-session holder wedges (stalled I/O, slow NFS), and main()'s
# try/except cannot fail open on a thread parked in the syscall. With a deadline we
# retry LOCK_NB and, on timeout, raise (caught by main -> return 0), skipping this one
# event (logged via log_internal) rather than stalling the agent's tool pipeline. Kept
# short: real contention is sub-second, so a multi-second wait means a wedged holder.
LOCK_ACQUIRE_TIMEOUT = 10.0


def _dropped_counter_path(base: str, safe: str) -> str:
    """Counter file recording session-lock-timeout drops: one byte per dropped
    event (its SIZE is the count). Appends are atomic (O_APPEND), so concurrent
    droppers never lose each other's mark without any locking -- which is the
    point: this path runs exactly when the lock could NOT be taken."""
    return os.path.join(base, "locks", safe + ".dropped")


def _record_dropped_event(base: str, safe: str) -> None:
    """Mark one event as dropped (lock timeout). Best-effort and fail-open: a
    failure to record the drop must never turn the drop into a crash."""
    with contextlib.suppress(OSError):
        fd = os.open(_dropped_counter_path(base, safe),
                     os.O_WRONLY | os.O_CREAT | os.O_APPEND | _SAFE_STORE_OPEN,
                     0o600)
        try:
            os.write(fd, b"1")
        finally:
            os.close(fd)


def _flush_dropped_events(base: str, session: str) -> None:
    """Called under the session lock, before the next event is written: if any
    events were dropped on lock timeout, append ONE ``events_dropped`` marker so
    the audit log records the gap -- a silent gap would read as "no access
    happened", a false all-clear (issue #7). Best-effort: a drop recorded between
    the size read and the truncate below is lost (it required a concurrent
    timeout in that microsecond window; the semantics stay fail-open)."""
    safe = _safe_session(session)
    path = _dropped_counter_path(base, safe)
    try:
        count = os.path.getsize(path)
    except OSError:
        return                                    # no counter file -> no drops
    if count <= 0:
        return
    with contextlib.suppress(OSError, ValueError, TypeError):
        _append_event(base, session, {
            "seq": next_seq(base, session),
            "session": session,
            "kind": "events_dropped",
            "ts": now_ts(base),
            "count": int(count),
            "reason": "session_lock_timeout",
        })
        fd = os.open(path, os.O_WRONLY | os.O_TRUNC | _SAFE_STORE_OPEN, 0o600)
        os.close(fd)


@contextlib.contextmanager
def session_lock(base: str, session: str):
    safe = _safe_session(session)
    path = os.path.join(base, "locks", safe + ".lock")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | _SAFE_STORE_OPEN, 0o600)
    acquired = False
    try:
        deadline = time.monotonic() + LOCK_ACQUIRE_TIMEOUT
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    log_internal("session lock busy {0}; dropping event".format(safe))
                    # Record the drop so the NEXT successful writer appends an
                    # ``events_dropped`` marker -- the gap must not be silent.
                    _record_dropped_event(base, safe)
                    raise TimeoutError("session lock busy: " + safe)
                time.sleep(0.02)
        # Holding the lock: surface any drops recorded by earlier timed-out
        # writers before this event is appended (fail-open on its own errors).
        with contextlib.suppress(Exception):
            _flush_dropped_events(base, session)
        yield
    finally:
        if acquired:
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


# ---- pending stack (Pre -> Post correlation) -----------------------------

def pending_path(base: str, session: str) -> str:
    return os.path.join(base, "pending", _safe_session(session) + ".json")


def _load_stack(path: str) -> List[Dict]:
    if not os.path.exists(path):
        return []
    try:
        with safe_store_read(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return []
    if not isinstance(data, list):
        log_internal("pending not a list; resetting")
        return []
    return [r for r in data if isinstance(r, dict)]


def _write_stack(path: str, stack: List[Dict]) -> None:
    # Per-writer tmp name (pid+random), matching save_manifest: on a
    # filesystem where flock is advisory-ignored (some NFS/SMB), two same-session
    # writers would otherwise share one fixed `.tmp` inode and interleave writes.
    tmp = "{0}.{1}.{2}.tmp".format(path, os.getpid(), os.urandom(6).hex())
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(stack, fh)
        os.replace(tmp, path)
    finally:
        # Remove a partial tmp if json.dump failed mid-write (ENOSPC/EIO) before the
        # replace -- mirrors save_manifest so no stray .tmp is left behind.
        with contextlib.suppress(OSError):
            if os.path.exists(tmp):
                os.remove(tmp)


def list_pending(base: str, session: str) -> List[Dict]:
    """The still-open Pre records for a session (Pres without a Post yet)."""
    return _load_stack(pending_path(base, session))


def push_pending(base: str, session: str, record: Dict) -> None:
    path = pending_path(base, session)
    stack = _load_stack(path)
    stack.append(record)
    # Evict stale orphan Pres so a stream of denied/aborted tools can't grow the
    # stack forever. TTL is skipped under a frozen clock (all ts equal); the
    # length cap always applies.
    now = record.get("ts")
    if now and not os.environ.get("ALOG_FROZEN_CLOCK"):
        stack = [r for r in stack
                 if (now - (r.get("ts") or now)) <= PENDING_TTL_SECONDS]
    if len(stack) > MAX_PENDING:
        stack = stack[-MAX_PENDING:]
    _write_stack(path, stack)


def pop_pending(base: str, session: str, tool: str,
                file_path: Optional[str],
                tool_use_id: Optional[str] = None) -> Optional[Dict]:
    """Pop the Pre record matching this Post, or None if there is no match.

    Correlation is by ``tool_use_id`` -- the per-invocation id that Claude Code
    puts on BOTH the Pre and the Post of one tool call. Exact-id matching is what
    makes parallel / interleaved tool calls correct: the old tool(+file_path)
    LIFO scan would, under interleaving, pop a DIFFERENT invocation's Pre and so
    pair a wrong 'before' with this 'after' (fabricated diffs), and an orphaned
    Bash Pre could be popped by a later single-file Post (fabricated deletions).

    A Post whose id has no pending Pre is a genuine orphan (e.g. the Pre hook
    never ran); we return None so the event degrades to 'before unknown' rather
    than stealing an unrelated Pre. Payloads without an id fall back to the
    original tool(+file_path) LIFO for backward compatibility.
    """
    path = pending_path(base, session)
    stack = _load_stack(path)
    if not stack:
        return None

    idx = None
    if tool_use_id:
        for j in range(len(stack) - 1, -1, -1):
            # Cross-validate the TOOL, not just the id: a same-id / different-tool
            # pairing (payload corruption, a reused/duplicated id, or a crafted
            # payload) would fabricate a confident wrong diff -- e.g. a Bash 'after'
            # against an Edit 'before'. Claude Code always puts the same id+tool on a
            # call's Pre and Post, so requiring both is exact, never lossy.
            if stack[j].get("id") == tool_use_id and stack[j].get("tool") == tool:
                idx = j
                break
    else:
        def matches(rec: Dict) -> bool:
            # An id-tracked Pre is claimable ONLY by its own id: an id-less Post must
            # never hijack it via the legacy LIFO scan (that would steal a different
            # in-flight invocation's 'before' and strand its real Post).
            if rec.get("id"):
                return False
            if rec.get("tool") != tool:
                return False
            if tool in SINGLE_FILE_TOOLS:
                return rec.get("file_path") == file_path
            return True

        # Bash (no file_path) matches purely on tool, so a LIFO scan with two open
        # Bash Pres would pop the NEWEST regardless of which command is posting,
        # pairing a wrong before-snapshot. For Bash prefer the OLDEST open Pre (FIFO)
        # -- a closer approximation to real completion order on the legacy no-id path.
        # Single-file tools keep LIFO (their file_path disambiguates exactly).
        if tool == "Bash" and file_path is None:
            for j in range(len(stack)):           # FIFO: oldest matching Bash first
                if matches(stack[j]):
                    idx = j
                    break
        else:
            for j in range(len(stack) - 1, -1, -1):  # LIFO scan
                if matches(stack[j]):
                    idx = j
                    break
    if idx is None:
        return None
    record = stack.pop(idx)
    _write_stack(path, stack)
    return record


# ---- event assembly ------------------------------------------------------

def session_file(base: str, session: str) -> str:
    return os.path.join(base, "sessions", _safe_session(session) + ".ndjson")


def _append_event(base: str, session: str, event: Dict) -> None:
    """Append one event as an NDJSON line, creating the session file 0600.

    0600 (not the umask-inherited 0644) honours the DESIGN store-permission
    invariant: the log can hold command strings / prompts and must not be
    world-readable.
    """
    # A non-UTF-8 filename (os.walk decodes it with surrogateescape) becomes a lone
    # surrogate in the event; json.dumps(ensure_ascii=False) keeps it, and encoding
    # that to UTF-8 raises -- which used to lose the ENTIRE event (all its changes),
    # not just the bad path. Probe the encode first and fall back to the ASCII-escaped
    # form (\uXXXX), which is pure ASCII -> always writable AND readable strict-UTF-8.
    try:
        line = json.dumps(event, ensure_ascii=False)
        line.encode("utf-8")
    except (UnicodeEncodeError, ValueError, TypeError):
        line = json.dumps(event, ensure_ascii=True)
    fd = os.open(session_file(base, session),
                 os.O_WRONLY | os.O_CREAT | os.O_APPEND | _SAFE_STORE_OPEN, 0o600)
    # Self-heal perms: O_CREAT's mode only applies on CREATE, so an existing log
    # loosened by a previous run / umask reset / mode-preserving copy would stay
    # world-readable. The log can hold command strings + prompts -> keep it 0600.
    with contextlib.suppress(OSError):
        os.fchmod(fd, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def read_session_events(base: str, session: str) -> List[Dict]:
    """All recorded events for a session (best-effort; skips malformed lines)."""
    path = session_file(base, session)
    out: List[Dict] = []
    if not os.path.exists(path):
        return out
    # errors="replace": a torn multibyte tail from a SIGKILL'd mid-append must skip
    # one line, not raise UnicodeDecodeError and permanently disable turn capture for
    # the session (the write path already ASCII-escapes; keep the read symmetric).
    try:
        with safe_store_read(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if isinstance(obj, dict):
                    out.append(obj)
    except OSError:                 # store node swapped (FIFO/symlink) -- degrade
        return out
    return out


def read_session_events_after(base: str, session: str, after_seq: int) -> List[Dict]:
    """Events with seq > after_seq, read from the file TAIL so a Bash Post's
    concurrency scan is O(window) instead of O(whole session) on every call.

    Reads a 64KiB tail; if that window reaches back to (after_seq) the result is
    complete (events are appended in ascending seq), otherwise it falls back to a
    full scan for correctness (rare: only with very large events in the window).
    """
    path = session_file(base, session)
    if not os.path.exists(path):
        return []
    try:
        with safe_store_read(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 65536))
            tail = fh.read()
    except OSError:                 # store node swapped (FIFO/symlink) -- degrade
        return []
    lines = tail.split(b"\n")
    if size > 65536:
        lines = lines[1:]                      # drop the leading partial line
    events, seqs = [], []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if not isinstance(ev, dict):
            continue
        s = ev.get("seq")
        if isinstance(s, int):
            seqs.append(s)
            if s > after_seq:
                events.append(ev)
    # The window is complete iff we read from the start, or it contains an event
    # at/below the boundary (so no overlap event lies before the window).
    reaches = size <= 65536 or (seqs and min(seqs) <= after_seq + 1)
    if reaches:
        return events
    return [e for e in read_session_events(base, session)
            if isinstance(e.get("seq"), int) and e["seq"] > after_seq]


def next_seq(base: str, session: str) -> int:
    """Next monotonic seq. Reads only the file's tail (last line) so it is O(1)
    per call instead of O(N) -- a long session otherwise made each Post O(N) and
    the whole session O(N^2)."""
    path = session_file(base, session)
    if not os.path.exists(path):
        return 1
    try:
        with safe_store_read(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            if size == 0:
                return 1
            fh.seek(max(0, size - 65536))
            tail = fh.read()
    except OSError:                 # store node swapped -- try the full scan below
        tail = b""
    for line in reversed(tail.split(b"\n")):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        seq = obj.get("seq") if isinstance(obj, dict) else None
        if isinstance(seq, int):
            return seq + 1
        # A type-corrupt / non-dict line: keep scanning back for a valid one
        # rather than abandoning to the fallback (`continue`, not `break`).
        continue
    # Fallback: the tail had no parseable integer seq (e.g. a single line longer
    # than the 64KiB window). Scan the whole file for the LAST valid seq -- using
    # the line COUNT would be wrong whenever seq diverges from the line number.
    last = 0
    try:
        with safe_store_read(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                seq = obj.get("seq") if isinstance(obj, dict) else None
                if isinstance(seq, int):
                    last = seq
    except OSError:                 # store node swapped (FIFO/symlink) -- degrade
        return last + 1
    return last + 1


def build_changes(before: Dict[str, Optional[Dict]],
                  after: Dict[str, Optional[Dict]],
                  had_before: bool,
                  named: Optional[str],
                  is_bash: bool = False,
                  concurrent: Optional[List[Dict]] = None,
                  read_only: bool = False) -> List[Dict]:
    """Diff two snapshot maps into per-path change records.

    `named` is the single display path a single-file tool targeted; it is always
    reported even if absent both sides (e.g. a Read of a secret that isn't there
    -- a notable access attempt). `had_before` False means there was no Pre, so
    we cannot claim 'added' vs 'modified': such files are reported 'present'.

    For a Bash event, `concurrent` is the set of OTHER tools whose Pre window was
    still open -- any change here may have been produced by one of them rather
    than by this command, so each Bash change is tagged with an `attribution`
    (exclusive / ambiguous / claimed_by_concurrent) for honest reporting.
    """
    concurrent = concurrent or []
    concurrent_paths = {c.get("file_path") for c in concurrent if c.get("file_path")}
    has_concurrent = bool(concurrent)
    changes = []
    paths = set(before) | set(after)
    if named:
        paths.add(named)
    for path in sorted(paths):
        b = before.get(path)
        a = after.get(path)
        b_exists = b is not None
        a_exists = a is not None
        b_sha = b.get("sha") if b else None
        a_sha = a.get("sha") if a else None
        b_large = bool(b and b.get("toolarge"))
        a_large = bool(a and a.get("toolarge"))
        b_unread = bool(b and b.get("unreadable"))
        a_unread = bool(a and a.get("unreadable"))
        # Content-unavailable: too-large or unreadable. Both carry sha=None, so a
        # real change would otherwise tie on sha and hide as 'read'.
        unavailable = b_large or a_large or b_unread or a_unread
        redacted = bool((b and b.get("redacted")) or (a and a.get("redacted")))
        b_nonreg = bool(b and b.get("kind") == "non-regular")
        a_nonreg = bool(a and a.get("kind") == "non-regular")

        def _meta(rec_, key):
            return rec_.get(key) if rec_ else None

        if not b_exists and not a_exists:
            if path != named:
                continue
            status = "missing"          # named secret/file not present
        elif b_exists and a_exists and b_nonreg != a_nonreg:
            status = "typechange"       # regular <-> non-regular (a file replaced by
                                        # a symlink, or a symlink made a real file)
        elif not had_before and a_exists:
            status = "present"          # before unknown; cannot call it added
        elif b_exists and a_exists and b_sha == a_sha:
            # Equal shas usually mean 'unchanged access'. For content-unavailable
            # files fall back to size/mtime/ctime (ctime catches a rewrite that
            # forged mtime) so a real change isn't silently reported as 'read'.
            # For two non-regular records (both sha=None), a symlink REPOINTED in
            # place keeps its kind but changes link_target/mtime/ctime -- compare
            # those so the retarget surfaces as 'modified', not a phantom 'read'.
            nonreg_changed = b_nonreg and a_nonreg and (
                _meta(b, "link_target") != _meta(a, "link_target")
                or _meta(b, "mtime") != _meta(a, "mtime")
                or _meta(b, "ctime") != _meta(a, "ctime"))
            # A pure permission change (chmod +x deploy.sh) leaves content -- and so
            # the sha -- identical, but IS a real, security-relevant modification that
            # git records. Surface it as 'modified' with a mode-change annotation.
            b_mode = _meta(b, "mode")
            a_mode = _meta(a, "mode")
            mode_changed = (b_mode is not None and a_mode is not None
                            and b_mode != a_mode)
            # Defense-in-depth tripwire: for a normal (regular, hashed) file an
            # equal digest but DIFFERENT size is impossible for an honest keyed
            # hash (content fixes both). If it happens, the digest was forged --
            # a tampered/extended salt trying to hide a real edit as a 'read'.
            # Treat any digest-equal-but-size-different regular file as modified,
            # never a silent read. (unavailable files carry sha=None and are
            # handled by the mtime/ctime branch below.)
            size_mismatch = (not b_nonreg and not a_nonreg and not unavailable
                             and _meta(b, "size") is not None
                             and _meta(a, "size") is not None
                             and _meta(b, "size") != _meta(a, "size"))
            if nonreg_changed:
                status = "modified"
            elif mode_changed:
                status = "modified"
            elif size_mismatch:
                status = "modified"
            elif unavailable and (
                    _meta(b, "size") != _meta(a, "size")
                    or _meta(b, "mtime") != _meta(a, "mtime")
                    or _meta(b, "ctime") != _meta(a, "ctime")):
                status = "modified"
            else:
                status = "read"         # observed but unchanged == an access
        elif not b_exists and a_exists:
            status = "added"
        elif b_exists and not a_exists:
            status = "deleted"
        else:
            status = "modified"

        # A READ-ONLY tool (Read) cannot author a change: a content difference between
        # its Pre and Post snapshots is an EXTERNAL/concurrent write, not the Read's
        # doing. Record it as a 'read' access with an external-change marker rather
        # than falsely attributing authorship (`read MODIFIED ...`).
        external_change = False
        if read_only and status in ("added", "modified", "deleted", "typechange"):
            external_change = True
            status = "read"

        # A symlink whose resolved target is sensitive (alias.txt -> .env) carries
        # target_sensitive from _nonregular_rec: OR it in so the aliased secret access
        # surfaces in the audit even though the link's own name isn't sensitive.
        target_sensitive = bool((b and b.get("target_sensitive"))
                                or (a and a.get("target_sensitive")))
        rec = {
            "path": path,
            "status": status,
            "before": b_sha,
            "after": a_sha,
            # `redacted` is ORed in so the field is consistent with the abspath-based
            # classification (a .ssh/config sensitive only by a segment above cwd is
            # redacted=True; is_sensitive(relative path) is False).
            "sensitive": is_sensitive(path) or target_sensitive or redacted,
            "redacted": redacted,
        }
        if external_change:
            rec["external_change"] = True
        # Annotate a mode transition (chmod) whenever both modes are known and
        # differ -- INDEPENDENT of whether content also changed. Gating this on
        # b_sha == a_sha dropped the permission change whenever a single tool call
        # both edited a file and chmod'd it (the reader then lost the mode story).
        if (_meta(b, "mode") is not None and _meta(a, "mode") is not None
                and _meta(b, "mode") != _meta(a, "mode")):
            rec["mode_change"] = [_meta(b, "mode"), _meta(a, "mode")]
        # Sizes are part of the change-detection story `alog diff` renders -- but
        # NOT for a sensitive file: the renderer suppresses everything beyond
        # status there, so a recorded size would be stored-but-never-shown data
        # that leaks a secret's byte length (a side channel on key type / token
        # shape). Gate on the FINAL `sensitive` flag, not `redacted`: an unreadable
        # or too-large sensitive file (whose content-less record carries no
        # `redacted`) is still sensitive by name/path and must not leak its size.
        if not rec["sensitive"]:
            rec["before_size"] = _meta(b, "size")
            rec["after_size"] = _meta(a, "size")
        if unavailable:
            # The renderer must print a notice instead of implying the digest
            # comparison covered content it never read.
            rec["content_unavailable"] = "large" if (b_large or a_large) else "unreadable"
            if b_large or a_large:
                rec["large"] = True
        if is_bash:
            if path in concurrent_paths:
                rec["attribution"] = "claimed_by_concurrent"
            elif has_concurrent:
                rec["attribution"] = "ambiguous"
            else:
                rec["attribution"] = "exclusive"
        changes.append(rec)
    return changes


def _snapshot(base: str, tool: str, tool_input: Dict, cwd: str, salt: bytes,
              session: str) -> Dict[str, Optional[Dict]]:
    """Bash snapshots the whole tree (manifest-cached); single-file tools snapshot
    just their named path (always fresh -- it is one file, so no cache needed)."""
    if tool == "Bash":
        return snapshot_tree(base, cwd, salt, session)
    return snapshot_set(files_of_interest(tool, tool_input, cwd), cwd, salt)


def _tree_skip_event(base: str, session: str, phase: str, tool: str,
                     tool_use_id: Optional[str],
                     exc: "TreeCeilingExceeded") -> Dict:
    """The distinct event line recording a SKIPPED whole-tree snapshot (issue #5):
    the audit trail must show the gap, never a silent all-clear."""
    return {
        "seq": next_seq(base, session),
        "session": session,
        "kind": "tree_snapshot_skipped",
        "ts": now_ts(base),
        "tool": tool,
        "tool_use_id": tool_use_id,
        "phase": phase,                      # "pre" | "post"
        "reason": exc.reason,                # "file_count" | "time_budget"
        "files_seen": exc.files_seen,
        "elapsed_seconds": round(exc.elapsed, 3),
        "max_files": tree_max_files(),
        "max_seconds": tree_max_seconds(),
    }


def handle_pre(base: str, payload: Dict, tool: str, cwd: str, salt: bytes,
               tool_use_id: Optional[str] = None) -> None:
    session = payload.get("session_id", "default")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):   # a truthy non-dict (list/str/int) would
        tool_input = {}                    # raise on .get() and silently drop the event
    fp = named_file_path(tool, tool_input, cwd)
    # Capture the seq boundary BEFORE the before-snapshot, not after acquiring the
    # lock: a concurrent tool that POSTs during the snapshot or while we block on the
    # lock would otherwise fall OUTSIDE the window (seq <= nseq) and also be gone from
    # pending, so its write -- absent from `before` but present in a later Bash's
    # `after` -- got a false 'exclusive'. Capturing early OVER-includes such events
    # (they land in the window -> honest 'ambiguous'), which is the safe direction.
    nseq_at_pre = next_seq(base, session) - 1
    # Snapshot OUTSIDE the lock (see handle_post): the whole-tree Bash walk is
    # O(tree) and must not hold the per-session lock while it runs.
    skip: Optional[TreeCeilingExceeded] = None
    try:
        before = _snapshot(base, tool, tool_input, cwd, salt, session)
    except TreeCeilingExceeded as exc:
        # Degrade LOUDLY (issue #5): skip the before-snapshot, record the gap as
        # its own event line, and mark the pending record so the Post treats the
        # before-state as unknown (never fabricating 'added' for the whole tree).
        before = {}
        skip = exc
        log_internal("tree snapshot skipped (pre, {0}): {1} files in {2:.3f}s "
                     "-- raise ALOG_MAX_TREE_FILES/ALOG_MAX_TREE_SECONDS or "
                     "scope ALOG_DATA".format(exc.reason, exc.files_seen,
                                              exc.elapsed))
    with session_lock(base, session):
        if skip is not None:
            _append_event(base, session, _tree_skip_event(
                base, session, "pre", tool, tool_use_id, skip))
        record = {
            "id": tool_use_id,
            "tool": tool,
            "file_path": rel_to_cwd(cwd, fp) if fp else None,
            "ts": now_ts(base),
            # Number of events already written when this Pre fired (captured before
            # the snapshot). A later Bash uses it to find tools that POSTED in its
            # window.
            "nseq_at_pre": nseq_at_pre,
            "before": before,
        }
        if skip is not None:
            record["before_skipped"] = True
        push_pending(base, session, record)


def handle_post(base: str, payload: Dict, tool: str, cwd: str, salt: bytes,
                tool_use_id: Optional[str] = None, failed: bool = False) -> None:
    session = payload.get("session_id", "default")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):   # a truthy non-dict (list/str/int) would
        tool_input = {}                    # raise on .get() and silently drop the event
    fp = named_file_path(tool, tool_input, cwd)
    named = rel_to_cwd(cwd, fp) if fp else None

    command = tool_input.get("command") if tool == "Bash" else None
    if not isinstance(command, str):
        command = None
    cmd_sensitive = scan_cmd_for_secrets(command, cwd) if command else []

    # Snapshot OUTSIDE the lock: the whole-tree Bash walk is O(tree) and used to
    # hold the per-session lock, serializing every other concurrent tool hook in the
    # session. The lock now guards only the fast pending/seq/log mutations below; the
    # manifest cache uses atomic os.replace, so concurrent snapshots are safe (a lost
    # cache write just forces a re-read, never a wrong result).
    after_skip: Optional[TreeCeilingExceeded] = None
    try:
        after = _snapshot(base, tool, tool_input, cwd, salt, session)
    except TreeCeilingExceeded as exc:
        # Degrade LOUDLY (issue #5): the after-state is unknown, so no tree diff
        # can be built -- the tool event is still written (command string, secret
        # scan) with empty changes and an explicit skip marker, plus a distinct
        # ``tree_snapshot_skipped`` event line for the audit trail.
        after = {}
        after_skip = exc
        log_internal("tree snapshot skipped (post, {0}): {1} files in {2:.3f}s "
                     "-- raise ALOG_MAX_TREE_FILES/ALOG_MAX_TREE_SECONDS or "
                     "scope ALOG_DATA".format(exc.reason, exc.files_seen,
                                              exc.elapsed))
    with session_lock(base, session):
        pending = pop_pending(base, session, tool, named, tool_use_id)
        before = pending.get("before", {}) if pending else {}
        ts_pre = pending.get("ts") if pending else None
        matched_pre_id = pending.get("id") if pending else None
        # A Pre whose tree snapshot was skipped pushed an EMPTY before with a
        # marker: the before-state is unknown, so the diff must run in the
        # had_before=False mode ('present', never a fabricated 'added').
        before_skipped = bool(pending and pending.get("before_skipped"))
        had_before = pending is not None and not before_skipped
        # A Bash command snapshots the whole tree; a change it observed may have
        # been produced by a CONCURRENT tool, not the command. Two overlap classes:
        #   (1) other tools whose Pre is still open (this Bash's own Pre was just
        #       popped above, so list_pending holds only OTHERS -- no id filter
        #       needed, which also fixes the id==None false-exclude bug).
        #   (2) single-file tools that POSTED *after* this Bash's Pre fired, i.e.
        #       finished inside the window. Detected via event seq (monotonic,
        #       frozen-clock safe) so a fast Edit that completes before the Bash
        #       Post is no longer misattributed to the command.
        concurrent: List[Dict] = []
        if tool == "Bash":
            for r in list_pending(base, session):
                # A still-open Pre is UNCONFIRMED -- the tool has not posted, so it may
                # never author anything (a user-rejected/aborted Edit leaves an orphan
                # Pre that lingers for hours). It must NOT CLAIM its file_path: doing so
                # stamped a later genuine Bash write to that path 'claimed_by_concurrent'
                # and the audit then dropped the real secret write entirely. An open Pre
                # only makes this command's attribution 'ambiguous' (file_path=None);
                # authorship is confirmed solely by POSTED events (the posted-overlap
                # branch below). Read-only Pres don't even warrant ambiguity.
                if r.get("tool") in READ_ONLY_TOOLS:
                    continue
                concurrent.append({"id": r.get("id"), "tool": r.get("tool"),
                                   "file_path": None, "via": "open-pre"})
            pre_count = pending.get("nseq_at_pre") if pending else None
            if isinstance(pre_count, int):
                # Only the events that POSTED after this Bash's Pre (seq>pre_count)
                # can overlap -- read just that tail, not the whole session.
                for ev in read_session_events_after(base, session, pre_count):
                    ev_tool = ev.get("tool")
                    # WRITE_TOOLS excludes Read: a concurrent Read of the same path
                    # is read-only, so a Bash write to it stays this command's (never
                    # claimed_by_concurrent). Only change-authoring tools can claim --
                    # and only if the Write actually AUTHORED that path. A no-op Write
                    # (wrote identical bytes -> its own change status is 'read') must
                    # NOT claim, else it disowns THIS command's real write to the path.
                    if ev_tool in WRITE_TOOLS and ev.get("file_path"):
                        wfp = ev.get("file_path")
                        # Claim the path ONLY if the Write both AUTHORED it (its own
                        # change status is added/modified/deleted -- a no-op 'read'
                        # write must not claim) AND its change is SENSITIVE/REDACTED.
                        # A BENIGN Write that claims a path can't be relied on to
                        # report a secret access: if this Bash wrote a secret to the
                        # same path, claiming would suppress it from the audit with
                        # nothing else reporting it (false all-clear). When the Write
                        # is benign, leave the overlap ambiguous instead.
                        # ...AND the Write's FINAL state for wfp equals THIS Bash's
                        # after-state (same after-sha). If they differ, the Bash wrote
                        # a DIFFERENT value than the Write (each authored a distinct
                        # state), so the Write's event does not report the Bash's write
                        # -- suppressing it would hide a real (possibly secret) change.
                        bash_after_sha = (after.get(wfp) or {}).get("sha") if after.get(wfp) else None
                        claim = any(
                            c.get("path") == wfp
                            and c.get("status") in (
                                "added", "modified", "deleted", "typechange")
                            and (c.get("redacted") or c.get("sensitive"))
                            and c.get("after") == bash_after_sha
                            for c in (ev.get("changes") or []) if isinstance(c, dict))
                        concurrent.append({"id": ev.get("tool_use_id"),
                                           "tool": ev_tool,
                                           "file_path": wfp if claim else None,
                                           "via": "posted-overlap"})
                    elif ev_tool == "Bash":
                        # A CONCURRENT Bash that finished inside our window. It ALSO
                        # snapshots the whole tree, so a 'modified'/'added'/'deleted'
                        # entry in ITS diff is NOT proof it authored that path -- the
                        # tree merely changed during its window, which may be THIS
                        # command's own write. So never CLAIM a specific path from a
                        # concurrent Bash (that would disown the real author): record
                        # the overlap with no path, which honestly downgrades all of
                        # THIS command's changes to 'ambiguous' rather than a false
                        # 'exclusive'. (A single-file WRITE tool, by contrast, has a
                        # definite target, so it still claims its path above.)
                        concurrent.append({"id": ev.get("tool_use_id"),
                                           "tool": "Bash", "file_path": None,
                                           "via": "posted-bash-overlap"})
        if after_skip is not None:
            # After-state unknown: diffing a full 'before' against an empty
            # 'after' would fabricate a whole-tree 'deleted'. Record no changes;
            # the skip marker below says WHY they are absent.
            changes: List[Dict] = []
            _append_event(base, session, _tree_skip_event(
                base, session, "post", tool, tool_use_id, after_skip))
        else:
            changes = build_changes(before, after, had_before, named,
                                    tool == "Bash", concurrent,
                                    read_only=tool in READ_ONLY_TOOLS)

        event = {
            "seq": next_seq(base, session),
            "session": session,
            "tool": tool,
            "tool_use_id": tool_use_id,
            "matched_pre_id": matched_pre_id,
            "ts_pre": ts_pre,
            "ts": now_ts(base),
            "had_before": had_before,
            "outcome": "failure" if failed else "success",
            "cwd": cwd,
            "command": redact_command(command) if command else None,
            "file_path": named,
            "changes": changes,
            "cmd_sensitive": cmd_sensitive,
            "concurrent": concurrent,
        }
        if after_skip is not None:
            event["snapshot_skipped"] = after_skip.reason
        if before_skipped:
            event["before_snapshot_skipped"] = True
        _append_event(base, session, event)


# ---- prompt / token capture (non-tool events) ----------------------------

def _tok_int(usage: Dict, key: str) -> int:
    """A usage field as a non-negative int, tolerant of junk in the transcript.

    Rejects: bool ('true' is not 1 token -- bool is an int subclass), NaN/Infinity
    (json.loads accepts these by default, and 1e400 overflows to inf; int(nan)
    raises ValueError, int(inf) raises OverflowError), and non-numeric values.
    """
    v = usage.get(key)
    if isinstance(v, bool):
        return 0
    if isinstance(v, int):
        return max(0, v)       # clamp: a negative token count would invert the
    if isinstance(v, float) and math.isfinite(v):   # session's cost total
        return max(0, int(v))
    return 0


def parse_transcript_turns(path: str, start_offset: int = 0) -> Tuple[List[Dict], int]:
    """One usage record per DISTINCT assistant message.id in a Claude Code
    transcript (JSONL), reading only the bytes at/after ``start_offset``.

    A single assistant message is written to the transcript once PER content
    block (thinking / text / tool_use), and every one of those lines repeats the
    SAME ``usage`` object -- so summing lines would multiply a turn's tokens by
    its block count (observed: 44 lines -> 19 ids on a real session). We dedupe
    by ``message.id`` (first occurrence wins).

    Returns ``(turns, new_offset)`` where ``new_offset`` is the byte position
    after the last COMPLETE line consumed; a trailing partial line (a torn write
    while another process is mid-flush) is left unconsumed so it is re-read next
    call. Passing ``new_offset`` back on the next Stop means a growing transcript
    is read once, not O(N) per Stop.

    Never raises (honours the hook's "never break the agent" contract): the file
    is read as BYTES and decoded per-line inside ``json.loads``, so a truncated
    multi-byte char at EOF is a caught ``ValueError`` (``UnicodeDecodeError``
    subclass), not an escaping exception; a missing file yields ``([], offset)``.
    """
    turns: Dict[str, Dict] = {}
    order: List[str] = []
    # Open O_NONBLOCK|O_NOFOLLOW and re-check S_ISREG AFTER the open, not before: the
    # handle_stop lstat guard is a check-then-open TOCTOU -- if the path is swapped to
    # a FIFO in that window, a plain blocking open() would park forever. O_NONBLOCK
    # returns immediately even for a writer-less FIFO; the fstat then rejects it.
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
                     | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return [], start_offset
    try:
        with os.fdopen(fd, "rb") as fh:
            st = os.fstat(fh.fileno())
            if not stat.S_ISREG(st.st_mode):
                return [], start_offset
            # Clamp the cursor to the current size: if the transcript was truncated or
            # rotated shorter than the saved offset, seeking past EOF would read b""
            # forever and freeze the cursor high, silently under-counting turns. Reset
            # to 0 on a shrink (the recorded_turn_ids gate prevents double-counting).
            size = st.st_size
            start = start_offset if 0 < start_offset <= size else 0
            fh.seek(start)
            # BOUNDED read: never slurp a whole huge/swapped transcript into memory
            # (a 10GB file would MemoryError -> caught fail-open, but risks an OS OOM
            # SIGKILL that breaks the agent). Read a chunk; the cursor advances by the
            # complete lines consumed, so the remainder is picked up on the next Stop.
            data = fh.read(MAX_TRANSCRIPT_READ)
    except OSError:
        return [], start_offset
    # The element after the final b"\n" is a trailing PARTIAL line (no terminator
    # yet); drop it and do NOT advance the offset past it, so a mid-flush final
    # line is re-read next time rather than parsed half-written.
    parts = data.split(b"\n")
    consumed = 0
    for raw in parts[:-1]:
        consumed += len(raw) + 1          # +1 for the split-off b"\n"
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)        # bytes ok; UnicodeDecodeError is a ValueError
        except ValueError:
            continue
        if not isinstance(obj, dict) or obj.get("type") != "assistant":
            continue
        msg = obj.get("message")
        if not isinstance(msg, dict):
            continue
        mid = msg.get("id")
        if not isinstance(mid, str) or not mid or mid in turns:
            continue
        usage = msg.get("usage")
        if not isinstance(usage, dict):
            usage = {}
        turns[mid] = {
            "message_id": mid,
            "model": msg.get("model") if isinstance(msg.get("model"), str) else None,
            "input_tokens": _tok_int(usage, "input_tokens"),
            "output_tokens": _tok_int(usage, "output_tokens"),
            "cache_creation_input_tokens": _tok_int(usage, "cache_creation_input_tokens"),
            "cache_read_input_tokens": _tok_int(usage, "cache_read_input_tokens"),
        }
        order.append(mid)
    # A single line longer than the read cap would never yield a complete line
    # (consumed stays 0 while the window is full), stranding the cursor forever.
    # Skip past that pathological line so progress resumes on the next Stop.
    if consumed == 0 and len(data) >= MAX_TRANSCRIPT_READ:
        return [], start + MAX_TRANSCRIPT_READ
    return [turns[m] for m in order], start + consumed


def recorded_turn_ids(base: str, session: str) -> Set[str]:
    """message_ids already written as ``turn`` events for this session -- the
    dedup GATE that keeps the log the single source of truth for what is recorded.

    The transcript read cursor (below) is only an I/O hint to avoid re-reading old
    bytes; this gate is what actually guarantees no double count, so a missing or
    stale cursor costs at most a re-read, never a duplicate. Reads the compact
    per-session metadata log (not the transcript)."""
    ids: Set[str] = set()
    for ev in read_session_events(base, session):
        if ev.get("kind") == "turn":
            mid = ev.get("message_id")
            if mid:
                ids.add(mid)
    return ids


def _cursor_path(base: str, session: str) -> str:
    return os.path.join(base, "cursors", _safe_session(session) + ".json")


def read_cursor(base: str, session: str, tpath: str) -> int:
    """Transcript byte offset already processed for this session (0 if none).

    The cursor is keyed by session_id, but the transcript FILE behind a session
    can change (e.g. a resumed session writing a new transcript path). The saved
    offset is only meaningful for the file it was taken from, so the cursor also
    records the transcript path and any mismatch resets to 0. A legacy cursor
    (offset only, no path -- written by older versions) resets the same way:
    re-reading is safe (recorded_turn_ids is the dedup gate), trusting a stale
    offset against a different file is not."""
    try:
        with safe_store_read(_cursor_path(base, session), "r", encoding="utf-8") as fh:
            obj = json.loads(fh.read() or "{}")
    except (OSError, ValueError):
        return 0
    if not isinstance(obj, dict) or obj.get("path") != tpath:
        return 0
    off = obj.get("offset")
    return off if isinstance(off, int) and off >= 0 else 0


def write_cursor(base: str, session: str, offset: int, tpath: str) -> None:
    """Persist the processed transcript offset + path (0600). Best-effort I/O hint."""
    fd = os.open(_cursor_path(base, session),
                 os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _SAFE_STORE_OPEN, 0o600)
    with contextlib.suppress(OSError):   # self-heal an existing cursor's perms
        os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"offset": int(offset), "path": tpath}))


def handle_user_prompt(base: str, payload: Dict) -> None:
    """Record the user's prompt (UserPromptSubmit) as a ``prompt`` event."""
    session = payload.get("session_id", "default")
    prompt = payload.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        return
    with session_lock(base, session):
        _append_event(base, session, {
            "seq": next_seq(base, session),
            "session": session,
            "kind": "prompt",
            "ts": now_ts(base),
            "prompt": redact_prompt(prompt),
            "chars": len(prompt),
        })


def handle_stop(base: str, payload: Dict) -> None:
    """Record per-turn token usage (Stop / SubagentStop) from the session
    transcript as ``turn`` events. Cost is NOT stored -- alog derives it from the
    raw token counts and its own price table, so re-pricing needs no re-capture."""
    session = payload.get("session_id", "default")
    tpath = payload.get("transcript_path")
    if not isinstance(tpath, str) or not tpath:
        return
    tpath = os.path.expanduser(tpath)
    # Require a REGULAR file: a symlink is refused (mirrors snapshot_file's discipline)
    # AND a FIFO / char-device / socket is refused, because parse_transcript_turns does
    # a blocking open()+read() -- a FIFO with no writer (or /dev/zero) would hang the
    # Stop hook forever (it runs OUTSIDE the lock, so neither the fail-open try/except
    # nor the lock deadline bounds it), stalling the agent until the host kills it.
    try:
        if not stat.S_ISREG(os.lstat(tpath).st_mode):
            return
    except OSError:
        return
    # Read the cursor and PARSE the transcript OUTSIDE the per-session lock: the
    # parse reads and JSON-decodes the whole transcript tail and must not serialize
    # every other same-session hook behind it (mirrors the snapshot-outside-lock
    # discipline in handle_pre/handle_post). recorded_turn_ids (taken under the lock
    # below) is the real dedup GATE, so a concurrent Stop re-reading the same bytes
    # is harmless -- it just writes nothing.
    offset = read_cursor(base, session, tpath)
    turns, new_offset = parse_transcript_turns(tpath, offset)
    with session_lock(base, session):
        # recorded_turn_ids is the dedup GATE (log = source of truth); the cursor is
        # only the I/O hint. Advancing the cursor even when nothing new was recorded
        # skips already-read bytes next time; a write failure just leaves the old
        # cursor, and the gate prevents any double count on the re-read.
        seen = recorded_turn_ids(base, session)
        seq = next_seq(base, session)
        ts = now_ts(base)
        for t in turns:
            if t["message_id"] in seen:
                continue
            _append_event(base, session, {
                "seq": seq,
                "session": session,
                "kind": "turn",
                "ts": ts,
                "message_id": t["message_id"],
                "model": t["model"],
                "input_tokens": t["input_tokens"],
                "output_tokens": t["output_tokens"],
                "cache_creation_input_tokens": t["cache_creation_input_tokens"],
                "cache_read_input_tokens": t["cache_read_input_tokens"],
            })
            seq += 1
        write_cursor(base, session, new_offset, tpath)


def main() -> int:
    # Read raw bytes and decode locale-independently: sys.stdin.read() decodes
    # with the process locale, so under a non-UTF-8 locale (e.g. *.SJIS) an
    # ordinary non-ASCII UTF-8 payload raises UnicodeDecodeError and crashes the
    # hook on its first statement -- before the try/except below can fail open.
    try:
        # BOUNDED read: cap the payload so a huge (or maliciously large) stdin can't
        # OOM the hook before the fail-open guards run. A legitimate Write payload
        # carries the file's content; MAX_PAYLOAD_BYTES is generous for that. An
        # over-cap payload truncates -> json.loads fails -> return 0 (fail-open).
        raw = sys.stdin.buffer.read(MAX_PAYLOAD_BYTES + 1).decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001 -- audit must never break the agent
        return 0
    if len(raw) > MAX_PAYLOAD_BYTES:
        log_internal("payload exceeds {0} bytes; skipping".format(MAX_PAYLOAD_BYTES))
        return 0
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except Exception as exc:  # noqa: BLE001 -- not just ValueError: a deeply-nested
        # payload raises RecursionError and an oversized one MemoryError, neither a
        # ValueError; an unguarded raise here escapes the fail-open contract. Match
        # the decode guard above and the handler guards below (return 0, never raise).
        log_internal("bad payload json: {0}".format(exc))
        return 0
    if not isinstance(payload, dict):
        log_internal("payload not an object: {0}".format(type(payload).__name__))
        return 0

    event_name = payload.get("hook_event_name", "")
    if not isinstance(event_name, str):   # non-string (e.g. a list) is unhashable:
        event_name = ""                   # the `in NONTOOL_EVENTS` test would crash
    # os.path.abspath() calls os.getcwd() internally for a RELATIVE path, and
    # os.getcwd() raises FileNotFoundError if the hook process's own cwd was deleted.
    # Both the relative-cwd branch and the getcwd() fallback must be guarded, or an
    # unguarded raise here (this sits between the two protective try/except blocks)
    # escapes the fail-open contract and crashes the hook instead of returning 0.
    raw_cwd = payload.get("cwd")
    try:
        if isinstance(raw_cwd, str) and raw_cwd:
            cwd = os.path.abspath(raw_cwd)
        else:
            cwd = os.path.abspath(os.getcwd())
    except OSError:
        return 0

    # Non-tool events carry no tool_name: the user prompt and the end-of-turn
    # token/cost capture. They feed the same per-session NDJSON log but do not
    # snapshot files (so no salt is needed).
    if event_name in NONTOOL_EVENTS:
        try:
            base = data_dir(cwd)
            ensure_dirs(base)
            if event_name == "UserPromptSubmit":
                handle_user_prompt(base, payload)
            else:  # Stop / SubagentStop
                handle_stop(base, payload)
        except Exception as exc:  # noqa: BLE001 -- audit must never break the agent
            log_internal("swallowed error: {0!r}".format(exc))
        return 0

    tool = payload.get("tool_name", "")
    if not isinstance(tool, str):         # same: a non-string tool_name is
        tool = ""                         # unhashable and would crash the set test
    tool_use_id = payload.get("tool_use_id")
    if not isinstance(tool_use_id, str) or not tool_use_id:
        # Treat "" like a missing id: an empty id would match nothing yet is
        # truthy enough to skip the legacy path, stranding the Post.
        tool_use_id = None

    if tool not in SINGLE_FILE_TOOLS and tool != "Bash":
        return 0

    try:
        base = data_dir(cwd)
        ensure_dirs(base)
        salt = get_salt(base)
        if event_name == "PreToolUse":
            handle_pre(base, payload, tool, cwd, salt, tool_use_id)
        elif event_name in ("PostToolUse", "PostToolUseFailure"):
            # PostToolUseFailure fires when a tool FAILS (Bash non-zero, Write/Edit
            # error). Claude Code sends it INSTEAD of PostToolUse, so a hook that
            # dispatched only PostToolUse missed every failed call -- and a failed
            # command that partially wrote files left an orphan Pre and no event, so
            # its real changes were invisible. Snapshot the after-state either way;
            # tag the outcome so the reader can show that the tool failed.
            handle_post(base, payload, tool, cwd, salt, tool_use_id,
                        failed=(event_name == "PostToolUseFailure"))
        else:
            log_internal("ignored event {0}".format(event_name))
    except Exception as exc:  # noqa: BLE001 -- audit must never break the agent
        log_internal("swallowed error: {0!r}".format(exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
