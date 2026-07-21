#!/usr/bin/env bash
# Demo for agent-trail: the agent audit-log CLI (alog).
#
# Simulates a realistic Claude Code session by feeding synthesized Pre/PostToolUse
# hook payloads to hook.py around REAL filesystem operations -- exactly the way
# Claude Code fires the hook before and after each tool runs. Then it uses `alog`
# to reconstruct, fully offline, what the agent did.
#
# Built to exercise the cases that matter (NOT a happy path). A hard-won lesson:
# bugs hide in the edges, and a demo that skips them is rigged. So we include the
# edges that an adversarial review confirmed as real bugs and that are now fixed:
#   - opaque Bash command that names no file yet adds+deletes files
#   - opaque Bash command that modifies a tracked file via a script
#   - the agent READING .env (git can NEVER show this)
#   - a Bash command referencing a secret path (caught by command scan)
#   - a binary file / a filename with spaces + non-ASCII
#   - NO-BYTES-AT-REST: the store must NOT contain ANY file's bytes (v0.2+:
#     salted digests + metadata only; there is no object store at all)
#   - the store must carry its own .gitignore so it can't be committed
#   - an ORPHAN Bash Pre (denied tool, no Post) must NOT poison a later Post
#     into fabricating deletions of untouched files
#   - false-positive guards: token_bucket.py / backup.sshconfig are NOT secrets
#   - a Read of an ABSENT secret is recorded as a read-attempt
#
# This NEVER touches your real repo: all activity happens in $WORK (/tmp).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
HOOK="$HERE/hook.py"
ALOG="$HERE/alog.py"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/agent-trail-demo.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
export WORK
export ALOG_DATA="$WORK/.alog"
export ALOG_FROZEN_CLOCK=1700000000   # deterministic, reproducible output
SECRET='sk-demo-secret-DO-NOT-LEAK-9173'

emit_file () {  # event tool file_path
  python3 -c 'import json,sys,os; print(json.dumps({"session_id":"demo","hook_event_name":sys.argv[1],"tool_name":sys.argv[2],"cwd":os.environ["WORK"],"tool_input":{"file_path":sys.argv[3]}}))' "$1" "$2" "$3" | python3 "$HOOK"
}
emit_bash () {  # event command
  python3 -c 'import json,sys,os; print(json.dumps({"session_id":"demo","hook_event_name":sys.argv[1],"tool_name":"Bash","cwd":os.environ["WORK"],"tool_input":{"command":sys.argv[2]}}))' "$1" "$2" | python3 "$HOOK"
}
# Variants that pick a session AND carry a tool_use_id -- to exercise the
# id-based Pre/Post correlation and concurrent-window attribution (the parallel
# cases the strictly-sequential scenarios above cannot reach).
emitf () {  # session event tool file_path id
  python3 -c 'import json,sys,os; print(json.dumps({"session_id":sys.argv[1],"hook_event_name":sys.argv[2],"tool_name":sys.argv[3],"cwd":os.environ["WORK"],"tool_input":{"file_path":sys.argv[4]},"tool_use_id":sys.argv[5]}))' "$1" "$2" "$3" "$4" "$5" | python3 "$HOOK"
}
emitb () {  # session event command id
  python3 -c 'import json,sys,os; print(json.dumps({"session_id":sys.argv[1],"hook_event_name":sys.argv[2],"tool_name":"Bash","cwd":os.environ["WORK"],"tool_input":{"command":sys.argv[3]},"tool_use_id":sys.argv[4]}))' "$1" "$2" "$3" "$4" | python3 "$HOOK"
}
# Non-tool events: the user's prompt, and end-of-turn token/cost read from the
# session transcript (these have no tool_name).
emit_prompt () {  # session prompt
  python3 -c 'import json,sys,os; print(json.dumps({"session_id":sys.argv[1],"hook_event_name":"UserPromptSubmit","cwd":os.environ["WORK"],"prompt":sys.argv[2]}))' "$1" "$2" | python3 "$HOOK"
}
emit_stop () {  # session transcript_path
  python3 -c 'import json,sys,os; print(json.dumps({"session_id":sys.argv[1],"hook_event_name":"Stop","cwd":os.environ["WORK"],"transcript_path":sys.argv[2]}))' "$1" "$2" | python3 "$HOOK"
}

echo "=== throwaway repo: $WORK ==="
git -C "$WORK" init -q
git -C "$WORK" config user.email demo@local
git -C "$WORK" config user.name demo
mkdir -p "$WORK/src" "$WORK/config"

# Baseline committed state (BEFORE the agent session begins).
printf 'name: demo\nfeature_x: false\n'      > "$WORK/config/app.yaml"
printf 'API_TOKEN=%s\n' "$SECRET"            > "$WORK/.env"
printf 'temporary scratch data\n'            > "$WORK/src/old.tmp"
cat > "$WORK/gen.sh" <<'SH'
#!/bin/sh
mkdir -p generated
printf 'generated report\nbuild ok\n' > generated/report.txt
rm -f src/old.tmp
SH
cat > "$WORK/mutate.sh" <<'SH'
#!/bin/sh
python3 - <<'PY'
p = "src/app.py"
s = open(p).read().replace("foo", "bar")
open(p, "w").write(s)
PY
SH
git -C "$WORK" add -A
git -C "$WORK" commit -q -m "baseline"

# ---- the simulated agent session -----------------------------------------

# S1: Write a brand-new file (added).
emit_file PreToolUse Write src/app.py
printf "value = 'foo'\nprint(value)\n" > "$WORK/src/app.py"
emit_file PostToolUse Write src/app.py

# S2: Edit an existing tracked file (modified).
emit_file PreToolUse Edit config/app.yaml
printf 'name: demo\nfeature_x: true\n' > "$WORK/config/app.yaml"
emit_file PostToolUse Edit config/app.yaml

# S3: Bash command whose string names NO file, yet adds + deletes files.
emit_bash PreToolUse "sh ./gen.sh"
( cd "$WORK" && sh ./gen.sh )
emit_bash PostToolUse "sh ./gen.sh"

# S4: Bash command that modifies a tracked file via a script.
emit_bash PreToolUse "sh ./mutate.sh"
( cd "$WORK" && sh ./mutate.sh )
emit_bash PostToolUse "sh ./mutate.sh"

# S5: the agent READS .env via the Read tool (no change on disk).
emit_file PreToolUse Read .env
emit_file PostToolUse Read .env

# S6: Bash command referencing a secret OUTSIDE cwd (caught by command scan).
emit_bash PreToolUse "cat ~/.ssh/id_rsa | head -1"
emit_bash PostToolUse "cat ~/.ssh/id_rsa | head -1"

# S6b: Bash command naming an in-cwd secret by a non-obvious extension.
emit_bash PreToolUse "grep API config/service.env"
emit_bash PostToolUse "grep API config/service.env"

# S7: Write a binary file (diff must say "binary", not spew bytes).
emit_file PreToolUse Write assets/logo.png
mkdir -p "$WORK/assets"
printf '\x89PNG\r\n\x1a\n\x00\x00binary\x00data' > "$WORK/assets/logo.png"
emit_file PostToolUse Write assets/logo.png

# S8: Write a file whose name has a space and non-ASCII chars.
WEIRD='src/with space 日本語.txt'
emit_file PreToolUse Write "$WEIRD"
printf 'unicode + space survives\n' > "$WORK/$WEIRD"
emit_file PostToolUse Write "$WEIRD"

# S9: FALSE-POSITIVE GUARDS -- these names must NOT be classified as secrets.
emit_file PreToolUse Write src/token_bucket.py
printf 'class TokenBucket: pass\n' > "$WORK/src/token_bucket.py"
emit_file PostToolUse Write src/token_bucket.py
emit_file PreToolUse Write config/backup.sshconfig
printf 'Host demo\n' > "$WORK/config/backup.sshconfig"
emit_file PostToolUse Write config/backup.sshconfig

# S10: a Read of an ABSENT secret -> recorded as a read-attempt.
emit_file PreToolUse Read .env.production
emit_file PostToolUse Read .env.production

# S11: ORPHAN Bash Pre (a denied tool fires Pre but never Post), followed by an
# Edit Post that has NO matching Edit Pre. The fixed pop_pending must NOT pop the
# orphan Bash whole-tree snapshot and fabricate deletions of untouched files.
emit_bash PreToolUse "git clean -fdx"     # denied -> snapshots whole tree, no Post
printf "value = 'bar'\nprint(value)\n# touched\n" > "$WORK/src/app.py"
emit_file PostToolUse Edit src/app.py     # no preceding Edit Pre this turn

# ---- fixed-behavior regression scenarios (separate session 'fix') ---------
# Each carries a tool_use_id; kept in its own session so the legacy assertions
# above stay isolated. These cover the parallel/secret bugs an adversarial
# review found (fabricated diffs, cross-attribution, secret-at-rest recall gaps).

# F1: interleaved Edits to the SAME file. Correlated by tool_use_id, each Post
# must keep ITS OWN Pre's 'before' (eA->v0, eB->v1): NO before-swap.
printf 'v0\n' > "$WORK/src/inter.py"
emitf fix PreToolUse  Edit src/inter.py eA
printf 'v1\n' > "$WORK/src/inter.py"
emitf fix PreToolUse  Edit src/inter.py eB
printf 'v2\n' > "$WORK/src/inter.py"
emitf fix PostToolUse Edit src/inter.py eA
emitf fix PostToolUse Edit src/inter.py eB

# F2: a Bash command whose window overlaps a parallel Write. The Write owns
# injected.py; the Bash event must FLAG it (claimed_by_concurrent) not silently
# claim it, and mark its own out.txt 'ambiguous'.
emitb fix PreToolUse  "echo hi > out.txt" bX
emitf fix PreToolUse  Write src/injected.py wY
printf 'leaked = True\n' > "$WORK/src/injected.py"
( cd "$WORK" && echo hi > out.txt )
emitb fix PostToolUse "echo hi > out.txt" bX
emitf fix PostToolUse Write src/injected.py wY

# F3: a secret modified by a parallel Edit during a Bash window must NOT be
# reported in audit as the Bash command's doing.
printf 'TOKEN=old\n' > "$WORK/config/secrets.env"
emitb fix PreToolUse  "echo done" bZ
emitf fix PreToolUse  Edit config/secrets.env eV
printf 'TOKEN=rotatedsecret999\n' > "$WORK/config/secrets.env"
emitb fix PostToolUse "echo done" bZ
emitf fix PostToolUse Edit config/secrets.env eV

# F4: secret-RECALL by name (.dev.vars / *.tfvars) plus a private key under an
# innocent name -- NO file's bytes ever land in the store (digests only).
# (Write fires Pre -> the bytes hit disk -> Post, so these are 'added'.)
emitf fix PreToolUse  Write .dev.vars d1
printf 'API_TOKEN = topsecret_devvars_7777\n' > "$WORK/.dev.vars"
emitf fix PostToolUse Write .dev.vars d1
emitf fix PreToolUse  Write prod.tfvars t1
printf 'db_password = "tfvars_secret_8888"\n' > "$WORK/prod.tfvars"
emitf fix PostToolUse Write prod.tfvars t1
emitf fix PreToolUse  Write src/notes.txt n1
printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nbody_keysecret_9999\n-----END OPENSSH PRIVATE KEY-----\n' > "$WORK/src/notes.txt"
emitf fix PostToolUse Write src/notes.txt n1

# F5: FALSE-POSITIVE allowlist. A clean .env.example and a .pub public key must
# NOT be flagged sensitive; their change is still recorded (digest + metadata).
emitf fix PreToolUse  Write .env.example x1
printf '# copy to .env and fill in your real values\n' > "$WORK/.env.example"
emitf fix PostToolUse Write .env.example x1
emitf fix PreToolUse  Write id_ed25519.pub p2
printf 'ssh-ed25519 AAAApublickeydata comment\n' > "$WORK/id_ed25519.pub"
emitf fix PostToolUse Write id_ed25519.pub p2

# F6: compound env-var secrets in a stored Bash command string must be masked.
CMD6="deploy && export DB_PASSWORD=prodpw_secret_4444 AWS_SECRET_ACCESS_KEY=akkey_secret_5555"
emitb fix PreToolUse  "$CMD6" r1
emitb fix PostToolUse "$CMD6" r1

# F7: a change to a >10MB file must be 'modified', not silently 'read'.
python3 -c "open('$WORK/big.bin','wb').truncate(11*1024*1024)"
emitb fix PreToolUse  "truncate big.bin" g1
python3 -c "open('$WORK/big.bin','r+b').truncate(12*1024*1024)"
emitb fix PostToolUse "truncate big.bin" g1

# ---- second-round regressions for the bug-hunt fixes (session 'fix2') ------
mkdir -p "$WORK/docs" "$WORK/deploy"

# G1: MC-1 -- a fast Edit that POSTS BEFORE a slow Bash's Post. The Bash must NOT
# be blamed for the secret (the old fix only handled the Bash-posts-first order).
printf 'TOKEN=old\n' > "$WORK/config/g.env"
emitb fix2 PreToolUse  "echo go" gbash
emitf fix2 PreToolUse  Edit config/g.env gedit
printf 'TOKEN=rotated_g_secret\n' > "$WORK/config/g.env"
emitf fix2 PostToolUse Edit config/g.env gedit     # Edit posts FIRST
( cd "$WORK" && echo go > /dev/null )
emitb fix2 PostToolUse "echo go" gbash             # Bash posts AFTER -> overlap by seq

# G2: sc-1/REG-1 -- a doc that merely NAMES AWS_SECRET_ACCESS_KEY (no value) must
# keep its content stored (the bare-substring sniff used to withhold it).
emitf fix2 PreToolUse  Write docs/aws-setup.md awsdoc
printf 'Set AWS_SECRET_ACCESS_KEY in CI before deploy.\n' > "$WORK/docs/aws-setup.md"
emitf fix2 PostToolUse Write docs/aws-setup.md awsdoc

# G3: a credential value left in a template can never leak at rest -- no file
# content is stored for ANY file (structural guarantee, v0.2+).
emitf fix2 PreToolUse  Write deploy/.env.sample samp
printf 'AWS_SECRET_ACCESS_KEY=EXAMPLEPLACEHOLDER0000000000\n' > "$WORK/deploy/.env.sample"
emitf fix2 PostToolUse Write deploy/.env.sample samp

# G4: alog-1/F2 -- an after-snapshot that is UNREADABLE must show a notice, not a
# fabricated full deletion of the before content.
printf 'line1\nline2\n' > "$WORK/src/perm.txt"
emitf fix2 PreToolUse  Edit src/perm.txt gperm
printf 'line1\nline2\nline3\n' > "$WORK/src/perm.txt"
chmod 000 "$WORK/src/perm.txt"
emitf fix2 PostToolUse Edit src/perm.txt gperm
chmod 644 "$WORK/src/perm.txt"

# G6: alog-2 -- a Bash that BOTH names and writes a secret must be counted once.
emitb fix2 PreToolUse  "echo x > c.env" gdbl
( cd "$WORK" && echo x > c.env )
emitb fix2 PostToolUse "echo x > c.env" gdbl

# H1: cas-4 -- the manifest-cached tree snapshot must NOT invent changes on a
# warm (no-op) Bash. Two Bash commands that touch nothing -> zero file changes.
emitb warm PreToolUse  "echo noop"       hwarm1
( cd "$WORK" && echo noop > /dev/null )
emitb warm PostToolUse "echo noop"       hwarm1
emitb warm PreToolUse  "echo noop again" hwarm2
( cd "$WORK" && echo noop again > /dev/null )
emitb warm PostToolUse "echo noop again" hwarm2

# P1: concurrency -- 20 PARALLEL single-file events on one session must yield 20
# NDJSON lines with unique seqs (flock serialization). Backs the DESIGN claim and
# catches a flock regression (making the lock a no-op corrupts seq under load).
for i in $(seq 1 20); do
  ( emitf conc PreToolUse Write "src/p$i.txt" "c$i"
    printf 'x\n' > "$WORK/src/p$i.txt"
    emitf conc PostToolUse Write "src/p$i.txt" "c$i" ) &
done
wait

# ---- Q: prompt capture + token/cost capture (the MVP: what git NEVER sees) --
# The user's PROMPT (with an inline secret to prove redaction) and per-turn TOKEN
# usage, read from the session transcript. A single assistant message.id repeats
# once per content block with identical usage, so the parser MUST dedupe by id or
# the turn's tokens get multiplied by its block count.
emit_prompt obs "please deploy using API_KEY=$SECRET and summarize the result"
# R4-1: a PEM private key pasted into a prompt must NOT sit in the store cleartext
# (the file path already guards this; the prompt path must too).
PEMKEY=$'-----BEGIN RSA PRIVATE KEY-----\nKEYBODY_demo_secret_pem_4242\n-----END RSA PRIVATE KEY-----'
emit_prompt obs "here is my key, please debug it: $PEMKEY"
TRANSCRIPT="$WORK/obs-transcript.jsonl"
python3 - "$TRANSCRIPT" <<'PY'
import json, sys
rows = []
# msg_1: opus turn written as THREE lines (thinking + 2 tool_use), same usage.
u1 = {"input_tokens": 4, "output_tokens": 500,
      "cache_creation_input_tokens": 40000, "cache_read_input_tokens": 20000}
for blk in ("thinking", "tool_use", "tool_use"):
    rows.append({"type": "assistant",
                 "message": {"id": "msg_1", "model": "claude-opus-4-8",
                             "usage": u1, "content": [{"type": blk}]}})
# msg_2: a cheaper haiku follow-up turn.
rows.append({"type": "assistant",
             "message": {"id": "msg_2", "model": "claude-haiku-4-5-20251001",
                         "usage": {"input_tokens": 800, "output_tokens": 120,
                                   "cache_read_input_tokens": 2000}}})
# a plain user line must be ignored by the token parser.
rows.append({"type": "user", "message": {"role": "user", "content": "thanks"}})
with open(sys.argv[1], "w") as fh:
    for r in rows:
        fh.write(json.dumps(r) + "\n")
PY
emit_stop obs "$TRANSCRIPT"
emit_stop obs "$TRANSCRIPT"   # idempotent: a 2nd Stop over the same transcript

OBS="$WORK/obs.txt"; OBSCOST="$WORK/obscost.txt"
python3 "$ALOG" --session obs show > "$OBS"
python3 "$ALOG" --session obs cost > "$OBSCOST"
echo
echo "=== alog show (obs: prompt + token turns) ==="
cat "$OBS"
echo
echo "=== alog cost (obs) ==="
cat "$OBSCOST"

# Q-checks emitted as tokens for the assertion block below.
python3 - > "$WORK/checkq.txt" <<PY
import importlib.util as U
def load(n):
    s = U.spec_from_file_location(n, "$HERE/" + n + ".py"); m = U.module_from_spec(s); s.loader.exec_module(m); return m
alog = load("alog")
evs = alog.load_events("$ALOG_DATA", "obs")
turns = [e for e in evs if e.get("kind") == "turn"]
prompts = [e for e in evs if e.get("kind") == "prompt"]
# dedupe: msg_1 must appear exactly once despite 3 transcript lines.
m1 = [t for t in turns if t["message_id"] == "msg_1"]
print("Q_dedupe_OK" if len(m1) == 1 and m1[0]["output_tokens"] == 500 else "Q_dedupe_FAIL")
# idempotent: two Stops -> still exactly 2 turns (msg_1, msg_2).
print("Q_idempotent_OK" if len(turns) == 2 else "Q_idempotent_FAIL n=%d" % len(turns))
# redaction: the prompt secret must NOT be stored anywhere in the session log.
raw = open(alog.sessions_dir("$ALOG_DATA") + "/obs.ndjson").read()
print("Q_prompt_redacted_OK" if "$SECRET" not in raw and prompts and "<redacted>" in prompts[0]["prompt"] else "Q_prompt_redacted_FAIL")
# R4-1: a pasted PEM private-key body must never sit in the store cleartext.
print("Q_pem_redacted_OK" if "KEYBODY_demo_secret_pem_4242" not in raw else "Q_pem_redacted_FAIL")
# cost derivation: opus turn cost > haiku turn cost, and total is positive.
c_opus = alog.turn_cost(m1[0]); c_hai = alog.turn_cost([t for t in turns if t["message_id"] == "msg_2"][0])
print("Q_cost_OK" if c_opus and c_hai and c_opus > c_hai else "Q_cost_FAIL")
PY

# ---- inspect with alog (legacy scenarios: scope to the 'demo' session) -----
SHOW="$WORK/show.txt"; DIFF="$WORK/diff.txt"; AUDIT="$WORK/audit.txt"
python3 "$ALOG" --session demo show          > "$SHOW"
python3 "$ALOG" --session demo diff          > "$DIFF"
python3 "$ALOG" --session demo audit --time  > "$AUDIT"

echo
echo "=== alog show ==="
cat "$SHOW"
echo
echo "=== alog diff (excerpt: src/app.py) ==="
python3 "$ALOG" --session demo diff "src/app.py"
echo
echo "=== alog audit ==="
cat "$AUDIT"

echo
echo "=== what plain git shows about the .env READ ==="
if [ -z "$(git -C "$WORK" diff -- .env)" ]; then
  echo "  git diff -- .env : <empty>  (git cannot see that the agent read it)"
else
  echo "  FAIL: unexpected git change to .env"; exit 1
fi

# ---- assertions -----------------------------------------------------------
echo
echo "=== assertions ==="
fail=0
assert () { if grep -qF -- "$3" "$2"; then echo "  OK: $1"; else echo "  FAIL: $1 (missing: $3)"; fail=1; fi; }
refute () { if grep -qF -- "$3" "$2"; then echo "  FAIL: $1 (should be absent: $3)"; fail=1; else echo "  OK: $1"; fi; }

# core change detection
assert "S1 new file shown as added"              "$SHOW"  "A src/app.py"
assert "S2 edit shown as modified"               "$SHOW"  "M config/app.yaml"
assert "S3 opaque cmd: added file detected"      "$SHOW"  "A generated/report.txt"
assert "S3 opaque cmd: deletion detected"        "$SHOW"  "D src/old.tmp"
assert "S4 diff detects the script's change"     "$DIFF"  "modified: src/app.py"
assert "S4 diff shows the size delta"            "$DIFF"  "bytes"
refute "S4 diff never dumps content (-)"         "$DIFF"  "-value = 'foo'"
refute "S4 diff never dumps content (+)"         "$DIFF"  "+value = 'bar'"
assert "diff points at git for content"          "$DIFF"  "content is never stored"
assert "binary file added, no bytes dumped"      "$DIFF"  "created: assets/logo.png"
assert "unicode+space filename intact"           "$SHOW"  "日本語"

# sensitive detection -- the git-can't-do-this view
assert "S5 .env read surfaced"                   "$SHOW"  "R .env"
assert "audit reports .env READ"                 "$AUDIT" "READ .env"
assert "S6 ssh key command ref"                  "$AUDIT" "id_rsa"
assert "S6b in-cwd .env command ref"             "$AUDIT" "config/service.env"
assert "S10 absent-secret read-attempt logged"   "$AUDIT" ".env.production"
# the hook hashes .env during S3/S4 Bash tree scans; must NOT be a false read
refute "no false 'secret read' from Bash scan"   "$AUDIT" "bash READ .env"
# false-positive guards: ordinary names must never be classified as secrets
refute "token_bucket.py is NOT a secret"         "$AUDIT" "token_bucket"
refute "backup.sshconfig is NOT a secret"        "$AUDIT" "sshconfig"

# no-bytes-at-rest: the WHOLE store must not persist the secret's bytes (v0.2+
# there is no object store at all -- scan every file under the store).
echo "  -- scanning the whole store for the cleartext secret --"
if grep -rqF -- "$SECRET" "$ALOG_DATA" 2>/dev/null; then
  echo "  FAIL: cleartext secret found in the audit store"; fail=1
else
  echo "  OK: secret bytes are NOT stored anywhere (digest-only)"
fi
if [ -d "$ALOG_DATA/objects" ]; then
  echo "  FAIL: an objects/ dir was created (the CAS must be gone)"; fail=1
else
  echo "  OK: no objects/ dir exists (no content storage tier)"
fi
assert ".alog ships its own .gitignore"          "$ALOG_DATA/.gitignore" "*"

# orphan-Pre poisoning: the denied Bash Pre must not fabricate deletions
refute "orphan Bash Pre did NOT fake-delete config" "$SHOW" "D config/app.yaml"
refute "orphan Bash Pre did NOT fake-delete gen.sh"  "$SHOW" "D gen.sh"
assert "orphan-paired Edit degrades to 'unknown'"    "$SHOW" "before-state unknown"

# ---- fixed-behavior assertions (session 'fix') ----------------------------
echo
echo "=== fixed-behavior assertions (the parallel/secret fixes) ==="
SHOWF="$WORK/showf.txt"; DIFFF="$WORK/difff.txt"; AUDITF="$WORK/auditf.txt"
NDJF="$ALOG_DATA/sessions/fix.ndjson"
python3 "$ALOG" --session fix show  > "$SHOWF"
python3 "$ALOG" --session fix diff  > "$DIFFF"
python3 "$ALOG" --session fix audit > "$AUDITF"

# F1/F2: structural checks straight off the NDJSON event log.
python3 - "$NDJF" "$HERE/hook.py" "$ALOG_DATA" > "$WORK/checkf.txt" <<'PY'
import json, sys, importlib.util
spec = importlib.util.spec_from_file_location("hook", sys.argv[2])
h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
salt = h.get_salt(sys.argv[3])
sha = lambda b: h.salted_digest(salt, b)          # all digests are salted (v0.2+)
ev = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
def chg(e, p): return next((c for c in e.get("changes", []) if c.get("path") == p), None)
def by_tuid(i): return next((e for e in ev if e.get("tool_use_id") == i), None)
# Key by the POST's OWN tool_use_id (fixed), then require it popped its own Pre.
# Keying by matched_pre_id would be tautological (a LIFO mis-pop also mislabels
# matched_pre_id, so its before always 'agrees').
ea, eb = by_tuid("eA"), by_tuid("eB")
if ea and ea.get("matched_pre_id") == "eA" and chg(ea, "src/inter.py") and chg(ea, "src/inter.py")["before"] == sha(b"v0\n"): print("F1_eA_before_v0")
if eb and eb.get("matched_pre_id") == "eB" and chg(eb, "src/inter.py") and chg(eb, "src/inter.py")["before"] == sha(b"v1\n"): print("F1_eB_before_v1")
bx = by_tuid("bX")
# An open (still-unposted) Write Pre is UNCONFIRMED, so it can't CLAIM its path from
# the Bash -- doing so let an ORPHAN (rejected) Pre disown a real Bash secret write.
# It only makes the Bash's overlapping changes 'ambiguous'; the Write's OWN event
# still definitively owns its file.
if bx and chg(bx, "src/injected.py") and chg(bx, "src/injected.py").get("attribution") == "ambiguous": print("F2_injected_ambiguous")
if bx and chg(bx, "out.txt") and chg(bx, "out.txt").get("attribution") == "ambiguous": print("F2_out_ambiguous")
wy = by_tuid("wY")
if wy and chg(wy, "src/injected.py") and chg(wy, "src/injected.py")["status"] == "added": print("F2_write_owns_injected")
PY

assert "F1 id-match keeps eA before=v0 (no swap)"  "$WORK/checkf.txt" "F1_eA_before_v0"
assert "F1 id-match keeps eB before=v1 (no swap)"  "$WORK/checkf.txt" "F1_eB_before_v1"
assert "F2 open Write Pre makes Bash ambiguous"    "$WORK/checkf.txt" "F2_injected_ambiguous"
assert "F2 Bash own output marked ambiguous"       "$WORK/checkf.txt" "F2_out_ambiguous"
assert "F2 Write correctly owns its file"          "$WORK/checkf.txt" "F2_write_owns_injected"
assert "F2 concurrency caveat shown to user"       "$SHOWF" "attribution uncertain"

# F3: a secret modified during a Bash window whose only concurrent tool is an
# UNCONFIRMED (still-open) Edit Pre. The modification MUST be surfaced -- an open Pre
# may be an orphan, so silently crediting it and dropping the write would be a false
# all-clear. The Edit's own event owns it; the Bash entry carries an uncertainty note.
assert "F3 secret modification is surfaced"        "$AUDITF" "MODIFIED config/secrets.env"
assert "F3 concurrency caveat shown for secret"    "$SHOWF" "attribution uncertain"

# F4: no file's bytes may sit ANYWHERE in the store (there is no content tier).
echo "  -- scanning the whole store for at-rest file bytes --"
for s in topsecret_devvars_7777 tfvars_secret_8888 body_keysecret_9999 rotatedsecret999; do
  if grep -rqF -- "$s" "$ALOG_DATA" 2>/dev/null; then
    echo "  FAIL: '$s' found in the store"; fail=1
  else
    echo "  OK: '$s' is NOT at rest"
  fi
done
assert "F4 .dev.vars flagged as a secret write"    "$AUDITF" "WROTE .dev.vars"
assert "F4 *.tfvars flagged as a secret write"     "$AUDITF" "WROTE prod.tfvars"

# F5: allowlist -- templates/public keys not flagged sensitive; their change is
# still recorded (digest + size), never their content.
refute "F5 .env.example NOT flagged sensitive"     "$AUDITF" ".env.example"
refute "F5 public .pub key NOT flagged sensitive"  "$AUDITF" "id_ed25519.pub"
assert "F5 .env.example change still recorded"     "$DIFFF" "created: .env.example"
refute "F5 template content not in the diff"       "$DIFFF" "fill in your real values"

# F6: compound env-var secrets masked in the stored command string.
assert "F6 command redaction applied"              "$NDJF" "<redacted>"
refute "F6 DB_PASSWORD value not stored"           "$NDJF" "prodpw_secret_4444"
refute "F6 AWS secret value not stored"            "$NDJF" "akkey_secret_5555"

# F7: a >10MB file change is 'modified', not hidden as an unchanged 'read'.
assert "F7 large-file change shown as modified"    "$SHOWF" "M big.bin"
assert "F7 large-file note explains no hashing"    "$SHOWF" "large;"

# ---- bug-hunt fix regressions (session 'fix2') ----------------------------
echo
echo "=== bug-hunt fix regressions ==="
SHOWG="$WORK/showg.txt"; DIFFG="$WORK/diffg.txt"; AUDITG="$WORK/auditg.txt"
python3 "$ALOG" --session fix2 show  > "$SHOWG"
python3 "$ALOG" --session fix2 diff  > "$DIFFG"
python3 "$ALOG" --session fix2 audit > "$AUDITG"

# G1: reverse-order concurrency -- Edit owns the secret, Bash is NOT blamed.
assert "G1 Edit owns the secret (reverse order)"   "$AUDITG" "MODIFIED config/g.env"
refute "G1 Bash NOT blamed (posted-overlap caught)" "$AUDITG" "bash MODIFIED config/g.env"
# G2: a doc that merely NAMES the AWS var is not flagged sensitive.
assert "G2 doc change recorded"                    "$DIFFG" "created: docs/aws-setup.md"
refute "G2 doc is not flagged sensitive"           "$AUDITG" "aws-setup.md"
# G3: a template's value never lands at rest (nothing is stored for any file).
refute "G3 template value NOT anywhere in diff"    "$DIFFG" "EXAMPLEPLACEHOLDER0000000000"
if grep -rqF -- "EXAMPLEPLACEHOLDER0000000000" "$ALOG_DATA" 2>/dev/null; then
  echo "  FAIL: G3 template value found in the store"; fail=1
else
  echo "  OK: G3 template value is NOT at rest"
fi
# G4: unreadable after-snapshot -> notice, not a fabricated deletion.
assert "G4 unreadable shows a notice"              "$DIFFG" "unreadable at snapshot"
refute "G4 unreadable does NOT fake-delete line1"  "$DIFFG" "-line1"
# G6: a Bash naming+writing a secret is counted once (no CMD-REF duplicate).
assert "G6 secret write reported once"             "$AUDITG" "WROTE c.env"
refute "G6 no duplicate CMD-REF for same secret"   "$AUDITG" "CMD-REF c.env"

# G7 (perms) + ReDoS timing + cas-4: structural checks in python.
python3 - "$ALOG_DATA" "$ALOG" "$WORK" "$HERE/hook.py" > "$WORK/checkg.txt" <<'PY'
import sys, os, json, hashlib, subprocess, time, importlib.util
data, alog, work, hookpath = sys.argv[1:5]

# G7: session ndjson and pending json must be 0600 (not umask 0644).
bad = []
for sub in ("sessions", "pending"):
    d = os.path.join(data, sub)
    for n in os.listdir(d) if os.path.isdir(d) else []:
        if n.endswith(".tmp"):
            continue
        mode = os.stat(os.path.join(d, n)).st_mode & 0o777
        if mode & 0o077:
            bad.append("{0}/{1}={2:o}".format(sub, n, mode))
print("G7_store_files_0600_OK" if not bad else "G7_FAIL:" + ",".join(bad))

# ReDoS: redact_command on a 20k-char token must finish fast (was ~20s before).
spec = importlib.util.spec_from_file_location("hook", hookpath)
h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
t = time.perf_counter()
h.redact_command("echo " + "A" * 20000 + " token " + "B" * 20000)
dt = (time.perf_counter() - t) * 1000
print("REDOS_bounded_OK ({0:.0f}ms)".format(dt) if dt < 3000 else "REDOS_FAIL ({0:.0f}ms)".format(dt))

# cas-4: a content change that FORGES mtime back is STILL detected, because the
# reuse key includes ctime (which a write always bumps). If only (mtime,size)
# keyed the cache, the stale sha would be reused and the change hidden.
salt = h.get_salt(data)
bd = os.path.join(work, "ctdir"); os.makedirs(bd, exist_ok=True)
fp = os.path.join(bd, "ct.txt")
open(fp, "wb").write(b"AAAA")
snap1 = h.snapshot_tree(data, bd, salt, "ctsess")
orig_m = os.stat(fp).st_mtime_ns
open(fp, "wb").write(b"BBBB")                         # same size, different content
os.utime(fp, ns=(os.stat(fp).st_atime_ns, orig_m))   # forge mtime back; ctime bumps
snap2 = h.snapshot_tree(data, bd, salt, "ctsess")
def _rec(snap):
    return next((v for k, v in snap.items() if k.endswith("ct.txt") and v), None)
r1, r2 = _rec(snap1), _rec(snap2)
print("CAS4_ctime_forge_detected_OK"
      if r1 and r2 and r1.get("sha") != r2.get("sha")
      else "CAS4_FAIL keys1={0} keys2={1}".format(list(snap1), list(snap2)))

# cas-4: a WARM snapshot must actually reuse (no re-read), else H1's "0 changes"
# is a tautology that passes even with the cache disabled. Count snapshot_file.
calls = {"n": 0}; orig_sf = h.snapshot_file
def _counting(*a, **k):
    calls["n"] += 1; return orig_sf(*a, **k)
h.snapshot_file = _counting
wd = os.path.join(work, "warmcount"); os.makedirs(wd, exist_ok=True)
for i in range(5):
    open(os.path.join(wd, "w%d.txt" % i), "w").write("data%d" % i)
h.snapshot_tree(data, wd, salt, "warmcount"); cold_n = calls["n"]; calls["n"] = 0
h.snapshot_tree(data, wd, salt, "warmcount"); warm_n = calls["n"]
h.snapshot_file = orig_sf
print("CAS4_warm_reuse_OK" if cold_n >= 5 and warm_n == 0
      else "CAS4_warm_FAIL cold={0} warm={1}".format(cold_n, warm_n))

# cas-4: two cwds in one session must record their OWN content (abspath key),
# never cross-substitute on a same-relative-name collision.
ca = os.path.join(work, "cwa"); cb = os.path.join(work, "cwb")
os.makedirs(ca, exist_ok=True); os.makedirs(cb, exist_ok=True)
open(os.path.join(ca, "VERSION"), "w").write("1.0.0\n")
open(os.path.join(cb, "VERSION"), "w").write("2.0.0\n")
sa = h.snapshot_tree(data, ca, salt, "xcwd"); sb = h.snapshot_tree(data, cb, salt, "xcwd")
def _sha(snap, name):
    r = next((v for k, v in snap.items() if os.path.basename(k) == name and v), None)
    return r.get("sha") if r else None
print("CAS4_xcwd_OK"
      if _sha(sa, "VERSION") == h.salted_digest(salt, b"1.0.0\n")
      and _sha(sb, "VERSION") == h.salted_digest(salt, b"2.0.0\n")
      else "CAS4_xcwd_FAIL sa={0} sb={1}".format(list(sa), list(sb)))

# sc-2 fail-safe: the reverted doc carve-out must NOT make secrets.md storable.
# A file named secrets.md / secret.rst, and one inside .ssh/, stays sensitive.
print("SC2_failsafe_OK"
      if h.is_sensitive("secrets.md") and h.is_sensitive("app/secret.rst")
      and h.is_sensitive(".ssh/secret.md")
      else "SC2_failsafe_FAIL")
PY
assert "G7 sessions/pending files are 0600"         "$WORK/checkg.txt" "G7_store_files_0600_OK"
assert "ReDoS: redaction is bounded (<3s on 40KB)"  "$WORK/checkg.txt" "REDOS_bounded_OK"

# cas-4: manifest-cached whole-tree snapshot.
SHOWW="$WORK/showw.txt"
python3 "$ALOG" --session warm show > "$SHOWW"
assert "H1 warm Bash invents no changes"            "$SHOWW" "0 file change(s)"
if [ -f "$ALOG_DATA/manifests/warm.json" ]; then
  echo "  OK: cas-4 reuse manifest is created (warm.json)"
else
  echo "  FAIL: cas-4 manifest missing"; fail=1
fi
assert "cas-4 forged-mtime change still detected"   "$WORK/checkg.txt" "CAS4_ctime_forge_detected_OK"
assert "cas-4 warm snapshot reuses (no re-read)"    "$WORK/checkg.txt" "CAS4_warm_reuse_OK"
assert "cas-4 distinct cwds keep own content"       "$WORK/checkg.txt" "CAS4_xcwd_OK"
assert "sc-2 secrets.md stays sensitive (no leak)"  "$WORK/checkg.txt" "SC2_failsafe_OK"

# P1: concurrency -- 20 parallel events -> 20 lines, unique seqs (flock).
python3 - "$ALOG_DATA/sessions/conc.ndjson" > "$WORK/conc.txt" <<'PY'
import json, sys
seqs = [json.loads(l)["seq"] for l in open(sys.argv[1]) if l.strip()]
print("CONC_OK" if len(seqs) == 20 and sorted(seqs) == list(range(1, 21))
      else "CONC_FAIL n={0} uniq={1}".format(len(seqs), len(set(seqs))))
PY
assert "P1 20 parallel events: 20 lines, unique seqs" "$WORK/conc.txt" "CONC_OK"

# Q: prompt capture + token/cost capture (the MVP git can't give you).
assert "Q1 turn dedupe by message.id (tokens not multiplied)" "$WORK/checkq.txt" "Q_dedupe_OK"
assert "Q2 repeated Stop is idempotent (no double count)"      "$WORK/checkq.txt" "Q_idempotent_OK"
assert "Q3 prompt secret redacted, never stored"              "$WORK/checkq.txt" "Q_prompt_redacted_OK"
assert "Q4 per-turn cost derived (opus > haiku)"              "$WORK/checkq.txt" "Q_cost_OK"
assert "Q5 show renders the prompt line"                      "$OBS" "prompt"
assert "Q6 show renders a token turn with a cost estimate"    "$OBS" "~$"
assert "Q7 cost command totals tokens across turns"           "$OBSCOST" "TOTAL"
refute "Q8 prompt secret absent from show output"             "$OBS" "$SECRET"
assert "Q9 pasted PEM private key never stored (R4-1)"        "$WORK/checkq.txt" "Q_pem_redacted_OK"

echo
if [ "$fail" -eq 0 ]; then echo "ALL ASSERTIONS PASSED"; else echo "SOME ASSERTIONS FAILED"; exit 1; fi
