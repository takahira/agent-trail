#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""alog -- read the agent audit log produced by hook.py.

Reads the local NDJSON event log and reports, fully offline:

  alog show       a git-status-like timeline of what the agent did
  alog diff       change detection (status / size delta / mode) per changed file
  alog audit      ONLY the sensitive-file accesses (the view git cannot give you)
  alog cost       per-model token usage + estimated cost for the session
  alog sessions   list recorded sessions

The timeline also carries two non-tool event kinds git never sees: ``prompt``
(what the agent was asked, redacted) and ``turn`` (per-message token usage).
``cost`` derives dollars from the recorded tokens and the MODEL_PRICING table in
this file -- a rough estimate, not a billing source; tokens are the ground truth.

The point: the hook detects what changed from observed content DIGESTS -- so
`diff` sees what a Bash `sed -i` / `rm` changed even though the command string
never named the file -- and `audit` surfaces reads of secrets, which leave no
git trace at all. File CONTENT is never stored (v0.2+: salted digests +
metadata only), so `diff` shows change detection, not content hunks; for a
git-tracked file, `git diff` has the content story.

Python 3.9 compatible; standard library only.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import stat
import sys
import time
from typing import Dict, List, Optional, Tuple

# Single source of truth for the package version (read by pyproject.toml).
__version__ = "0.2.0"

STATUS_LETTER = {"added": "A", "modified": "M", "deleted": "D", "read": "R",
                 "present": "?", "missing": "!", "typechange": "T"}
CHANGE_STATUSES = ("added", "modified", "deleted", "typechange")

# --- token cost (ESTIMATE ONLY) -------------------------------------------
# USD per 1,000,000 tokens, per model FAMILY (longest matching prefix wins).
# SINGLE SOURCE OF TRUTH for the cost estimate: UPDATE THESE MANUALLY when
# Anthropic pricing changes. Cost is DERIVED here at display time from the raw
# token counts the hook recorded -- the log stores ground-truth tokens, not
# dollars, so re-pricing is just re-running alog. These rates are illustrative
# for the audit-cost demo, NOT a billing source of record.
#   tuple = (input, output, cache_write_5m, cache_read)  USD / 1e6 tokens
# APPROXIMATION: ALL cache-creation tokens are priced at the 5-minute-TTL write
# rate. The transcript records one `cache_creation_input_tokens` total and does not
# break it down by TTL, so a 1-hour-TTL write (a higher rate) is under-counted here.
# This only shifts the ESTIMATE; the recorded token counts stay ground truth.
# Keyed by FAMILY token (matched anywhere in the id) so legacy shapes like
# `claude-3-5-sonnet-20241022` / `claude-3-opus-20240229` price correctly, not just
# the `claude-<family>-*` form.
MODEL_PRICING = {
    "opus": (15.0, 75.0, 18.75, 1.50),
    "sonnet": (3.0, 15.0, 3.75, 0.30),
    "haiku": (1.0, 5.0, 1.25, 0.10),
}
PRICE_PER = 1_000_000
TURN_TOKEN_KEYS = ("input_tokens", "output_tokens",
                   "cache_creation_input_tokens", "cache_read_input_tokens")


def _num(v) -> int:
    """A recorded token field as a non-negative int, tolerant of a hand-edited /
    partially-corrupt log: rejects bool, NaN/Infinity, and non-numeric values
    (mirrors the hook's _tok_int so the reader never crashes on junk it didn't
    write). The hook only ever emits ints, so this only matters off the happy path.
    Clamps negatives to 0, matching the hook's _tok_int -- a negative token field in
    a hand-edited log would otherwise subtract from totals and the cost estimate."""
    if isinstance(v, bool):
        return 0
    if isinstance(v, int):
        return max(0, v)
    if isinstance(v, float):
        return max(0, int(v)) if math.isfinite(v) else 0
    return 0


def _snum(v):
    """A numeric field usable as a sort key / gmtime arg, or 0 for any non-number
    (string/None/bool). The hook only writes numeric ts/seq; this guards a
    corrupt/tampered log so one bad line can't crash sorting or timestamp rendering."""
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else 0


def _seq(ev: Dict) -> int:
    """An event's seq as an int for `{0:02d}` display; 0 for a non-int (a corrupt log
    with `\"seq\":\"x\"` would otherwise raise ValueError and abort the whole command)."""
    v = ev.get("seq")
    return v if isinstance(v, int) and not isinstance(v, bool) else 0


def _changes(ev: Dict) -> List[Dict]:
    """An event's change records as a list of dicts, tolerant of a corrupt/tampered
    log: `{\"changes\":null}` or a non-dict element would otherwise raise
    (`for c in None` / `c.get` on a str) and abort the whole command."""
    raw = ev.get("changes")
    return [c for c in raw if isinstance(c, dict)] if isinstance(raw, list) else []


def _markers(ev: Dict) -> List:
    """An event's cmd_sensitive markers as a list of STRINGS (empty for a non-list).
    Non-string elements (e.g. `cmd_sensitive: [{}]` in a tampered log) are dropped so
    a `marker in sens_paths` membership test can't crash on an unhashable dict."""
    raw = ev.get("cmd_sensitive")
    return [m for m in raw if isinstance(m, str)] if isinstance(raw, list) else []


def _sess(ev: Dict) -> str:
    """An event's session id as a string, so it is safe to put in a set / dict key
    and print. A tampered log can carry a non-string (list) session_id that the hook
    kept verbatim in the event, which would raise `unhashable type` in a set build."""
    s = ev.get("session")
    return s if isinstance(s, str) else ("" if s is None else str(s))


def price_for(model: Optional[str]) -> Optional[Tuple[float, float, float, float]]:
    """(input, output, cache_write, cache_read) rate tuple for a model, or None
    when the model is not a known family (a newer model whose price we don't know,
    or a non-string value in a corrupt log -- we report tokens but decline to
    invent a dollar figure)."""
    if not isinstance(model, str) or not model:
        return None
    m = model.lower()
    best = None
    for fam, rates in MODEL_PRICING.items():
        if fam in m and (best is None or len(fam) > len(best[0])):
            best = (fam, rates)
    return best[1] if best else None


def turn_tokens(ev: Dict) -> int:
    """Total tokens (input + output + cache write + cache read) for a turn."""
    return sum(_num(ev.get(k)) for k in TURN_TOKEN_KEYS)


def turn_cost(ev: Dict) -> Optional[float]:
    """Estimated USD for one turn from its recorded tokens, or None if the
    model's price is unknown."""
    rates = price_for(ev.get("model"))
    if not rates:
        return None
    pi, po, pcw, pcr = rates
    return (_num(ev.get("input_tokens")) * pi
            + _num(ev.get("output_tokens")) * po
            + _num(ev.get("cache_creation_input_tokens")) * pcw
            + _num(ev.get("cache_read_input_tokens")) * pcr) / PRICE_PER


_MODEL_DATE_RE = re.compile(r"-\d{8}$")


def short_model(model: Optional[str]) -> str:
    """'claude-opus-4-8' -> 'opus-4-8'; 'claude-haiku-4-5-20251001' -> 'haiku-4-5'.
    Drops the 'claude-' prefix and any trailing -YYYYMMDD date for compact,
    column-friendly display (family pricing keys off the family, not the date).
    A non-string model (corrupt log) renders as '?'."""
    if not isinstance(model, str) or not model:
        return "?"
    m = model[len("claude-"):] if model.startswith("claude-") else model
    return _MODEL_DATE_RE.sub("", m)


def cost_summary(turns: List[Dict]):
    """(total_tokens, est_cost_or_None, n_unknown_price) over a list of turns."""
    total_tok = sum(turn_tokens(e) for e in turns)
    costs = [turn_cost(e) for e in turns]
    known = [c for c in costs if c is not None]
    est = sum(known) if known else None
    return total_tok, est, len(costs) - len(known)


def fmt_cost(est: Optional[float], n_unknown: int) -> str:
    """Render an estimated cost with an honest marker for unknown-price turns."""
    s = "~${0:.4f}".format(est) if est is not None else "n/a"
    if n_unknown:
        s += " (+{0} turn(s) w/ unknown model price)".format(n_unknown)
    return s


# ---- loading -------------------------------------------------------------

def sessions_dir(base: str) -> str:
    return os.path.join(base, "sessions")


def list_session_ids(base: str) -> List[str]:
    d = sessions_dir(base)
    if not os.path.isdir(d):
        return []
    return [n[: -len(".ndjson")] for n in sorted(os.listdir(d))
            if n.endswith(".ndjson")]


def load_events(base: str, session: Optional[str]) -> List[Dict]:
    ids = [session] if session else list_session_ids(base)
    events: List[Dict] = []
    for sid in ids:
        path = os.path.join(sessions_dir(base), sid + ".ndjson")
        # Open a REGULAR file only, via a non-following/non-blocking fd: a crafted
        # store where `<sid>.ndjson` is a directory (IsADirectoryError), a symlink, or
        # a FIFO (blocking read) would otherwise crash or hang the reader. Per-session
        # try/except so one bad session file is skipped, not fatal. errors="replace"
        # keeps a torn byte from dropping the whole command.
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
        except OSError:
            continue
        try:
            with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as fh:
                if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                    continue
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(obj, dict):
                        events.append(obj)
        except OSError:
            continue
    # Sort by (ts, session, seq): seq is per-session, so without the session key
    # a default all-sessions view interleaves and shows colliding seq numbers.
    # Coerce every key defensively (see _snum): one corrupt/tampered line with a
    # string ts or seq (json.loads accepts it) would otherwise raise TypeError
    # mid-sort and brick the reader, defeating the "skip malformed lines" design.
    events.sort(key=lambda e: (_snum(e.get("ts")), str(e.get("session") or ""),
                               _snum(e.get("seq"))))
    return events


# ---- formatting ----------------------------------------------------------

def fmt_time(ts, show_time: bool) -> str:
    # Guard ts to a real number: a corrupt/tampered log with `"ts":"x"` (truthy
    # string) or an out-of-range value would otherwise raise in time.gmtime under
    # --time and abort the command. _snum coerces non-numbers to 0 -> falsy -> "".
    if not show_time:
        return ""
    n = _snum(ts)
    if not n:
        return ""
    try:
        return time.strftime("%H:%M:%S", time.gmtime(n)) + " "
    except (ValueError, OverflowError, OSError):
        return ""


# Control chars AND lone surrogates. A non-UTF-8 filename is recorded by the hook as
# a lone surrogate (json ensure_ascii escape); left intact it raises UnicodeEncodeError
# when print() encodes stdout as UTF-8, crashing the reader. Fold both to U+FFFD.
_CTRL_RE = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f-\x9f\ud800-\udfff"
    # Unicode bidi/invisible FORMAT chars: RLM/LRM/RLO/LRO/PDF, isolates, ALM, word
    # joiner, BOM. Without these, a path/command with U+202E renders REVERSED on the
    # terminal, so a sensitive `prod.env` can be shown as a benign name -- defeating
    # _safe's anti-spoof promise. U+2028/U+2029 (LINE/PARAGRAPH SEPARATOR) are folded
    # too: some terminals treat them as newlines, forging extra timeline lines even
    # though _safe_inline only collapses \n/\r.
    "  ؜​-‏‪-‮⁠-⁤⁦-⁯﻿]")


def _safe(s) -> str:
    """Neutralise terminal control characters (ESC/ANSI/OSC, CR, etc.) and lone
    surrogates in any agent-influenced string -- file paths, Bash commands, prompts,
    file content -- before it is printed, so a crafted value can't spoof/drive the
    reviewer's terminal or crash print() when they run `alog show/diff/audit`. Keeps
    \\t and \\n (callers handle line breaks); other C0/C1 + DEL + surrogates → U+FFFD."""
    return _CTRL_RE.sub("�", s if isinstance(s, str) else str(s))


def _safe_inline(s) -> str:
    """_safe() for a value printed on a SINGLE output line (a path, a marker, a
    model name). Also collapses newlines to spaces: _safe keeps '\\n' for multi-line
    content (diff bodies), but a value rendered inline must not carry one -- an
    attacker-named path like 'notes.txt\\n          A prod.env  ⚠ sensitive' would
    otherwise inject a forged second timeline line and fabricate a fake event."""
    return _safe(s).replace("\n", " ").replace("\r", " ")


def summarize_event(ev: Dict) -> str:
    if ev.get("tool") == "Bash":
        cmd = _safe_inline(ev.get("command") or "")
        return "$ " + (cmd[:65] + "…" if len(cmd) > 65 else cmd)
    return _safe_inline(ev.get("file_path") or "")


def render_nontool(ev: Dict, show_time: bool, multi: bool) -> str:
    """One timeline line for a prompt or turn event (no file changes)."""
    seq = _seq(ev)
    head = "[#{0:02d}] {1}{2}".format(seq, fmt_time(ev.get("ts"), show_time),
                                      sess_tag(ev, multi))
    if ev.get("kind") == "prompt":
        text = _safe_inline(ev.get("prompt") or "")
        shown = text[:65] + "…" if len(text) > 65 else text
        return '{0}{1:<7} "{2}"'.format(head, "prompt", shown)
    # turn
    cost = turn_cost(ev)
    cost_s = "~${0:.4f}".format(cost) if cost is not None else "cost: price n/a"
    return "{0}{1:<7} {2}  in {3} out {4} cache_r {5} cache_w {6}  {7}".format(
        head, "turn", _safe_inline(short_model(ev.get("model")) or ""),
        _num(ev.get("input_tokens")), _num(ev.get("output_tokens")),
        _num(ev.get("cache_read_input_tokens")),
        _num(ev.get("cache_creation_input_tokens")), cost_s)


def is_agent_sensitive(ev: Dict, change: Dict) -> bool:
    """A sensitive access we attribute to the agent.

    'Sensitive' here means the name/path heuristic flagged it: change['sensitive']
    (which ORs in symlink-target sensitivity) or the hook-side 'redacted' flag.
    Both are honoured so an event written by any hook version -- including v0.1
    logs where 'redacted' could also mean a content-sniff hit -- keeps surfacing
    in `alog audit` / the ⚠ marker / --fail-on-hit.

    A Bash command snapshots the whole work tree, so an UNCHANGED sensitive file
    seen there was hashed by us, not deliberately read by the agent -- counting
    it would be a false 'secret read'. Only a single-file tool that NAMED the
    path, or an actual change, or a command-string reference counts.

    Attribution only governs a Bash change's DOUBLE-COUNTING, not whether the
    access happened. 'claimed_by_concurrent' means a CONFIRMED concurrent single-file
    write (which posted) authored this exact path -- that tool's own event reports the
    access, so suppressing it here avoids counting it twice. 'ambiguous' means NO
    other tool claimed it, so the change is real and MUST be reported (with an
    'attribution uncertain' note) -- suppressing it silently drops a genuine secret
    write from the audit and returns a false all-clear from --fail-on-hit.
    """
    if not (change.get("sensitive") or change.get("redacted")):
        return False
    tool = ev.get("tool")
    # An UNCHANGED ('read') or absent ('missing') sensitive file seen in a Bash whole-
    # tree scan was hashed by us, not deliberately accessed -- don't count it. But
    # 'present' (before-state UNKNOWN because the Bash had no matching Pre -- its Pre
    # was evicted or its lock timed out) may be a file the command CREATED; since we
    # only reach here for a SENSITIVE change, surface it with a caveat rather than
    # silently dropping a possible secret write (a false all-clear for --fail-on-hit).
    if tool == "Bash" and change.get("status") in ("read", "missing"):
        return False
    # Only a confirmed concurrent AUTHOR suppresses (it reports the access itself);
    # 'ambiguous' is still a real, reported access. The claim is only set (hook side)
    # when the claiming tool's OWN change is sensitive/redacted -- so suppressing here
    # never drops a secret access that nothing else reports.
    if tool == "Bash" and change.get("attribution") == "claimed_by_concurrent":
        return False
    return True


def attribution_note(ev: Dict, change: Dict) -> str:
    """A visible caveat when a Bash change can't be cleanly pinned on the command."""
    if ev.get("tool") != "Bash":
        return ""
    attr = change.get("attribution")
    if attr == "claimed_by_concurrent":
        return "  (also targeted by a concurrent tool; attribution uncertain)"
    if attr == "ambiguous":
        return "  (concurrent tool active; attribution uncertain)"
    return ""


def sess_tag(ev: Dict, multi: bool) -> str:
    """Session marker (first 8 chars), shown only when more than one session is
    displayed, to disambiguate the otherwise per-session seq numbers."""
    # Sanitize BEFORE truncating: a 4-byte ESC sequence (e.g. \x1b[2J) fits under
    # the 8-char cap, so a raw slice would still drive the reviewer's terminal.
    return "{{{0}}} ".format(_safe_inline(_sess(ev) or "?")[:8]) if multi else ""


def agent_sensitive_paths(ev: Dict) -> set:
    """Paths in this event already counted as an agent secret access -- so a
    command-string reference to the SAME path isn't double-counted on top."""
    return {c.get("path") for c in _changes(ev) if is_agent_sensitive(ev, c)}


# ---- commands ------------------------------------------------------------

def cmd_sessions(base: str) -> int:
    ids = list_session_ids(base)
    if not ids:
        print("no sessions recorded (is the hook wired up?)")
        return 0
    print("sessions:")
    for sid in ids:
        evs = load_events(base, sid)
        n_changes = sum(1 for e in evs for c in _changes(e)
                        if c.get("status") in CHANGE_STATUSES)
        n_sens = 0
        for e in evs:
            sp = agent_sensitive_paths(e)
            n_sens += len(sp)
            n_sens += sum(1 for m in _markers(e) if m not in sp)
        n_prompts = sum(1 for e in evs if e.get("kind") == "prompt")
        turns = [e for e in evs if e.get("kind") == "turn"]
        total_tok, est, n_unknown = cost_summary(turns)
        print("  {0}  events={1}  changes={2}  sensitive={3}  prompts={4}"
              "  turns={5}  tokens={6:,}  cost={7}".format(
                  _safe_inline(sid), len(evs), n_changes, n_sens, n_prompts,
                  len(turns), total_tok, fmt_cost(est, n_unknown)))
    return 0


def _change_line(ev: Dict, c: Dict, tool: str) -> Optional[str]:
    """The `alog show` line for one change, or None to skip it (an incidental
    whole-tree read seen under a Bash scan is not the agent's deliberate access)."""
    status = c.get("status")
    letter = STATUS_LETTER.get(status, "?")
    sflag = "  ⚠ sensitive" if is_agent_sensitive(ev, c) else ""
    anote = attribution_note(ev, c)
    path = _safe_inline(c.get("path"))
    if status in ("read", "present", "missing"):
        # A Bash whole-tree observation is normally skipped -- EXCEPT a SENSITIVE
        # 'present' (before unknown; a possible no-Pre write), which is surfaced with a
        # caveat so a secret the command may have created is not silently dropped.
        if tool == "Bash" and not (status == "present" and is_agent_sensitive(ev, c)):
            return None
        note = {"read": "", "present": " (before unknown; possible write)",
                "missing": " (named but absent)"}.get(status, "")
        if c.get("external_change"):
            note += " (content changed externally during the read)"
        return "          {0} {1}{2}{3}{4}".format(letter, path, note, anote, sflag)
    tc = "  (type change)" if status == "typechange" else ""
    lc = ""
    if status != "typechange" and c.get("large"):
        lc = "  (large; {0}->{1} bytes, content not hashed)".format(
            _safe_inline(str(c.get("before_size"))), _safe_inline(str(c.get("after_size"))))
    elif status != "typechange" and c.get("content_unavailable") == "unreadable":
        lc = "  (unreadable at snapshot; content not captured)"
    mc = ""
    if isinstance(c.get("mode_change"), list) and len(c["mode_change"]) == 2:
        b_m, a_m = c["mode_change"]
        if isinstance(b_m, int) and isinstance(a_m, int):
            mc = "  (mode {0:o}->{1:o})".format(b_m, a_m)   # e.g. chmod +x: 644->755
    return "          {0} {1}{2}{3}{4}{5}{6}".format(letter, path, tc, lc, mc, anote, sflag)


def cmd_show(base: str, session: Optional[str], show_time: bool) -> int:
    events = load_events(base, session)
    if not events:
        print("no events recorded")
        return 0
    multi = session is None and len({_sess(e) for e in events}) > 1
    if multi:
        print("(multiple sessions; each line tagged {sessio…})")
    n_changes = 0
    n_sens = 0
    for ev in events:
        kind = ev.get("kind")
        if kind in ("prompt", "turn"):
            # Non-tool events (what was asked / token cost) sit inline in the
            # timeline by seq; they carry no file changes so we render + skip.
            print(render_nontool(ev, show_time, multi))
            continue
        tool = _safe_inline(ev.get("tool") or "?")   # also strips ANSI from a crafted
        prefix = "[#{0:02d}] {1}{2}{3:<7}".format(    # or MCP-supplied tool name
            _seq(ev), fmt_time(ev.get("ts"), show_time),
            sess_tag(ev, multi), tool.lower())
        print("{0} {1}".format(prefix, summarize_event(ev)))
        if not ev.get("had_before"):
            print("        (no matching pre-snapshot; before-state unknown)")
        sens_paths = agent_sensitive_paths(ev)
        for c in _changes(ev):
            line = _change_line(ev, c, tool)
            if line is not None:
                print(line)
                if c.get("status") in CHANGE_STATUSES:
                    n_changes += 1
            if is_agent_sensitive(ev, c):
                n_sens += 1
        for marker in _markers(ev):
            if marker in sens_paths:   # already counted as a change above
                continue
            n_sens += 1
            print("          ⚠ command references sensitive path: {0}".format(_safe_inline(marker)))
    print()
    print("summary: {0} events, {1} file change(s), {2} sensitive access(es)".format(
        len(events), n_changes, n_sens))
    prompts = [e for e in events if e.get("kind") == "prompt"]
    turns = [e for e in events if e.get("kind") == "turn"]
    if prompts or turns:
        total_tok, est, n_unknown = cost_summary(turns)
        print("         {0} prompt(s), {1} turn(s), {2:,} tokens, est. cost {3}".format(
            len(prompts), len(turns), total_tok, fmt_cost(est, n_unknown)))
    return 0


def _size_int(v) -> Optional[int]:
    """A recorded size as an int, or None for anything else (tampered log)."""
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def render_one_diff(ev: Dict, change: Dict) -> List[str]:
    """Change-detection record for one change: status, size delta, mode change.

    No content hunks: the hook stores salted digests + metadata only (v0.2+),
    never file bytes. For a git-tracked file `git diff` has the content story;
    what this view adds is changes by opaque Bash commands, untracked/ignored
    files, and sensitive accesses."""
    path = _safe_inline(change.get("path"))  # sanitized once; used in every header below
    status = change.get("status")
    out = ["diff --alog [#{0:02d} {1}] {2}".format(
        _seq(ev), _safe_inline(ev.get("tool") or "?"), path)]

    # A sensitive change is reported as an access, with NO metadata beyond the
    # status -- in particular no size, so a secret's byte length is never shown.
    # This must fire for EVERY sensitive record, not just redacted/'S:' ones: a
    # sensitive-by-path non-regular record (e.g. an added `.env` symlink, or a
    # target-sensitive alias) carries `sensitive=True` but neither `redacted` nor
    # an `S:` digest (its sha is None), and would otherwise fall through to the
    # size-disclosing branches below and print `created: .env (0 bytes)`.
    if change.get("redacted") or change.get("sensitive") \
            or str(change.get("before") or "").startswith("S:") \
            or str(change.get("after") or "").startswith("S:"):
        verb = {"added": "created", "modified": "modified",
                "deleted": "deleted"}.get(status if isinstance(status, str) else None,
                                          "touched")
        out.append("[sensitive -- content not stored; {0}, access recorded]".format(verb))
        return out
    if status == "typechange":
        out.append("type change (regular file <-> directory/special): {0}".format(path))
        return out
    cu = change.get("content_unavailable")
    if change.get("large") or cu == "large":
        out.append("large file (>{0} bytes, content not hashed): size {1} -> {2}".format(
            10 * 1024 * 1024, _safe_inline(str(change.get("before_size"))),
            _safe_inline(str(change.get("after_size")))))
        return out
    if cu == "unreadable":
        out.append("unreadable at snapshot time (change detected via stat): {0}".format(path))
        return out

    b_size = _size_int(change.get("before_size"))
    a_size = _size_int(change.get("after_size"))
    if status == "added":
        line = "created: {0}".format(path)
        if a_size is not None:
            line += "  ({0:,} bytes)".format(a_size)
    elif status == "deleted":
        line = "deleted: {0}".format(path)
        if b_size is not None:
            line += "  (was {0:,} bytes)".format(b_size)
    else:
        line = "modified: {0}".format(path)
        if b_size is not None and a_size is not None:
            delta = a_size - b_size
            line += "  ({0:,} -> {1:,} bytes, {2}{3:,})".format(
                b_size, a_size, "+" if delta >= 0 else "", delta)
    out.append(line)
    mc = change.get("mode_change")
    if isinstance(mc, list) and len(mc) == 2 \
            and all(isinstance(m, int) and not isinstance(m, bool) for m in mc):
        out.append("mode: {0:o} -> {1:o}".format(mc[0], mc[1]))
    return out


def cmd_diff(base: str, session: Optional[str], only_path: Optional[str]) -> int:
    events = load_events(base, session)
    printed = 0
    for ev in events:
        for c in _changes(ev):
            if c.get("status") not in CHANGE_STATUSES:
                continue
            if only_path and c.get("path") != only_path:
                continue
            for line in render_one_diff(ev, c):
                print(line)
            print()
            printed += 1
    if printed == 0:
        print("no file changes recorded"
              + (" for {0}".format(only_path) if only_path else ""))
    else:
        print("note: file content is never stored (salted digests + metadata only);")
        print("      for tracked files, `git diff` / `git log -p` has the content story.")
    return 0


def cmd_audit(base: str, session: Optional[str], show_time: bool,
              fail_on_hit: bool = False) -> int:
    """Only the things git cannot show: sensitive accesses & command refs.

    With fail_on_hit, returns 2 when any sensitive access is found, so the command
    can gate a pre-commit hook / CI step (otherwise it always returns 0)."""
    events = load_events(base, session)
    multi = session is None and len({_sess(e) for e in events}) > 1
    hits = 0
    print("=== sensitive access audit ===")
    for ev in events:
        seq = _seq(ev)
        # Default AND sanitize: an event missing 'tool' (corrupt/tampered log) would
        # make tool.lower() raise AttributeError below and abort the WHOLE audit --
        # dropping every later sensitive access and never firing --fail-on-hit. The
        # _safe_inline also strips ANSI from a crafted (or MCP-supplied) tool name.
        tool = _safe_inline(ev.get("tool") or "?")
        t = fmt_time(ev.get("ts"), show_time)
        st = sess_tag(ev, multi)
        sens_paths = set()
        for c in _changes(ev):
            if not is_agent_sensitive(ev, c):
                continue
            hits += 1
            sens_paths.add(c.get("path"))
            verb = {"read": "READ", "added": "WROTE", "modified": "MODIFIED",
                    "deleted": "DELETED", "missing": "READ-ATTEMPT (absent)",
                    "present": "ACCESSED"}.get(c.get("status"), "TOUCHED")
            print("  [#{0:02d}] {1}{2}{3} {4} {5}".format(
                seq or 0, t, st, tool.lower(), verb, _safe_inline(c.get("path"))))
        for marker in _markers(ev):
            if marker in sens_paths:   # already reported as a change; don't double-count
                continue
            hits += 1
            print("  [#{0:02d}] {1}{2}{3} CMD-REF {4}  ({5})".format(
                seq or 0, t, st, tool.lower(), _safe_inline(marker),
                # str()-coerce BEFORE slicing: a tampered non-string `command`
                # (int/dict) made the raw `[:50]` slice raise TypeError and abort
                # the whole audit -- dropping later hits and skipping --fail-on-hit.
                # Matches summarize_event (sanitize/coerce first, then truncate).
                _safe_inline(str(ev.get("command") or ""))[:50]))
    if hits == 0:
        print("  (none) -- no sensitive files were accessed")
    else:
        print()
        print("{0} sensitive access(es). NOTE: a plain `git diff` shows NONE of".format(hits))
        print("the read-only accesses above -- reading a secret leaves no git trace.")
    return 2 if (fail_on_hit and hits) else 0


def cmd_cost(base: str, session: Optional[str]) -> int:
    """Token usage and estimated cost, aggregated per model.

    The dollar figure is a rough estimate derived from the token counts in the log
    and the MODEL_PRICING table at the top of this file (illustrative, not a
    billing source). Raw tokens are the ground truth; cost is recomputable by
    editing that table and re-running -- no re-capture needed."""
    events = load_events(base, session)
    turns = [e for e in events if e.get("kind") == "turn"]
    if not turns:
        print("no token/cost data recorded "
              "(wire the Stop hook -- see settings-snippet.json)")
        return 0
    per_model = {}
    order = []
    for e in turns:
        model = e.get("model")
        if not isinstance(model, str) or not model:   # a corrupt log's list/dict model
            model = "?"                                # is unhashable -> TypeError as a key
        if model not in per_model:
            per_model[model] = {k: 0 for k in TURN_TOKEN_KEYS}
            per_model[model]["turns"] = 0
            order.append(model)
        agg = per_model[model]
        agg["turns"] += 1
        for k in TURN_TOKEN_KEYS:
            agg[k] += _num(e.get(k))

    print("=== token usage & estimated cost (estimate) ===")
    print("  {0:<16} {1:>6} {2:>9} {3:>9} {4:>11} {5:>11}  {6}".format(
        "model", "turns", "input", "output", "cache_read", "cache_wr", "est. cost"))
    for model in order:
        agg = per_model[model]
        # A per-model cost: reuse turn_cost by feeding the aggregate as one pseudo-turn.
        pseudo = {"model": model, **{k: agg[k] for k in TURN_TOKEN_KEYS}}
        c = turn_cost(pseudo)
        cost_s = "~${0:.4f}".format(c) if c is not None else "price n/a"
        print("  {0:<16} {1:>6} {2:>9,} {3:>9,} {4:>11,} {5:>11,}  {6}".format(
            _safe_inline(short_model(model)), agg["turns"], agg["input_tokens"],
            agg["output_tokens"], agg["cache_read_input_tokens"],
            agg["cache_creation_input_tokens"], cost_s))
    total_tok, est, n_unknown = cost_summary(turns)
    print()
    print("  TOTAL: {0} turn(s), {1:,} tokens, est. cost {2}".format(
        len(turns), total_tok, fmt_cost(est, n_unknown)))
    print("  NOTE: cost is a rough estimate from MODEL_PRICING in alog.py "
          "(update rates there); tokens are the recorded ground truth.")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    # default=SUPPRESS is load-bearing: the common args live on BOTH the main
    # parser and every subparser (so they work before OR after the subcommand),
    # and a normal default would let the subparser RESET the attribute to that
    # default -- so `alog --session X show` silently lost the filter and showed
    # ALL sessions. With SUPPRESS the subparser only sets the attr when actually
    # given, letting the main-parser value (or vice versa) persist.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--data", default=argparse.SUPPRESS,
                        help="audit data dir (default: $ALOG_DATA or ./.alog)")
    common.add_argument("--session", default=argparse.SUPPRESS,
                        help="restrict to one session id (default: all)")
    common.add_argument("--time", action="store_true", default=argparse.SUPPRESS,
                        help="show timestamps (HH:MM:SS, UTC)")

    parser = argparse.ArgumentParser(
        description="read the local agent audit log", parents=[common])
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("sessions", help="list recorded sessions", parents=[common])
    sub.add_parser("show", help="timeline of what the agent did", parents=[common])
    p_diff = sub.add_parser("diff", help="before/after diff of changed files",
                            parents=[common])
    p_diff.add_argument("path", nargs="?", default=None, help="restrict to one path")
    p_audit = sub.add_parser("audit", help="sensitive-file accesses only", parents=[common])
    p_audit.add_argument("--fail-on-hit", action="store_true", default=argparse.SUPPRESS,
                         help="exit nonzero (2) if any sensitive access is found (for CI)")
    sub.add_parser("cost", help="token usage & estimated cost per model", parents=[common])

    args = parser.parse_args(argv)
    data_arg = getattr(args, "data", None)
    session = getattr(args, "session", None)
    show_time = getattr(args, "time", False)
    base = os.path.abspath(
        data_arg or os.environ.get("ALOG_DATA") or os.path.join(os.getcwd(), ".alog"))
    if not os.path.isdir(base):
        print("no audit data at {0} (run something under the hook first)".format(base),
              file=sys.stderr)
        return 1

    if args.cmd == "sessions":
        return cmd_sessions(base)
    if args.cmd == "show":
        return cmd_show(base, session, show_time)
    if args.cmd == "diff":
        return cmd_diff(base, session, getattr(args, "path", None))
    if args.cmd == "audit":
        return cmd_audit(base, session, show_time, getattr(args, "fail_on_hit", False))
    if args.cmd == "cost":
        return cmd_cost(base, session)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
