#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the agent audit-log (hook.py + alog.py).

Function-level tests for hook.py and alog.py, complementing the integration-style
demo.sh. Standard library only (unittest), matching the project's zero-dependency
constraint. Run from the repo root with:

    python3 -m unittest discover -s tests -p "test_*.py" -t .

The tests pin a frozen clock and use throwaway temp stores/worktrees, so they are
deterministic and never touch a real .alog. Each test targets one behaviour or one
fixed bug (the docstring of each test names the finding id where relevant).
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import tempfile
import time
import unittest

# alog.py and hook.py live at the repo root, one level up from tests/.
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


hook = _load("hook")
alog = _load("alog")


def sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _redos_probe(payload: bytes) -> None:
    """Subprocess target: run the content sniff so a hang can be terminated
    (a thread cannot -- re.search holds the GIL for the whole scan)."""
    hook.content_looks_secret(payload)


# ===========================================================================
# Pure classifiers / redaction (no filesystem)
# ===========================================================================

class TestSensitiveClassification(unittest.TestCase):
    def test_exact_and_glob_names(self):
        for name in ("id_rsa", ".env", "server.key", "kubeconfig", "creds.pem",
                     ".npmrc", "terraform.tfstate", ".git-credentials"):
            self.assertTrue(hook.is_sensitive(name), name)

    def test_recall_dev_vars_and_tfvars(self):
        # FN1/FN2: the user's primary stack (CF Workers / Terraform).
        for name in (".dev.vars", "prod.tfvars", "main.auto.tfvars",
                     "vars.tfvars.json", "vpn.ovpn"):
            self.assertTrue(hook.is_sensitive(name), name)

    def test_case_insensitive_recall(self):
        # S1: a glob must match regardless of case.
        self.assertTrue(hook.is_sensitive("ServiceAccountKey.JSON"))
        self.assertTrue(hook.is_sensitive("Server.KEY"))

    def test_path_segments(self):
        self.assertTrue(hook.is_sensitive("home/.ssh/config"))
        self.assertTrue(hook.is_sensitive("a/.aws/credentials"))
        self.assertTrue(hook.is_sensitive("x/secrets/db.txt"))
        # substring of a segment must NOT trip it
        self.assertFalse(hook.is_sensitive("backup.sshconfig"))
        self.assertFalse(hook.is_sensitive("src/token_bucket.py"))

    def test_allowlist_false_positives(self):
        # FP1/FP2/FP3: public/template artifacts are never secret.
        for name in (".env.example", ".env.sample", "config/.env.template",
                     "id_rsa.pub", "id_ed25519.pub", "fullchain.pem",
                     "chain.pem", "ca.pem", ".dev.vars.example"):
            self.assertFalse(hook.is_sensitive(name), name)
            self.assertTrue(hook.is_allowlisted(name), name)

    def test_dev_vars_template_allowlisted_but_real_one_sensitive(self):
        # sc-3: the template is exempt; the real .dev.vars is not.
        self.assertFalse(hook.is_sensitive(".dev.vars.example"))
        self.assertTrue(hook.is_sensitive(".dev.vars"))

    def test_sc2_secret_doc_stays_sensitive(self):
        # sc-2 fail-safe: a doc carve-out was REVERTED because it leaked content
        # at rest. secrets.md / secret.rst / a doc inside .ssh stay sensitive.
        self.assertTrue(hook.is_sensitive("secrets.md"))
        self.assertTrue(hook.is_sensitive("app/secret.rst"))
        self.assertTrue(hook.is_sensitive(".ssh/secret.md"))

    def test_value_bearing_secret_files(self):
        self.assertTrue(hook.is_sensitive("secret.json"))
        self.assertTrue(hook.is_sensitive("secrets.yaml"))


class TestContentSniff(unittest.TestCase):
    def test_private_key_header(self):
        self.assertTrue(hook.content_looks_secret(b"-----BEGIN OPENSSH PRIVATE KEY-----\nx"))
        self.assertTrue(hook.content_looks_secret(b"-----BEGIN RSA PRIVATE KEY-----"))

    def test_cloud_credential_shapes(self):
        self.assertTrue(hook.content_looks_secret(b"AKIAIOSFODNN7EXAMPLE0"))
        self.assertTrue(hook.content_looks_secret(b"ghp_" + b"a" * 30))

    def test_aws_key_requires_value(self):
        # sc-1/REG-1: a mere mention of the env name must NOT trip the sniff.
        self.assertFalse(hook.content_looks_secret(b"Set AWS_SECRET_ACCESS_KEY in CI"))
        self.assertTrue(hook.content_looks_secret(
            b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfi"))

    def test_plain_text_is_not_secret(self):
        self.assertFalse(hook.content_looks_secret(b"hello world\nlprint(1)\n"))

    def test_pgp_private_key_block(self):
        # PGP armor uses the " BLOCK" suffix -- it must be caught (atrest-pgp).
        pgp = b"-----BEGIN PGP PRIVATE KEY BLOCK-----\nxyz\n"
        self.assertTrue(hook.content_has_private_key(pgp))
        self.assertTrue(hook.content_looks_secret(pgp))
        # but public/cert armor must NOT be treated as a private key
        self.assertFalse(hook.content_has_private_key(b"-----BEGIN CERTIFICATE-----\nx"))
        self.assertFalse(hook.content_has_private_key(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nx"))


class TestRedaction(unittest.TestCase):
    def test_compound_env_names(self):
        # R1: the old leading \b left compound env names unmasked.
        for cmd, secret in (("DB_PASSWORD=supersecret123", "supersecret123"),
                            ("AWS_SECRET_ACCESS_KEY=abc/DEF+ghi123", "abc/DEF+ghi123"),
                            ("PGPASSWORD=hunter2 psql", "hunter2"),
                            ("export API_TOKEN=tok_live_99", "tok_live_99")):
            out = hook.redact_command(cmd)
            self.assertNotIn(secret, out, cmd)
            self.assertIn("<redacted>", out)

    def test_quoted_value_swallowed_whole(self):
        # redaction-scan-2: a quoted value with spaces must not leak its tail.
        out = hook.redact_command('export API_KEY="a b c secret"')
        self.assertNotIn("secret", out)

    def test_url_credentials_incl_empty_user(self):
        # redaction-scan-3: user:pass@host, including an empty user (redis://:p@h).
        self.assertNotIn("p4ss", hook.redact_command("curl https://u:p4ss@example.com"))
        self.assertNotIn("p4ss", hook.redact_command("redis-cli -u redis://:p4ss@h:6379"))

    def test_long_flag_value(self):
        self.assertNotIn("sekret", hook.redact_command("tool --password sekret --port 1"))

    def test_token_shapes(self):
        self.assertNotIn("ABCDEF123456", hook.redact_command("h Bearer ABCDEF123456"))

    def test_redos_is_bounded(self):
        # redaction-scan-1: the {0,40} bound + length cap kill the ReDoS that
        # made a long token take ~20s. Must finish well under a second's worth.
        payload = "x" + "a" * 20000 + "token" + "b" * 20000
        t = time.perf_counter()
        hook.redact_command(payload)
        self.assertLess(time.perf_counter() - t, 2.0)

    def test_command_length_cap(self):
        out = hook.redact_command("echo " + "Z" * (hook.MAX_COMMAND_CHARS + 5000))
        self.assertIn("truncated", out)
        self.assertLessEqual(len(out), hook.MAX_COMMAND_CHARS + 64)


class TestScanForSecrets(unittest.TestCase):
    CWD = "/work"  # absolute/~ tokens below don't resolve into it, so they stay verbatim

    def test_flag_equals_path(self):
        # R3: classify the RHS of --kubeconfig=/path.
        self.assertEqual(hook.scan_cmd_for_secrets(
            "kubectl --kubeconfig=/home/u/kubeconfig get po", self.CWD),
            ["/home/u/kubeconfig"])

    def test_no_double_count(self):
        # redaction-scan-4: NAME=/path must be classified once, not twice.
        found = hook.scan_cmd_for_secrets(
            "KUBECONFIG=/home/u/.kube/config kubectl", self.CWD)
        self.assertEqual(len(found), 1)

    def test_tilde_ssh_key(self):
        self.assertEqual(hook.scan_cmd_for_secrets("cat ~/.ssh/id_rsa | head", self.CWD),
                         ["~/.ssh/id_rsa"])

    def test_no_false_positive(self):
        self.assertEqual(hook.scan_cmd_for_secrets("echo hello && ls -la", self.CWD), [])


class TestSafeSession(unittest.TestCase):
    def test_injective(self):
        # MC-3: 'a/b' and 'a_b' must not collide.
        self.assertNotEqual(hook._safe_session("a/b"), hook._safe_session("a_b"))

    def test_uuid_untouched(self):
        self.assertEqual(hook._safe_session("5421aabb-21de-4214"), "5421aabb-21de-4214")

    def test_no_traversal(self):
        # All '/' are replaced, so the result is a single filename component:
        # any '..' left is literal text, not a path separator. Joining it under a
        # store dir must NOT escape that dir.
        s = hook._safe_session("../../etc/passwd")
        self.assertNotIn("/", s)
        self.assertNotIn(s, ("", ".", ".."))
        joined = os.path.normpath(os.path.join("/base/sessions", s + ".ndjson"))
        self.assertTrue(joined.startswith("/base/sessions/"))


# ===========================================================================
# Filesystem-backed: CAS, snapshots, manifest
# ===========================================================================

class StoreTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="agent-trail-test.")
        self.base = os.path.join(self.tmp, ".alog")
        self.work = os.path.join(self.tmp, "work")
        os.makedirs(self.work)
        hook.ensure_dirs(self.base)
        self.salt = hook.get_salt(self.base)
        self._prev_clock = os.environ.get("ALOG_FROZEN_CLOCK")
        os.environ["ALOG_FROZEN_CLOCK"] = "1700000000"

    def tearDown(self):
        if self._prev_clock is None:
            os.environ.pop("ALOG_FROZEN_CLOCK", None)
        else:
            os.environ["ALOG_FROZEN_CLOCK"] = self._prev_clock
        shutil.rmtree(self.tmp, ignore_errors=True)

    def wf(self, rel, content):
        p = os.path.join(self.work, rel)
        d = os.path.dirname(p)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(content if isinstance(content, bytes) else content.encode())
        return p


class TestCAS(StoreTestCase):
    def test_store_blob_roundtrip(self):
        s = hook.store_blob(self.base, b"hello\n")
        self.assertEqual(s, sha(b"hello\n"))
        obj = os.path.join(self.base, "objects", s[:2], s)
        self.assertTrue(os.path.exists(obj))
        with open(obj, "rb") as fh:
            self.assertEqual(fh.read(), b"hello\n")

    def test_store_blob_leaves_no_tmp(self):
        # cas-1: unique tmp + cleanup, no orphan .tmp.
        hook.store_blob(self.base, b"data")
        objdir = os.path.join(self.base, "objects", sha(b"data")[:2])
        self.assertFalse(any(n.endswith(".tmp") for n in os.listdir(objdir)))

    def test_salt_is_stable_and_16_bytes(self):
        # cas-2: idempotent, always >=16 bytes.
        self.assertEqual(len(self.salt), 16)
        self.assertEqual(hook.get_salt(self.base), self.salt)

    def test_sensitive_digest_is_salted(self):
        d = hook.sensitive_digest(self.salt, b"topsecret")
        self.assertTrue(d.startswith("S:"))
        self.assertNotEqual(d, "S:" + sha(b"topsecret")[:16])  # salted, not plain


class TestSnapshotFile(StoreTestCase):
    def test_regular_file_stored(self):
        p = self.wf("a.txt", b"content\n")
        rec = hook.snapshot_file(self.base, p, self.salt, False, False)
        self.assertEqual(rec["sha"], sha(b"content\n"))
        self.assertNotIn("redacted", rec)

    def test_sensitive_name_withheld(self):
        p = self.wf(".env", b"API_TOKEN=zzz\n")
        rec = hook.snapshot_file(self.base, p, self.salt, True, False)
        self.assertTrue(rec["redacted"])
        self.assertTrue(rec["sha"].startswith("S:"))
        # the secret bytes must NOT be in the object store
        self.assertFalse(self._blob_contains(b"API_TOKEN=zzz"))

    def test_content_sniff_withholds_misnamed_key(self):
        # FN3/S1: a private key saved under an innocent name is still withheld.
        p = self.wf("notes.txt", b"-----BEGIN OPENSSH PRIVATE KEY-----\nbody999\n")
        rec = hook.snapshot_file(self.base, p, self.salt,
                                 hook.is_sensitive("notes.txt"), hook.is_allowlisted("notes.txt"))
        self.assertTrue(rec["redacted"])
        self.assertFalse(self._blob_contains(b"body999"))

    def test_env_template_with_real_secret_withheld(self):
        # L3: env/vars TEMPLATES are NOT sniff-exempt, so a real credential left in
        # a .env.example (the copy-and-forget-to-strip pattern) is WITHHELD, not
        # stored in cleartext. Only structurally-public names (*.pub/cert) skip it.
        rel = ".env.example"
        p = self.wf(rel, b"AWS_SECRET_ACCESS_KEY=AKIAEXAMPLEREALKEY01234567890ABCD\n")
        rec = hook.snapshot_file(self.base, p, self.salt,
                                 hook.is_sensitive(rel), hook.is_sniff_exempt(rel))
        self.assertTrue(rec.get("redacted"))
        self.assertFalse(self._blob_contains(b"AKIAEXAMPLEREALKEY"))

    def test_clean_env_template_still_stored(self):
        # A template with no credential-shaped content stays storable/diffable.
        rel = ".env.example"
        p = self.wf(rel, b"# copy to .env\nPORT=3000\nHOST=localhost\n")
        rec = hook.snapshot_file(self.base, p, self.salt,
                                 hook.is_sensitive(rel), hook.is_sniff_exempt(rel))
        self.assertNotIn("redacted", rec)
        self.assertTrue(self._blob_contains(b"PORT=3000"))

    def test_toolarge_not_read(self):
        # cas-6/C1: >10MB carries size+mtime+ctime, not a blob.
        p = os.path.join(self.work, "big.bin")
        with open(p, "wb") as fh:
            fh.truncate(hook.MAX_BLOB_BYTES + 1024)
        rec = hook.snapshot_file(self.base, p, self.salt, False, False)
        self.assertTrue(rec["toolarge"])
        self.assertIsNone(rec["sha"])
        self.assertIn("ctime", rec)

    def test_missing_returns_none(self):
        self.assertIsNone(hook.snapshot_file(
            self.base, os.path.join(self.work, "nope"), self.salt, False, False))

    def _blob_contains(self, needle):
        objroot = os.path.join(self.base, "objects")
        for dp, _, files in os.walk(objroot):
            for f in files:
                with open(os.path.join(dp, f), "rb") as fh:
                    if needle in fh.read():
                        return True
        return False


class TestSnapshotTree(StoreTestCase):
    def test_warm_reuse_avoids_reread(self):
        # cas-4: a warm (unchanged) snapshot must re-read NOTHING.
        for i in range(5):
            self.wf("d/f%d.txt" % i, b"x" * 50)
        calls = {"n": 0}
        orig = hook.snapshot_file

        def counting(*a, **k):
            calls["n"] += 1
            return orig(*a, **k)
        hook.snapshot_file = counting
        try:
            hook.snapshot_tree(self.base, self.work, self.salt, "s")
            cold = calls["n"]
            calls["n"] = 0
            hook.snapshot_tree(self.base, self.work, self.salt, "s")
            warm = calls["n"]
        finally:
            hook.snapshot_file = orig
        self.assertGreaterEqual(cold, 5)
        self.assertEqual(warm, 0)

    def test_ctime_forge_still_detected(self):
        # cas-4/F1: a same-size content change with mtime forged back is still
        # caught because ctime is in the reuse key.
        p = self.wf("ct.txt", b"AAAA")
        s1 = hook.snapshot_tree(self.base, self.work, self.salt, "s")
        orig_m = os.stat(p).st_mtime_ns
        with open(p, "wb") as fh:
            fh.write(b"BBBB")
        os.utime(p, ns=(os.stat(p).st_atime_ns, orig_m))  # forge mtime; ctime bumps
        s2 = hook.snapshot_tree(self.base, self.work, self.salt, "s")
        self.assertNotEqual(s1["ct.txt"]["sha"], s2["ct.txt"]["sha"])

    def test_cross_cwd_no_substitution(self):
        # cas4-1: same session over two cwds keys by abspath, so same-named files
        # in different dirs keep their OWN content.
        a = os.path.join(self.work, "cwa")
        b = os.path.join(self.work, "cwb")
        os.makedirs(a)
        os.makedirs(b)
        with open(os.path.join(a, "VERSION"), "wb") as fh:
            fh.write(b"1.0.0\n")
        with open(os.path.join(b, "VERSION"), "wb") as fh:
            fh.write(b"2.0.0\n")
        sa = hook.snapshot_tree(self.base, a, self.salt, "x")
        sb = hook.snapshot_tree(self.base, b, self.salt, "x")
        self.assertEqual(sa["VERSION"]["sha"], sha(b"1.0.0\n"))
        self.assertEqual(sb["VERSION"]["sha"], sha(b"2.0.0\n"))

    def test_corrupt_manifest_rec_falls_through(self):
        # cas4-2: a rec without "sha" must NOT be reused.
        self.wf("v.txt", b"real")
        hook.snapshot_tree(self.base, self.work, self.salt, "s")
        # corrupt the manifest: blank out the rec
        mp = hook.manifest_path(self.base, "s")
        with open(mp) as fh:
            man = json.load(fh)
        key = next(iter(man))
        man[key]["rec"] = {}  # no "sha"
        with open(mp, "w") as fh:
            json.dump(man, fh)
        snap = hook.snapshot_tree(self.base, self.work, self.salt, "s")
        self.assertEqual(snap["v.txt"]["sha"], sha(b"real"))  # re-read, not the {}


# ===========================================================================
# Pending stack / correlation
# ===========================================================================

class TestPending(StoreTestCase):
    def test_pop_by_tool_use_id(self):
        hook.push_pending(self.base, "s", {"id": "A", "tool": "Edit",
                                           "file_path": "x", "ts": 1, "before": {"x": {"sha": "1"}}})
        hook.push_pending(self.base, "s", {"id": "B", "tool": "Edit",
                                           "file_path": "x", "ts": 1, "before": {"x": {"sha": "2"}}})
        # Post for A must pop A's record (not LIFO-most B): no before-swap.
        rec = hook.pop_pending(self.base, "s", "Edit", "x", "A")
        self.assertEqual(rec["before"]["x"]["sha"], "1")

    def test_orphan_id_returns_none(self):
        hook.push_pending(self.base, "s", {"id": "A", "tool": "Bash", "ts": 1, "before": {}})
        # A Post whose id has no pending Pre must NOT steal an unrelated record.
        self.assertIsNone(hook.pop_pending(self.base, "s", "Edit", "y", "ZZZ"))

    def test_legacy_lifo_without_id(self):
        hook.push_pending(self.base, "s", {"id": None, "tool": "Edit",
                                           "file_path": "x", "ts": 1, "before": {}})
        rec = hook.pop_pending(self.base, "s", "Edit", "x", None)
        self.assertIsNotNone(rec)

    def test_length_cap(self):
        for i in range(hook.MAX_PENDING + 20):
            hook.push_pending(self.base, "s", {"id": str(i), "tool": "Bash", "ts": 1, "before": {}})
        self.assertLessEqual(len(hook.list_pending(self.base, "s")), hook.MAX_PENDING)


# ===========================================================================
# build_changes status logic
# ===========================================================================

class TestBuildChanges(unittest.TestCase):
    @staticmethod
    def rec(sha=None, **kw):
        d = {"sha": sha, "size": kw.pop("size", 1)}
        d.update(kw)
        return d

    def test_added_modified_deleted_read(self):
        before = {"a": None, "b": self.rec("1"), "c": self.rec("9"), "d": self.rec("7")}
        after = {"a": self.rec("2"), "b": self.rec("3"), "c": None, "d": self.rec("7")}
        st = {c["path"]: c["status"] for c in
              hook.build_changes(before, after, True, None)}
        self.assertEqual(st["a"], "added")
        self.assertEqual(st["b"], "modified")
        self.assertEqual(st["c"], "deleted")
        self.assertEqual(st["d"], "read")

    def test_present_when_no_before(self):
        st = hook.build_changes({}, {"x": self.rec("1")}, False, None)
        self.assertEqual(st[0]["status"], "present")

    def test_missing_named(self):
        st = hook.build_changes({}, {}, True, "secret.env")
        self.assertEqual(st[0]["status"], "missing")

    def test_typechange(self):
        before = {"x": self.rec("1")}
        after = {"x": {"sha": None, "size": 0, "kind": "non-regular"}}
        st = hook.build_changes(before, after, True, None)
        self.assertEqual(st[0]["status"], "typechange")

    def test_toolarge_size_change_is_modified(self):
        # C1: two too-large snapshots with different size -> modified, not read.
        before = {"x": {"sha": None, "size": 11_000_000, "toolarge": True, "mtime": 1, "ctime": 1}}
        after = {"x": {"sha": None, "size": 12_000_000, "toolarge": True, "mtime": 2, "ctime": 2}}
        c = hook.build_changes(before, after, True, None)[0]
        self.assertEqual(c["status"], "modified")
        self.assertEqual(c["content_unavailable"], "large")

    def test_unreadable_after_not_fake_deleted(self):
        # alog-1/F2: an unreadable 'after' must be content_unavailable, not a
        # phantom deletion (before sha set, after sha None but record exists).
        before = {"x": self.rec("1")}
        after = {"x": {"sha": None, "size": 5, "unreadable": True, "mtime": 9, "ctime": 9}}
        c = hook.build_changes(before, after, True, None)[0]
        self.assertEqual(c["status"], "modified")
        self.assertEqual(c["content_unavailable"], "unreadable")

    def test_bash_attribution(self):
        # M2/M3: concurrent tool overlap is marked, exclusive otherwise.
        before = {"o": None, "p": None}
        after = {"o": self.rec("1"), "p": self.rec("2")}
        changes = hook.build_changes(before, after, True, None, is_bash=True,
                                     concurrent=[{"file_path": "p"}])
        st = {c["path"]: c.get("attribution") for c in changes}
        self.assertEqual(st["p"], "claimed_by_concurrent")
        self.assertEqual(st["o"], "ambiguous")  # has_concurrent but not this path
        # no concurrent -> exclusive
        clean = hook.build_changes(before, after, True, None, is_bash=True, concurrent=[])
        self.assertEqual(clean[0]["attribution"], "exclusive")


# ===========================================================================
# Full Pre/Post flow through the hook
# ===========================================================================

class TestHookFlow(StoreTestCase):
    def emit(self, event, tool, sess="s", tid=None, fp=None, cmd=None):
        payload = {"session_id": sess, "tool_input": {}}
        if fp is not None:
            payload["tool_input"]["file_path"] = fp
        if cmd is not None:
            payload["tool_input"]["command"] = cmd
        fn = hook.handle_pre if event == "pre" else hook.handle_post
        fn(self.base, payload, tool, self.work, self.salt, tid)

    def events(self, sess="s"):
        return alog.load_events(self.base, sess)

    def test_write_added(self):
        self.emit("pre", "Write", tid="t1", fp="app.py")
        self.wf("app.py", b"print(1)\n")
        self.emit("post", "Write", tid="t1", fp="app.py")
        ev = self.events()[0]
        self.assertEqual(ev["changes"][0]["status"], "added")
        self.assertEqual(ev["changes"][0]["after"], sha(b"print(1)\n"))

    def test_bash_opaque_add_and_delete(self):
        # The headline: a command that names no file, reconstructed by tree diff.
        self.wf("old.tmp", b"scratch\n")
        self.emit("pre", "Bash", tid="b1", cmd="sh gen.sh")
        os.remove(os.path.join(self.work, "old.tmp"))
        self.wf("gen/report.txt", b"ok\n")
        self.emit("post", "Bash", tid="b1", cmd="sh gen.sh")
        st = {c["path"]: c["status"] for c in self.events()[0]["changes"]
              if c["status"] in alog.CHANGE_STATUSES}
        self.assertEqual(st.get("gen/report.txt"), "added")
        self.assertEqual(st.get("old.tmp"), "deleted")

    def test_secret_read_recorded(self):
        self.wf(".env", b"API_TOKEN=sekret\n")
        self.emit("pre", "Read", tid="r1", fp=".env")
        self.emit("post", "Read", tid="r1", fp=".env")
        c = self.events()[0]["changes"][0]
        self.assertEqual(c["status"], "read")
        self.assertTrue(c["sensitive"])

    def test_interleaved_edits_no_before_swap(self):
        # M1: Pre(A) Pre(B) Post(A) Post(B) on the same file. id correlation must
        # keep A's before=v0 and B's before=v1 (no swap).
        self.wf("f.py", b"v0\n")
        self.emit("pre", "Edit", tid="A", fp="f.py")
        self.wf("f.py", b"v1\n")
        self.emit("pre", "Edit", tid="B", fp="f.py")
        self.wf("f.py", b"v2\n")
        self.emit("post", "Edit", tid="A", fp="f.py")
        self.emit("post", "Edit", tid="B", fp="f.py")
        # Key by the POST's own tool_use_id (fixed), then assert it popped ITS OWN
        # Pre. Keying by matched_pre_id would be tautological: a LIFO mis-pop also
        # mislabels matched_pre_id, so the before would still "agree" with it.
        by_tuid = {e["tool_use_id"]: e for e in self.events()}
        self.assertEqual(by_tuid["A"]["matched_pre_id"], "A")
        self.assertEqual(by_tuid["B"]["matched_pre_id"], "B")
        self.assertEqual(by_tuid["A"]["changes"][0]["before"], sha(b"v0\n"))
        self.assertEqual(by_tuid["B"]["changes"][0]["before"], sha(b"v1\n"))

    def test_concurrent_edit_not_blamed_on_bash_reverse_order(self):
        # MC-1: a fast Edit that posts BEFORE the slow Bash post. The Bash must
        # not be credited with the secret change (posted-overlap by seq).
        self.wf("config.env", b"TOKEN=old\n")
        self.emit("pre", "Bash", tid="bash1", cmd="echo go")
        self.emit("pre", "Edit", tid="edit1", fp="config.env")
        self.wf("config.env", b"TOKEN=rotated\n")
        self.emit("post", "Edit", tid="edit1", fp="config.env")   # Edit posts first
        self.emit("post", "Bash", tid="bash1", cmd="echo go")     # Bash posts after
        bash_ev = next(e for e in self.events() if e["tool"] == "Bash")
        envc = next(c for c in bash_ev["changes"] if c["path"] == "config.env")
        self.assertEqual(envc.get("attribution"), "claimed_by_concurrent")
        self.assertFalse(alog.is_agent_sensitive(bash_ev, envc))

    def test_next_seq_monotonic(self):
        for i in range(4):
            self.emit("pre", "Write", tid="w%d" % i, fp="f%d" % i)
            self.wf("f%d" % i, b"x")
            self.emit("post", "Write", tid="w%d" % i, fp="f%d" % i)
        seqs = [e["seq"] for e in self.events()]
        self.assertEqual(seqs, sorted(set(seqs)))
        self.assertEqual(seqs, [1, 2, 3, 4])


# ===========================================================================
# alog reader / renderer
# ===========================================================================

class TestToLines(unittest.TestCase):
    def test_binary_detected(self):
        lines, is_bin, _ = alog.to_lines(b"a\x00b")
        self.assertTrue(is_bin)

    def test_crlf_not_extra_split(self):
        lines, is_bin, _ = alog.to_lines(b"a\r\nb\r\n")
        self.assertFalse(is_bin)
        self.assertEqual(len(lines), 2)

    def test_no_final_newline(self):
        _, _, nonl = alog.to_lines(b"abc")
        self.assertTrue(nonl)


class TestAgentSensitive(unittest.TestCase):
    def test_bash_unchanged_secret_not_counted(self):
        ev = {"tool": "Bash"}
        self.assertFalse(alog.is_agent_sensitive(ev, {"sensitive": True, "status": "read"}))

    def test_bash_ambiguous_change_is_reported(self):
        # A real sensitive MODIFICATION with uncertain attribution must still be
        # reported (with a caveat) -- suppressing it returns a false all-clear from
        # --fail-on-hit (Codex#4 / Workflow orphan-Pre). Only a CONFIRMED concurrent
        # author (claimed_by_concurrent, which reports it on its own event) suppresses.
        ev = {"tool": "Bash"}
        self.assertTrue(alog.is_agent_sensitive(
            ev, {"sensitive": True, "status": "modified", "attribution": "ambiguous"}))
        self.assertFalse(alog.is_agent_sensitive(
            ev, {"sensitive": True, "status": "modified",
                 "attribution": "claimed_by_concurrent"}))
        # an ambiguous whole-tree READ under Bash is still an incidental observation
        self.assertFalse(alog.is_agent_sensitive(
            ev, {"sensitive": True, "status": "read", "attribution": "ambiguous"}))

    def test_single_file_secret_counted(self):
        ev = {"tool": "Read"}
        self.assertTrue(alog.is_agent_sensitive(ev, {"sensitive": True, "status": "read"}))


class TestRenderDiff(StoreTestCase):
    def test_added_shows_content(self):
        s = hook.store_blob(self.base, b"hello\n")
        out = "\n".join(alog.render_one_diff(
            self.base, {"seq": 1, "tool": "Write"},
            {"path": "a", "status": "added", "before": None, "after": s}))
        self.assertIn("+hello", out)

    def test_binary_not_dumped(self):
        s = hook.store_blob(self.base, b"\x00\x01bin")
        out = "\n".join(alog.render_one_diff(
            self.base, {"seq": 1, "tool": "Write"},
            {"path": "a.bin", "status": "added", "before": None, "after": s}))
        self.assertIn("Binary", out)

    def test_redacted_not_shown(self):
        out = "\n".join(alog.render_one_diff(
            self.base, {"seq": 1, "tool": "Write"},
            {"path": ".env", "status": "added", "redacted": True, "after": "S:abc"}))
        self.assertIn("content not stored", out)

    def test_missing_blob_notice(self):
        # alog-3: a present sha that resolves to no blob -> notice, not fake diff.
        out = "\n".join(alog.render_one_diff(
            self.base, {"seq": 1, "tool": "Bash"},
            {"path": "x", "status": "modified", "before": "deadbeef" * 8, "after": None}))
        self.assertIn("missing or pruned", out)

    def test_unreadable_notice(self):
        out = "\n".join(alog.render_one_diff(
            self.base, {"seq": 1, "tool": "Edit"},
            {"path": "x", "status": "modified", "before": None, "after": None,
             "content_unavailable": "unreadable"}))
        self.assertIn("unreadable at snapshot", out)


class TestArgparseSessionFilter(StoreTestCase):
    """The --session/--data/--time flags must work BEFORE or AFTER the subcommand
    (the SUPPRESS fix for the parent/subparser default clobber)."""

    def setUp(self):
        super().setUp()
        for sess, name in (("s1", "alpha.txt"), ("s2", "beta.txt")):
            payload = {"session_id": sess, "tool_input": {"file_path": name}}
            hook.handle_pre(self.base, payload, "Write", self.work, self.salt, sess + "t")
            self.wf(name, b"x")
            hook.handle_post(self.base, payload, "Write", self.work, self.salt, sess + "t")

    def run_main(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = alog.main(argv)
        return rc, buf.getvalue()

    def test_session_before_subcommand(self):
        _, out = self.run_main(["--data", self.base, "--session", "s1", "show"])
        self.assertIn("alpha.txt", out)
        self.assertNotIn("beta.txt", out)

    def test_session_after_subcommand(self):
        _, out = self.run_main(["--data", self.base, "show", "--session", "s1"])
        self.assertIn("alpha.txt", out)
        self.assertNotIn("beta.txt", out)

    def test_no_session_shows_all(self):
        _, out = self.run_main(["--data", self.base, "show"])
        self.assertIn("alpha.txt", out)
        self.assertIn("beta.txt", out)


# ===========================================================================
# Round-3 fix regressions (atrest-1/2/3, next_seq, multi-session, notebook, ...)
# ===========================================================================

class TestRedactionR3(unittest.TestCase):
    def test_authorization_header_credential(self):
        # atrest-3: mask the credential, not just the scheme word.
        for cmd, sec in (("curl -H 'Authorization: token ghp_realABC123' u", "ghp_realABC123"),
                         ("curl -H 'Authorization: Basic dXNlcjpwdw==' u", "dXNlcjpwdw==")):
            self.assertNotIn(sec, hook.redact_command(cmd), cmd)

    def test_aws_space_delimited_arg(self):
        # atrest-2: `aws configure set aws_secret_access_key VALUE` (no =/:).
        self.assertNotIn("wJaLrSecretVal123", hook.redact_command(
            "aws configure set aws_secret_access_key wJaLrSecretVal123"))

    def test_auth_header_unbalanced_quote_credential(self):
        # redaction-new-1: an unterminated leading quote must not leak the cred.
        self.assertNotIn("hunter2plainpass", hook.redact_command(
            'h Authorization: Bearer "hunter2plainpass'))


class TestAtRestAllowlist(StoreTestCase):
    PK = b"-----BEGIN OPENSSH PRIVATE KEY-----\nLEAKBODY_xyz\n-----END OPENSSH PRIVATE KEY-----\n"

    def _objects_contain(self, needle):
        root = os.path.join(self.base, "objects")
        for dp, _, files in os.walk(root):
            for f in files:
                with open(os.path.join(dp, f), "rb") as fh:
                    if needle in fh.read():
                        return True
        return False

    def test_private_key_in_allowlisted_name_withheld(self):
        # atrest-1: a real key under an allowlisted name must NOT land at rest.
        for name in ("backup.pub", "cert.pem", "fullchain.pem", ".env.production.example"):
            p = self.wf(name, self.PK)
            rec = hook.snapshot_file(self.base, p, self.salt,
                                     hook.is_sensitive(name), hook.is_allowlisted(name))
            self.assertTrue(rec.get("redacted"), name)
        self.assertFalse(self._objects_contain(b"LEAKBODY_xyz"))

    def test_public_key_still_stored(self):
        # The allowlist's purpose (storable public material) is preserved.
        p = self.wf("id_ed25519.pub", b"ssh-ed25519 AAAApublic comment\n")
        rec = hook.snapshot_file(self.base, p, self.salt,
                                 hook.is_sensitive("id_ed25519.pub"),
                                 hook.is_allowlisted("id_ed25519.pub"))
        self.assertNotIn("redacted", rec)
        self.assertTrue(self._objects_contain(b"ssh-ed25519 AAAApublic"))

    def test_blob_permissions_0600(self):
        s = hook.store_blob(self.base, b"perm-check\n")
        mode = os.stat(os.path.join(self.base, "objects", s[:2], s)).st_mode & 0o777
        self.assertEqual(mode & 0o077, 0, "blob must be 0600, got {0:o}".format(mode))

    def test_pgp_key_in_allowlisted_name_withheld(self):
        # atrest-pgp: a PGP private key under an allowlisted name must not leak.
        body = (b"-----BEGIN PGP PRIVATE KEY BLOCK-----\nPGPLEAK_abc\n"
                b"-----END PGP PRIVATE KEY BLOCK-----\n")
        p = self.wf("cert.pem", body)
        rec = hook.snapshot_file(self.base, p, self.salt,
                                 hook.is_sensitive("cert.pem"), hook.is_allowlisted("cert.pem"))
        self.assertTrue(rec.get("redacted"))
        self.assertFalse(self._objects_contain(b"PGPLEAK_abc"))


class TestBuildChangesCtime(unittest.TestCase):
    @staticmethod
    def large(size, mtime, ctime):
        return {"sha": None, "size": size, "toolarge": True, "mtime": mtime, "ctime": ctime}

    def test_ctime_only_difference_is_modified(self):
        # A rewrite that forges mtime+size but bumps ctime must be 'modified'.
        b = {"x": self.large(100, 5, 5)}
        a = {"x": self.large(100, 5, 9)}   # only ctime differs
        self.assertEqual(hook.build_changes(b, a, True, None)[0]["status"], "modified")

    def test_all_equal_is_read(self):
        b = {"x": self.large(100, 5, 5)}
        a = {"x": self.large(100, 5, 5)}
        self.assertEqual(hook.build_changes(b, a, True, None)[0]["status"], "read")


class TestNextSeqRobustness(StoreTestCase):
    def _write_session(self, sess, lines):
        p = hook.session_file(self.base, sess)
        with open(p, "w", encoding="utf-8") as fh:
            for o in lines:
                fh.write(json.dumps(o) + "\n")
        return p

    def test_huge_last_line_uses_seq_not_linecount(self):
        # >64KB last line forces the fallback; it must return last_seq+1, not
        # line_count+1 (which would be wrong here: 3 lines but seq 40/41/42).
        self._write_session("s", [
            {"seq": 40, "x": 1}, {"seq": 41, "x": 2},
            {"seq": 42, "pad": "Z" * 70000}])
        self.assertEqual(hook.next_seq(self.base, "s"), 43)

    def test_non_int_seq_in_tail_continues(self):
        self._write_session("s", [{"seq": 5}, {"seq": "corrupt"}])
        self.assertEqual(hook.next_seq(self.base, "s"), 6)

    def test_malformed_line_skipped(self):
        p = hook.session_file(self.base, "s")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"seq": 1}) + "\n")
            fh.write("{not json}\n")
            fh.write(json.dumps({"seq": 2}) + "\n")
        self.assertEqual(len(hook.read_session_events(self.base, "s")), 2)

    def test_non_dict_json_line_does_not_crash(self):
        # tr-1: a bare JSON value (int/list) has no .get -- next_seq and the
        # readers must skip it, not raise (which would silently drop the event).
        p = hook.session_file(self.base, "s")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"seq": 1}) + "\n")
            fh.write("12345\n")          # bare int line
            fh.write(json.dumps({"seq": 2}) + "\n")
        self.assertEqual(hook.next_seq(self.base, "s"), 3)
        self.assertEqual(len(hook.read_session_events(self.base, "s")), 2)
        self.assertEqual(
            [e["seq"] for e in hook.read_session_events_after(self.base, "s", 1)], [2])


class TestReadAfter(StoreTestCase):
    def test_tail_window_returns_overlap(self):
        p = hook.session_file(self.base, "s")
        with open(p, "w", encoding="utf-8") as fh:
            for i in range(1, 6):
                fh.write(json.dumps({"seq": i, "file_path": "f%d" % i}) + "\n")
        got = sorted(e["seq"] for e in hook.read_session_events_after(self.base, "s", 3))
        self.assertEqual(got, [4, 5])

    def test_full_fallback_when_window_too_small(self):
        # A huge OVERLAP event (seq 2) is pushed out of the 64KB tail, so the tail
        # window can't reach the boundary -> the code must fall back to a full scan
        # and still return BOTH overlap events (2 and 3), not just the visible one.
        p = hook.session_file(self.base, "s")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"seq": 1, "file_path": "early"}) + "\n")
            fh.write(json.dumps({"seq": 2, "file_path": "mid", "pad": "A" * 70000}) + "\n")
            fh.write(json.dumps({"seq": 3, "file_path": "late"}) + "\n")
        got = sorted(e["seq"] for e in hook.read_session_events_after(self.base, "s", 1))
        self.assertEqual(got, [2, 3])


class TestNotebookTools(StoreTestCase):
    def test_notebook_path_recorded(self):
        # NotebookEdit uses tool_input['notebook_path']; it must be captured.
        payload = {"session_id": "s", "tool_input": {"notebook_path": "nb.ipynb"}}
        hook.handle_pre(self.base, payload, "NotebookEdit", self.work, self.salt, "n1")
        self.wf("nb.ipynb", b'{"cells": []}\n')
        hook.handle_post(self.base, payload, "NotebookEdit", self.work, self.salt, "n1")
        ev = alog.load_events(self.base, "s")[0]
        self.assertEqual(ev["file_path"], "nb.ipynb")
        self.assertEqual(ev["changes"][0]["status"], "added")


class TestReaderCLI(StoreTestCase):
    def _emit(self, sess, tool, tid, **inp):
        payload = {"session_id": sess, "tool_input": inp}
        hook.handle_pre(self.base, payload, tool, self.work, self.salt, tid)
        for rel, content in inp.get("_write", []):
            self.wf(rel, content)
        hook.handle_post(self.base, payload, tool, self.work, self.salt, tid)

    def run_main(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = alog.main(argv)
        return rc, buf.getvalue()

    def test_multi_session_header_and_full_tag(self):
        for sess, name in (("sessA", "a.txt"), ("sessB", "b.txt")):
            p = {"session_id": sess, "tool_input": {"file_path": name}}
            hook.handle_pre(self.base, p, "Write", self.work, self.salt, sess)
            self.wf(name, b"x")
            hook.handle_post(self.base, p, "Write", self.work, self.salt, sess)
        _, out = self.run_main(["--data", self.base, "show"])
        self.assertIn("multiple sessions", out)
        self.assertIn("{sessA}", out)   # full id, not truncated to 8 chars
        self.assertIn("{sessB}", out)

    def test_audit_fail_on_hit_exit_code(self):
        self.wf(".env", b"API=zzz\n")
        self._emit("s", "Read", "r1", file_path=".env")
        rc, _ = self.run_main(["--data", self.base, "audit", "--fail-on-hit"])
        self.assertEqual(rc, 2)
        rc, _ = self.run_main(["--data", self.base, "audit"])
        self.assertEqual(rc, 0)

    def test_sensitive_count_deduped_in_show(self):
        # A Bash that both names and writes a secret counts once (no double).
        p = {"session_id": "s", "tool_input": {"command": "echo x > c.env"}}
        hook.handle_pre(self.base, p, "Bash", self.work, self.salt, "b1")
        self.wf("c.env", b"x\n")
        hook.handle_post(self.base, p, "Bash", self.work, self.salt, "b1")
        _, out = self.run_main(["--data", self.base, "--session", "s", "show"])
        self.assertIn("1 sensitive access(es)", out)


class TestNoNewlineMarker(StoreTestCase):
    def _render(self, before, after):
        bs = hook.store_blob(self.base, before)
        as_ = hook.store_blob(self.base, after)
        return alog.render_one_diff(
            self.base, {"seq": 1, "tool": "Edit"},
            {"path": "f", "status": "modified", "before": bs, "after": as_})

    def test_marker_attributed_to_after_when_only_after_lacks_nl(self):
        # before ends with \n, after does NOT: the marker must follow the '+' line.
        out = self._render(b"a\nb\n", b"a\nB")
        joined = "\n".join(out)
        self.assertIn("No newline at end of file", joined)
        # the marker must come AFTER the added line, and there is exactly one
        self.assertEqual(joined.count("No newline at end of file"), 1)
        plus_idx = max(i for i, l in enumerate(out) if l.startswith("+"))
        marker_idx = max(i for i, l in enumerate(out) if l.startswith("\\ No newline"))
        self.assertGreater(marker_idx, plus_idx)

    def test_marker_attributed_to_before_when_only_before_lacks_nl(self):
        # before lacks the newline, after HAS it: git puts the marker after the
        # '-' (before) line, i.e. BEFORE the last '+' line. The old end-only logic
        # implied the after side instead -- this pins the per-side attribution.
        out = self._render(b"a\nB", b"a\nB\n")
        joined = "\n".join(out)
        self.assertEqual(joined.count("No newline at end of file"), 1)
        minus_idx = max(i for i, l in enumerate(out) if l.startswith("-"))
        plus_idx = max(i for i, l in enumerate(out) if l.startswith("+"))
        marker_idx = max(i for i, l in enumerate(out) if l.startswith("\\ No newline"))
        self.assertGreater(marker_idx, minus_idx)
        self.assertLess(marker_idx, plus_idx)   # marker precedes the added line


class TestWalkWorktree(StoreTestCase):
    def test_records_symlinks_and_skips_skip_dirs(self):
        self.wf("keep.txt", b"x")
        self.wf(".git/HEAD", b"ref")           # in TREE_SKIP_DIRS
        self.wf("node_modules/p/i.js", b"y")   # in TREE_SKIP_DIRS
        os.symlink(os.path.join(self.work, "keep.txt"),
                   os.path.join(self.work, "link.txt"))
        found = {hook.rel_to_cwd(self.work, p) for p in hook.walk_worktree(self.work)}
        self.assertIn("keep.txt", found)
        self.assertNotIn(".git/HEAD", found)
        self.assertNotIn("node_modules/p/i.js", found)
        # T2d: symlinks are now RECORDED (as non-regular) -- never followed -- so a
        # Bash-created/replaced symlink is visible in the tree diff, not invisible.
        self.assertIn("link.txt", found)


# ===========================================================================
# Prompt capture (UserPromptSubmit) and token/cost capture (Stop)
# ===========================================================================

class TestRedactPrompt(unittest.TestCase):
    def test_masks_inline_secrets(self):
        # A prompt is prose, but a pasted secret leaks the same way -> mask it.
        out = hook.redact_prompt(
            "deploy with API_KEY=supersecret123 and Authorization: Bearer abc.def")
        self.assertNotIn("supersecret123", out)
        self.assertNotIn("abc.def", out)
        self.assertIn("<redacted>", out)

    def test_masks_url_credentials(self):
        out = hook.redact_prompt("connect to postgres://user:hunter2@db:5432/app")
        self.assertNotIn("hunter2", out)

    def test_benign_prose_unchanged(self):
        text = "add token tracking to the PoC and update the README"
        self.assertEqual(hook.redact_prompt(text), text)

    def test_truncates_huge_paste(self):
        out = hook.redact_prompt("x" * (hook.MAX_PROMPT_CHARS + 500))
        self.assertIn("truncated", out)
        self.assertLess(len(out), hook.MAX_PROMPT_CHARS + 100)


class TestTranscriptParse(StoreTestCase):
    def _transcript(self, rows):
        p = os.path.join(self.tmp, "transcript.jsonl")
        with open(p, "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
        return p

    @staticmethod
    def _asst(mid, model, usage, block="text"):
        return {"type": "assistant",
                "message": {"id": mid, "model": model, "usage": usage,
                            "content": [{"type": block}]}}

    def test_dedupes_by_message_id(self):
        # The SAME message.id is written once per content block with identical
        # usage; summing lines would multiply the turn's tokens. Dedupe by id.
        u = {"input_tokens": 2, "output_tokens": 403,
             "cache_creation_input_tokens": 35380, "cache_read_input_tokens": 20380}
        rows = [self._asst("msg_A", "claude-opus-4-8", u, "thinking"),
                self._asst("msg_A", "claude-opus-4-8", u, "tool_use"),
                self._asst("msg_A", "claude-opus-4-8", u, "tool_use"),
                self._asst("msg_B", "claude-sonnet-5", {"input_tokens": 5, "output_tokens": 9})]
        turns, off = hook.parse_transcript_turns(self._transcript(rows))
        self.assertEqual([t["message_id"] for t in turns], ["msg_A", "msg_B"])
        self.assertEqual(turns[0]["output_tokens"], 403)          # not 403*3
        self.assertEqual(turns[0]["cache_read_input_tokens"], 20380)
        self.assertGreater(off, 0)                                # offset advanced

    def test_ignores_non_assistant_and_corrupt_lines(self):
        p = os.path.join(self.tmp, "mixed.jsonl")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"type": "user", "message": {"content": "hi"}}) + "\n")
            fh.write("{ this is not json\n")
            fh.write("\n")
            fh.write(json.dumps(self._asst("m1", "claude-opus-4-8",
                                           {"input_tokens": 1, "output_tokens": 1})) + "\n")
        turns, _ = hook.parse_transcript_turns(p)
        self.assertEqual([t["message_id"] for t in turns], ["m1"])

    def test_missing_usage_and_model_degrade_safely(self):
        rows = [{"type": "assistant", "message": {"id": "m0", "model": 123}}]  # no usage, bad model
        turns, _ = hook.parse_transcript_turns(self._transcript(rows))
        self.assertEqual(turns[0]["input_tokens"], 0)
        self.assertIsNone(turns[0]["model"])

    def test_missing_file_returns_empty(self):
        self.assertEqual(hook.parse_transcript_turns(
            os.path.join(self.tmp, "nope.jsonl")), ([], 0))

    def test_never_raises_on_truncated_utf8_and_nan(self):
        # R4-2: a torn multi-byte char at EOF (mid-flush write) and NaN/Infinity
        # usage (json.loads accepts them) must yield [] / 0, never an escaping raise.
        p = os.path.join(self.tmp, "torn.jsonl")
        with open(p, "wb") as fh:
            fh.write(json.dumps(self._asst("m1", "claude-opus-4-8",
                                           {"output_tokens": 7})).encode() + b"\n")
            fh.write("日本語".encode("utf-8")[:-1])   # dangling partial multibyte
        turns, _ = hook.parse_transcript_turns(p)
        self.assertEqual([t["message_id"] for t in turns], ["m1"])   # no UnicodeDecodeError
        pn = os.path.join(self.tmp, "nan.jsonl")
        with open(pn, "w", encoding="utf-8") as fh:
            fh.write('{"type":"assistant","message":{"id":"n1",'
                     '"usage":{"input_tokens":NaN,"output_tokens":1e400}}}\n')
        turns, _ = hook.parse_transcript_turns(pn)      # int(nan)/int(inf) would raise
        self.assertEqual(turns[0]["input_tokens"], 0)
        self.assertEqual(turns[0]["output_tokens"], 0)

    def test_offset_reads_only_new_bytes(self):
        # R4-4: passing the returned offset back reads only the appended turn.
        p = os.path.join(self.tmp, "grow.jsonl")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(self._asst("a", "claude-opus-4-8", {"output_tokens": 1})) + "\n")
        first, off = hook.parse_transcript_turns(p)
        self.assertEqual([t["message_id"] for t in first], ["a"])
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(self._asst("b", "claude-opus-4-8", {"output_tokens": 2})) + "\n")
        second, _ = hook.parse_transcript_turns(p, off)
        self.assertEqual([t["message_id"] for t in second], ["b"])   # not 'a' again

    def test_partial_final_line_not_consumed(self):
        # A trailing line with no newline is left for the next read (offset stops
        # at the last complete line).
        p = os.path.join(self.tmp, "partial.jsonl")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(self._asst("a", "claude-opus-4-8", {"output_tokens": 1})) + "\n")
            fh.write('{"type":"assistant","message":{"id":"b"')   # torn, no newline
        turns, off = hook.parse_transcript_turns(p)
        self.assertEqual([t["message_id"] for t in turns], ["a"])
        # complete the torn line; re-reading from offset now sees 'b'
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(',"usage":{"output_tokens":2}}}\n')
        turns2, _ = hook.parse_transcript_turns(p, off)
        self.assertEqual([t["message_id"] for t in turns2], ["b"])


class TestPromptTurnCapture(StoreTestCase):
    def _transcript(self, rows):
        p = os.path.join(self.tmp, "t.jsonl")
        with open(p, "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
        return p

    def test_prompt_event_recorded_and_redacted(self):
        hook.handle_user_prompt(self.base, {
            "session_id": "s", "prompt": "ship it with API_KEY=leakme_9999"})
        evs = alog.load_events(self.base, "s")
        self.assertEqual(evs[0]["kind"], "prompt")
        self.assertEqual(evs[0]["chars"], len("ship it with API_KEY=leakme_9999"))
        self.assertNotIn("leakme_9999", evs[0]["prompt"])
        # and the secret is not sitting in the on-disk log either
        with open(hook.session_file(self.base, "s"), "r", encoding="utf-8") as fh:
            self.assertNotIn("leakme_9999", fh.read())

    def test_empty_prompt_ignored(self):
        hook.handle_user_prompt(self.base, {"session_id": "s", "prompt": "   "})
        self.assertEqual(alog.load_events(self.base, "s"), [])

    def test_turn_events_recorded_from_transcript(self):
        tp = self._transcript([
            {"type": "assistant", "message": {"id": "m1", "model": "claude-opus-4-8",
             "usage": {"input_tokens": 2, "output_tokens": 403,
                       "cache_read_input_tokens": 20380}}}])
        hook.handle_stop(self.base, {"session_id": "s", "transcript_path": tp})
        turns = [e for e in alog.load_events(self.base, "s") if e.get("kind") == "turn"]
        self.assertEqual(len(turns), 1)
        self.assertEqual(turns[0]["message_id"], "m1")
        self.assertEqual(turns[0]["output_tokens"], 403)

    def test_repeated_stop_does_not_double_count(self):
        # The transcript always holds the WHOLE session; a second Stop must add
        # only genuinely new turns (dedupe by message_id from the log itself).
        rows = [{"type": "assistant", "message": {"id": "m%d" % i,
                 "model": "claude-opus-4-8", "usage": {"output_tokens": 10}}}
                for i in range(2)]
        tp = self._transcript(rows)
        hook.handle_stop(self.base, {"session_id": "s", "transcript_path": tp})
        # a new turn appears, then Stop fires again over the grown transcript
        rows.append({"type": "assistant", "message": {"id": "m2",
                     "model": "claude-opus-4-8", "usage": {"output_tokens": 10}}})
        self._transcript(rows)
        hook.handle_stop(self.base, {"session_id": "s", "transcript_path": tp})
        turns = [e for e in alog.load_events(self.base, "s") if e.get("kind") == "turn"]
        self.assertEqual([t["message_id"] for t in turns], ["m0", "m1", "m2"])

    def test_missing_transcript_path_no_event(self):
        hook.handle_stop(self.base, {"session_id": "s"})
        self.assertEqual(alog.load_events(self.base, "s"), [])

    def test_seq_monotonic_across_kinds(self):
        # prompt -> tool -> turn all share one per-session monotonic seq.
        hook.handle_user_prompt(self.base, {"session_id": "s", "prompt": "go"})
        payload = {"session_id": "s", "tool_input": {"file_path": "a.py"}}
        hook.handle_pre(self.base, payload, "Write", self.work, self.salt, "w1")
        self.wf("a.py", b"x\n")
        hook.handle_post(self.base, payload, "Write", self.work, self.salt, "w1")
        tp = self._transcript([{"type": "assistant", "message": {"id": "m1",
             "model": "claude-opus-4-8", "usage": {"output_tokens": 5}}}])
        hook.handle_stop(self.base, {"session_id": "s", "transcript_path": tp})
        evs = alog.load_events(self.base, "s")
        self.assertEqual([e["seq"] for e in evs], [1, 2, 3])
        self.assertEqual([e.get("kind") for e in evs], ["prompt", None, "turn"])


class TestCost(unittest.TestCase):
    def test_price_for_prefix_and_unknown(self):
        self.assertEqual(alog.price_for("claude-opus-4-8"), (15.0, 75.0, 18.75, 1.5))
        self.assertEqual(alog.price_for("claude-haiku-4-5-20251001"),
                         (1.0, 5.0, 1.25, 0.10))
        self.assertIsNone(alog.price_for("claude-fable-5"))
        self.assertIsNone(alog.price_for(None))

    def test_turn_cost_exact(self):
        self.assertAlmostEqual(
            alog.turn_cost({"model": "claude-opus-4-8", "input_tokens": 1_000_000}), 15.0)
        self.assertAlmostEqual(
            alog.turn_cost({"model": "claude-sonnet-5", "output_tokens": 1_000_000}), 15.0)
        self.assertIsNone(alog.turn_cost({"model": "claude-fable-5",
                                          "input_tokens": 1_000_000}))

    def test_turn_tokens_sums_all_four(self):
        ev = {"input_tokens": 1, "output_tokens": 2,
              "cache_creation_input_tokens": 3, "cache_read_input_tokens": 4}
        self.assertEqual(alog.turn_tokens(ev), 10)

    def test_short_model_strips_prefix_and_date(self):
        self.assertEqual(alog.short_model("claude-opus-4-8"), "opus-4-8")
        self.assertEqual(alog.short_model("claude-haiku-4-5-20251001"), "haiku-4-5")


class TestCostRenderCLI(StoreTestCase):
    def setUp(self):
        super().setUp()
        hook.handle_user_prompt(self.base, {"session_id": "s", "prompt": "add cost"})
        rows = [
            {"type": "assistant", "message": {"id": "m1", "model": "claude-opus-4-8",
             "usage": {"input_tokens": 2, "output_tokens": 403,
                       "cache_creation_input_tokens": 35380,
                       "cache_read_input_tokens": 20380}}},
            {"type": "assistant", "message": {"id": "m2", "model": "claude-fable-5",
             "usage": {"input_tokens": 10, "output_tokens": 20}}},
        ]
        tp = os.path.join(self.tmp, "t.jsonl")
        with open(tp, "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
        hook.handle_stop(self.base, {"session_id": "s", "transcript_path": tp})

    def run_main(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = alog.main(argv)
        return rc, buf.getvalue()

    def test_show_renders_prompt_and_turn(self):
        _, out = self.run_main(["--data", self.base, "show"])
        self.assertIn("prompt", out)
        self.assertIn('"add cost"', out)
        self.assertIn("turn", out)
        self.assertIn("opus-4-8", out)
        self.assertIn("~$", out)                    # a cost estimate is shown

    def test_cost_command_totals_and_unknown_price(self):
        _, out = self.run_main(["--data", self.base, "cost"])
        self.assertIn("opus-4-8", out)
        self.assertIn("price n/a", out)             # fable-5 has no price
        self.assertIn("TOTAL", out)
        self.assertIn("unknown model price", out)   # honest about the gap

    def test_sessions_shows_tokens_and_cost(self):
        _, out = self.run_main(["--data", self.base, "sessions"])
        self.assertIn("turns=2", out)
        self.assertIn("tokens=", out)
        self.assertIn("cost=", out)


class TestRedactionHardening(unittest.TestCase):
    """R4-1 / R4-3 / R4-8: prompt redaction gaps and prose over-masking."""

    def test_pem_private_key_masked_in_prompt(self):
        # R4-1: the file path masks private keys unconditionally; the prompt path
        # must too. Both a full BEGIN..END block and a dangling (truncated) header.
        block = ("debug this:\n-----BEGIN RSA PRIVATE KEY-----\n"
                 "MIIEpAIBAAKCAQEA_secretbody_ZZZ\n-----END RSA PRIVATE KEY-----\nthx")
        out = hook.redact_prompt(block)
        self.assertNotIn("MIIEpAIBAAKCAQEA_secretbody_ZZZ", out)
        self.assertIn("<redacted: private key>", out)
        dangling = "here: -----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1_secretYYY"
        self.assertNotIn("b3BlbnNzaC1_secretYYY", hook.redact_prompt(dangling))

    def test_pem_private_key_masked_in_command(self):
        cmd = 'echo "-----BEGIN EC PRIVATE KEY-----\nkeybytes_secretQQQ\n-----END EC PRIVATE KEY-----"'
        self.assertNotIn("keybytes_secretQQQ", hook.redact_command(cmd))

    def test_prose_not_over_masked(self):
        # R4-3: ordinary prose with keyword:word must survive intact.
        for s in ("auth: yes please", "explain the token: economics",
                  "the ring Bearer carried it", "my secret: keep it simple"):
            self.assertEqual(hook.redact_prompt(s), s, s)

    def test_real_secret_values_still_masked_in_prompt(self):
        # ...but a value that looks like key material is still masked.
        for s, secret in (("api_key: aB3xK9mP2qR7wL5t", "aB3xK9mP2qR7wL5t"),
                          ("password: hunter2", "hunter2"),
                          ('token="s0m3-l0ng-t0k3n-value"', "s0m3-l0ng-t0k3n-value")):
            self.assertNotIn(secret, hook.redact_prompt(s), s)

    def test_command_bearer_still_greedy(self):
        # R4-3: commands keep greedy Bearer masking (short tokens included).
        self.assertNotIn("ABCDEF123456", hook.redact_command("curl -H 'Bearer ABCDEF123456'"))

    def test_stripe_and_jwt_shapes(self):
        # R4-8
        self.assertNotIn("abcdefghijklmnop1234",
                         hook.redact_prompt("key sk_live_" + "abcdefghijklmnop1234"))
        jwt = "eyJhbGciOiJI.eyJzdWIiOiIx.SflKxwRJSMeKKF"
        self.assertNotIn(jwt, hook.redact_prompt("token " + jwt))


class TestAlogReaderGuards(unittest.TestCase):
    """R4-6: alog cost/token readers must not crash on a hand-edited / junk log."""

    def test_non_string_model_degrades(self):
        self.assertEqual(alog.short_model(123), "?")
        self.assertIsNone(alog.price_for(123))
        self.assertIsNone(alog.turn_cost({"model": 123, "input_tokens": 5}))

    def test_non_numeric_tokens_do_not_crash(self):
        ev = {"model": "claude-opus-4-8", "input_tokens": float("nan"),
              "output_tokens": "oops", "cache_read_input_tokens": True}
        self.assertEqual(alog.turn_tokens(ev), 0)          # nan/str/bool -> 0
        self.assertEqual(alog.turn_cost(ev), 0.0)


class TestTranscriptSymlink(StoreTestCase):
    """R4-7: a symlinked transcript_path is refused (uniform read discipline)."""

    def _transcript(self, name):
        p = os.path.join(self.tmp, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"type": "assistant", "message": {
                "id": "m1", "model": "claude-opus-4-8",
                "usage": {"output_tokens": 9}}}) + "\n")
        return p

    def test_symlinked_transcript_refused(self):
        real = self._transcript("real.jsonl")
        link = os.path.join(self.tmp, "link.jsonl")
        os.symlink(real, link)
        hook.handle_stop(self.base, {"session_id": "s", "transcript_path": link})
        self.assertEqual([e for e in alog.load_events(self.base, "s")
                          if e.get("kind") == "turn"], [])          # refused
        # the real (non-symlink) path works
        hook.handle_stop(self.base, {"session_id": "s", "transcript_path": real})
        turns = [e for e in alog.load_events(self.base, "s") if e.get("kind") == "turn"]
        self.assertEqual([t["message_id"] for t in turns], ["m1"])

    def test_cursor_advances_after_stop(self):
        real = self._transcript("t.jsonl")
        hook.handle_stop(self.base, {"session_id": "s", "transcript_path": real})
        self.assertGreater(hook.read_cursor(self.base, "s"), 0)


class TestTier1SecurityFixes(StoreTestCase):
    """Regressions for the pre-publish adversarial review's Tier-1 findings."""

    def _blob_contains(self, needle):
        root = os.path.join(self.base, "objects")
        for dp, _, files in os.walk(root):
            for f in files:
                with open(os.path.join(dp, f), "rb") as fh:
                    if needle in fh.read():
                        return True
        return False

    def _sessions_text(self):
        import glob
        out = ""
        for f in glob.glob(os.path.join(self.base, "sessions", "*.ndjson")):
            with open(f, encoding="utf-8") as fh:
                out += fh.read()
        return out

    def test_l1_url_credential_masked_across_truncation_boundary(self):
        # L1: a URL credential whose closing '@' falls beyond the length cap used to
        # leak because truncation ran BEFORE redaction. Redact-first masks it.
        pw = "S3cr3tPassw0rd12345"
        pad = "x" * (hook.MAX_COMMAND_CHARS - len("echo ")
                     - len("https://user:") - len(pw))
        cmd = "echo " + pad + "https://user:" + pw + "@evil.example/api"
        self.assertGreater(len(cmd), hook.MAX_COMMAND_CHARS)  # '@' is past the cap
        self.assertNotIn(pw, hook.redact_command(cmd))
        # same on the prompt path
        ppad = "y" * (hook.MAX_PROMPT_CHARS - len("postgres://u:") - len(pw))
        prompt = ppad + "postgres://u:" + pw + "@h/db"
        self.assertNotIn(pw, hook.redact_prompt(prompt))

    def test_l1_url_cred_regex_is_linear(self):
        # #9: URL_CRED_RE must not backtrack quadratically on long '://'-free text
        # (it now scans the UNtruncated string). Bounded scheme run keeps it linear.
        big = "a" * 40000
        t0 = time.time()
        hook.URL_CRED_RE.sub("", big)
        self.assertLess(time.time() - t0, 1.0)

    def test_l2_content_sniff_withholds_openai_key(self):
        # L2: an OpenAI key in an innocently-named file was stored in cleartext
        # (the file sniff omitted sk- shapes the command redactor already caught).
        p = self.wf("notes.txt",
                    b"OPENAI_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD\n")
        rec = hook.snapshot_file(self.base, p, self.salt,
                                 hook.is_sensitive("notes.txt"),
                                 hook.is_sniff_exempt("notes.txt"))
        self.assertTrue(rec.get("redacted"))
        self.assertFalse(self._blob_contains(b"sk-proj-abcdefghij"))

    def test_l2_content_sniff_withholds_jwt(self):
        jwt = (b"token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
               b"abcDEFghijKLMnopQRS\n")
        p = self.wf("data.log", jwt)
        rec = hook.snapshot_file(self.base, p, self.salt,
                                 hook.is_sensitive("data.log"),
                                 hook.is_sniff_exempt("data.log"))
        self.assertTrue(rec.get("redacted"))

    def test_l2_content_sniff_withholds_quoted_config_secret(self):
        p = self.wf("config.yaml", b'db:\n  DB_PASSWORD: "hunter2secret"\n')
        rec = hook.snapshot_file(self.base, p, self.salt,
                                 hook.is_sensitive("config.yaml"),
                                 hook.is_sniff_exempt("config.yaml"))
        self.assertTrue(rec.get("redacted"))
        self.assertFalse(self._blob_contains(b"hunter2secret"))

    def test_l2_source_password_reference_still_stored(self):
        # False-positive guard: ordinary source that merely references 'password'
        # (unquoted, a function call) must stay stored so its diff survives.
        p = self.wf("app.py", b"password = get_password()\nreturn password\n")
        rec = hook.snapshot_file(self.base, p, self.salt,
                                 hook.is_sensitive("app.py"),
                                 hook.is_sniff_exempt("app.py"))
        self.assertNotIn("redacted", rec)
        self.assertTrue(self._blob_contains(b"get_password()"))

    def test_l4_symlink_not_followed_to_target_bytes(self):
        # L4: opening O_NOFOLLOW means a symlink (incl. one swapped in after a
        # classify stat) is rejected as non-regular, never read to its target.
        target = self.wf("secret_target", b"AKIA" + b"ABCDEFGHIJKLMNOP super secret\n")
        link = os.path.join(self.work, "innocent.txt")
        os.symlink(target, link)
        rec = hook.snapshot_file(self.base, link, self.salt,
                                 hook.is_sensitive("innocent.txt"),
                                 hook.is_sniff_exempt("innocent.txt"))
        self.assertEqual(rec.get("kind"), "non-regular")
        self.assertIsNone(rec.get("sha"))
        self.assertFalse(self._blob_contains(b"super secret"))

    def test_c1_stdin_text_decode_failure_does_not_crash(self):
        # C1: sys.stdin.read() decodes with the process locale; under a non-UTF-8
        # locale an ordinary non-ASCII payload raises and used to crash the hook.
        # main() now reads bytes and decodes utf-8/replace, so it fails open AND
        # still records the event.
        import sys
        payload = json.dumps({
            "hook_event_name": "UserPromptSubmit", "session_id": "s1",
            "cwd": self.work, "prompt": "このファイルを直して",
        }).encode("utf-8")

        class FakeStdin:
            def __init__(self, data):
                self.buffer = io.BytesIO(data)

            def read(self):
                raise UnicodeDecodeError("shift_jis", b"", 0, 1, "illegal multibyte")

        old_stdin = sys.stdin
        old_env = os.environ.get("ALOG_DATA")
        os.environ["ALOG_DATA"] = self.base
        try:
            sys.stdin = FakeStdin(payload)
            rc = hook.main()
        finally:
            sys.stdin = old_stdin
            if old_env is None:
                os.environ.pop("ALOG_DATA", None)
            else:
                os.environ["ALOG_DATA"] = old_env
        self.assertEqual(rc, 0)                       # did not crash
        self.assertIn('"kind": "prompt"', self._sessions_text())  # and recorded it


class TestTier234Fixes(StoreTestCase):
    """Regressions for the Tier 2/3/4 findings (audit correctness, fail-open, perf)."""

    def _run_main(self, payload):
        import sys

        class FakeStdin:
            def __init__(self, data):
                self.buffer = io.BytesIO(data)

        old_stdin = sys.stdin
        old_env = os.environ.get("ALOG_DATA")
        os.environ["ALOG_DATA"] = self.base
        try:
            sys.stdin = FakeStdin(json.dumps(payload).encode("utf-8"))
            return hook.main()
        finally:
            sys.stdin = old_stdin
            if old_env is None:
                os.environ.pop("ALOG_DATA", None)
            else:
                os.environ["ALOG_DATA"] = old_env

    # ---- Tier 3: fail-open (must never crash / silently drop) ----

    def test_t3a_non_string_event_name_no_crash(self):
        rc = self._run_main({"hook_event_name": ["PreToolUse"],  # unhashable
                             "cwd": self.work, "session_id": "s1"})
        self.assertEqual(rc, 0)

    def test_t3b_non_string_tool_name_no_crash(self):
        rc = self._run_main({"hook_event_name": "PreToolUse", "tool_name": ["Bash"],
                             "cwd": self.work, "session_id": "s1", "tool_input": {}})
        self.assertEqual(rc, 0)

    def test_t3c_non_dict_tool_input_records_event(self):
        # A non-dict tool_input used to raise .get() -> caught fail-open -> the whole
        # event silently vanished. It must be coerced and the event recorded.
        rc = self._run_main({"hook_event_name": "PostToolUse", "tool_name": "Bash",
                             "cwd": self.work, "session_id": "s1",
                             "tool_input": ["not", "a", "dict"], "tool_use_id": "x"})
        self.assertEqual(rc, 0)
        evs = hook.read_session_events(self.base, "s1")
        self.assertTrue(any(e.get("tool") == "Bash" for e in evs))

    # ---- Tier 2a: a non-UTF-8 filename must not drop the whole event ----

    def test_t2a_non_utf8_filename_keeps_whole_event(self):
        bad = "extracted\udc80name.txt"          # a lone surrogate = non-UTF-8 name
        ev = {"seq": 1, "session": "s1", "tool": "Bash", "changes": [
            {"path": bad, "status": "added"},
            {"path": "normal.txt", "status": "added"}]}
        hook._append_event(self.base, "s1", ev)
        evs = hook.read_session_events(self.base, "s1")
        self.assertEqual(len(evs), 1)             # the event survived, not dropped
        self.assertEqual(len(evs[0]["changes"]), 2)   # BOTH changes, not just the bad one lost

    # ---- Tier 2b: pop_pending correlation invariants ----

    def test_t2b_primary_id_requires_matching_tool(self):
        hook.push_pending(self.base, "s1",
                          {"id": "A", "tool": "Edit", "file_path": "f", "before": {}})
        # same id, DIFFERENT tool -> must not pair (would fabricate Bash-vs-Edit diff)
        self.assertIsNone(hook.pop_pending(self.base, "s1", "Bash", None, "A"))
        # same id + same tool -> pairs correctly
        self.assertIsNotNone(hook.pop_pending(self.base, "s1", "Edit", "f", "A"))

    def test_t2b_legacy_does_not_steal_id_tagged_pre(self):
        hook.push_pending(self.base, "s1",
                          {"id": "A", "tool": "Edit", "file_path": "f", "before": {}})
        # an id-LESS Post must not hijack an id-tracked Pre via the legacy LIFO scan
        self.assertIsNone(hook.pop_pending(self.base, "s1", "Edit", "f", None))

    # ---- Tier 2c: a concurrent Bash must not be credited as exclusive ----

    def test_t2c_concurrent_bash_change_not_exclusive(self):
        def pl(cmd="sh script"):
            return {"session_id": "s1", "tool_input": {"command": cmd}, "cwd": self.work}
        hook.handle_pre(self.base, pl(), "Bash", self.work, self.salt, "b1")
        hook.handle_pre(self.base, pl(), "Bash", self.work, self.salt, "b2")
        with open(os.path.join(self.work, "Y.txt"), "w") as fh:
            fh.write("y")
        hook.handle_post(self.base, pl(), "Bash", self.work, self.salt, "b2")
        with open(os.path.join(self.work, "X.txt"), "w") as fh:
            fh.write("x")
        hook.handle_post(self.base, pl(), "Bash", self.work, self.salt, "b1")
        evs = hook.read_session_events(self.base, "s1")
        b1 = [e for e in evs if e.get("tool_use_id") == "b1"][0]
        by_path = {c["path"]: c for c in b1["changes"]}
        # Y.txt was created by the concurrent bash2, not b1: never 'exclusive'.
        self.assertIn("Y.txt", by_path)
        self.assertNotEqual(by_path["Y.txt"].get("attribution"), "exclusive")

    # ---- Tier 2d: a Bash-created symlink is no longer invisible ----

    def test_t2d_new_symlink_visible_as_added(self):
        with open(os.path.join(self.work, "a.txt"), "w") as fh:
            fh.write("hi")
        before = hook.snapshot_tree(self.base, self.work, self.salt, "s1")
        os.symlink("/etc/hostname", os.path.join(self.work, "link"))
        after = hook.snapshot_tree(self.base, self.work, self.salt, "s1")
        ch = {c["path"]: c["status"]
              for c in hook.build_changes(before, after, True, None, True, [])}
        self.assertEqual(ch.get("link"), "added")

    def test_t2d_regular_to_symlink_is_typechange(self):
        f = os.path.join(self.work, "config")
        with open(f, "w") as fh:
            fh.write("real")
        before = hook.snapshot_tree(self.base, self.work, self.salt, "s2")
        os.remove(f)
        os.symlink("/etc/hostname", f)
        after = hook.snapshot_tree(self.base, self.work, self.salt, "s2")
        ch = {c["path"]: c["status"]
              for c in hook.build_changes(before, after, True, None, True, [])}
        self.assertEqual(ch.get("config"), "typechange")   # not a fabricated 'deleted'

    def test_t2d_stable_symlink_not_noisy_typechange(self):
        # A symlink that does NOT change must read as unchanged, not typechange on
        # every Bash call (that would be constant noise in a repo with symlinks).
        os.symlink("/etc/hostname", os.path.join(self.work, "stable"))
        before = hook.snapshot_tree(self.base, self.work, self.salt, "s3")
        after = hook.snapshot_tree(self.base, self.work, self.salt, "s3")
        ch = {c["path"]: c["status"]
              for c in hook.build_changes(before, after, True, None, True, [])}
        self.assertEqual(ch.get("stable"), "read")


class TestTier5678Fixes(StoreTestCase):
    """Regressions for the Tier 5/6/7/8 findings (packaging, hygiene, quality, injection)."""

    # ---- Tier 5: SubagentStop must be wired in the shipped snippet ----

    def test_t5a_subagentstop_wired_in_settings_snippet(self):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(repo_root, "settings-snippet.json"), encoding="utf-8") as fh:
            snippet = json.load(fh)
        self.assertIn("SubagentStop", snippet["hooks"])
        self.assertIn("SubagentStop", hook.NONTOOL_EVENTS)  # and the hook handles it

    # ---- Tier 6a: token counts clamp to non-negative ----

    def test_t6a_negative_token_clamped_to_zero(self):
        self.assertEqual(hook._tok_int({"k": -5}, "k"), 0)      # would invert cost
        self.assertEqual(hook._tok_int({"k": -1.0}, "k"), 0)
        self.assertEqual(hook._tok_int({"k": 12}, "k"), 12)

    # ---- Tier 6b: write paths self-heal loosened permissions ----

    def test_t6b_log_permissions_self_heal(self):
        hook._append_event(self.base, "s", {"seq": 1, "changes": []})
        log = hook.session_file(self.base, "s")
        os.chmod(log, 0o644)                                    # loosen it
        hook._append_event(self.base, "s", {"seq": 2, "changes": []})  # heals on next write
        self.assertEqual(os.stat(log).st_mode & 0o077, 0, "log must re-tighten to 0600")

    def test_t6b_cursor_permissions_self_heal(self):
        hook.write_cursor(self.base, "s", 10)
        cur = hook._cursor_path(self.base, "s")
        os.chmod(cur, 0o644)
        hook.write_cursor(self.base, "s", 20)
        self.assertEqual(os.stat(cur).st_mode & 0o077, 0)

    # ---- Tier 7a: prose with trailing punctuation is not over-masked ----

    def test_t7a_prose_trailing_punctuation_survives(self):
        self.assertEqual(hook.redact_prompt("auth: yes."), "auth: yes.")
        self.assertEqual(hook.redact_prompt("the token: economics,"),
                         "the token: economics,")
        # real key material is still masked
        self.assertNotIn("aB3xK9mZ1qW8vT2p0",
                         hook.redact_prompt("api_key: aB3xK9mZ1qW8vT2p0"))

    # ---- Tier 8: terminal control characters are neutralised in output ----

    def test_t8_safe_strips_terminal_control_chars(self):
        self.assertNotIn("\x1b", alog._safe("x\x1b[31mRED\x1b[0m"))   # ANSI colour
        self.assertNotIn("\r", alog._safe("overwrite\rme"))          # carriage return
        self.assertNotIn("\x07", alog._safe("bell\x07"))             # BEL
        self.assertEqual(alog._safe("normal/path-1.txt"), "normal/path-1.txt")
        self.assertEqual(alog._safe("keep\ttab\nnl"), "keep\ttab\nnl")  # \t,\n kept

    def test_t8_show_output_has_no_escape_from_crafted_path(self):
        # A change whose path carries an ANSI escape must not reach the terminal raw.
        ev = {"seq": 1, "session": "s", "tool": "Write",
              "file_path": "eviltxt", "had_before": True,
              "changes": [{"path": "evil\x1b[2Jname.txt", "status": "added",
                           "before": None, "after": None, "sensitive": False}]}
        hook._append_event(self.base, "s", ev)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            alog.cmd_show(self.base, "s", False)
        self.assertNotIn("\x1b", buf.getvalue())


class TestPostFixReviewFindings(StoreTestCase):
    """Regressions for the 13 findings of the post-Tier1-8 adversarial review
    (wf_0fb5088b). Each test targets one finding and was confirmed to FAIL on the
    pre-fix d409f8a code before the corresponding fix landed."""

    # ---- Finding 1 (HIGH): in-worktree store is never self-snapshotted ----

    def test_f1_in_worktree_store_not_walked(self):
        # ALOG_DATA inside the worktree under a NON-'.alog' name must be pruned from
        # the tree walk by its real path, so its 'salt' never lands in the CAS (a
        # readable salt turns every 'S:' digest into a known-salt offline oracle).
        store = os.path.join(self.work, "audit")     # not named '.alog'
        hook.ensure_dirs(store)
        salt = hook.get_salt(store)
        self.wf("app.py", b"print('hi')\n")
        paths = hook.walk_worktree(self.work, store)
        rels = {hook.rel_to_cwd(self.work, p) for p in paths}
        self.assertIn("app.py", rels)
        self.assertFalse(any(r.startswith("audit/") or r.startswith("audit" + os.sep)
                             for r in rels), "the store dir must not be walked")
        # end-to-end: the salt's bytes must not be stored as a CAS object
        snap = hook.snapshot_tree(store, self.work, salt, "s1")
        self.assertNotIn("audit/salt", snap)
        salt_sha = sha(salt)
        obj = os.path.join(store, "objects", salt_sha[:2], salt_sha)
        self.assertFalse(os.path.exists(obj), "salt must never be a plaintext CAS blob")

    # ---- Finding 2: full-content sniff (secret past the first 4 KiB) ----

    def test_f2_secret_deep_in_file_is_withheld(self):
        # A non-sensitively-NAMED file with an AWS key well past 4096 bytes must be
        # recorded as a salted digest, not stored in cleartext.
        content = b"# log\n" + b"x" * 5000 + b"\nAKIAIOSFODNN7EXAMPLE\n"
        p = self.wf("app.log", content)
        rec = hook.snapshot_file(self.base, p, self.salt, hook.is_sensitive("app.log"),
                                 hook.is_sniff_exempt("app.log"))
        self.assertTrue(rec.get("redacted"))
        self.assertTrue(str(rec.get("sha")).startswith("S:"))
        # and the cleartext key is not anywhere in the object store
        for root, _dirs, files in os.walk(os.path.join(self.base, "objects")):
            for f in files:
                with open(os.path.join(root, f), "rb") as fh:
                    self.assertNotIn(b"AKIAIOSFODNN7EXAMPLE", fh.read())

    def test_f2_clean_large_file_still_stored(self):
        # A big innocuous file must still be stored (not over-withheld).
        p = self.wf("data.txt", b"y" * 9000)
        rec = hook.snapshot_file(self.base, p, self.salt, False, False)
        self.assertFalse(rec.get("redacted"))
        self.assertFalse(str(rec.get("sha")).startswith("S:"))

    # ---- Finding 3: .pub name only exempt when content is really public ----

    def test_f3_pub_named_secret_is_withheld(self):
        p = self.wf("config.pub", b"sk_live_" + b"0123456789abcdef0123456789ABCD\n")
        rec = hook.snapshot_file(self.base, p, self.salt, hook.is_sensitive("config.pub"),
                                 hook.is_sniff_exempt("config.pub"))
        self.assertTrue(rec.get("redacted"), "a .pub holding a token must NOT be exempt")

    def test_f3_real_pubkey_still_stored(self):
        p = self.wf("id_ed25519.pub", b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 user@host\n")
        rec = hook.snapshot_file(self.base, p, self.salt,
                                 hook.is_sensitive("id_ed25519.pub"),
                                 hook.is_sniff_exempt("id_ed25519.pub"))
        self.assertFalse(rec.get("redacted"), "a genuine public key stays storable")

    # ---- Finding 4: a truncated salt is healed, never returned short ----

    def test_f4_zero_byte_salt_is_healed(self):
        base = os.path.join(self.tmp, "store4")
        hook.ensure_dirs(base)
        salt_path = os.path.join(base, "salt")
        with open(salt_path, "wb"):
            pass                                     # a 0-byte salt (dead writer)
        self.assertEqual(os.path.getsize(salt_path), 0)
        got = hook.get_salt(base)
        self.assertGreaterEqual(len(got), 16, "must never return a <16-byte salt")
        self.assertGreaterEqual(os.path.getsize(salt_path), 16, "the file is healed")
        # a healed salt yields a genuinely salted (non-sha256(content)) digest
        digest = hook.sensitive_digest(got, b"secret")
        self.assertNotEqual(digest, hook.sensitive_digest(b"", b"secret"))

    # ---- Finding 5: a repointed symlink surfaces as 'modified', not 'read' ----

    def test_f5_symlink_repoint_is_modified(self):
        link = os.path.join(self.work, "link")
        os.symlink("./safe.txt", link)
        before = hook.snapshot_tree(self.base, self.work, self.salt, "s5")
        os.remove(link)
        os.symlink("/etc/shadow", link)              # repoint, still a symlink
        after = hook.snapshot_tree(self.base, self.work, self.salt, "s5")
        ch = {c["path"]: c["status"]
              for c in hook.build_changes(before, after, True, None, True, [])}
        self.assertEqual(ch.get("link"), "modified",
                         "a symlink retarget must not hide as an unchanged 'read'")

    def test_f5_records_link_target(self):
        link = os.path.join(self.work, "l")
        os.symlink("/etc/hostname", link)
        rec = hook.snapshot_file(self.base, link, self.salt, False, False)
        self.assertEqual(rec.get("kind"), "non-regular")
        self.assertEqual(rec.get("link_target"), "/etc/hostname")

    # ---- Finding 6: a concurrent Read cannot claim a Bash write ----

    def test_f6_concurrent_read_does_not_claim_bash_write(self):
        def bash_pl(cmd="sh w.sh"):
            return {"session_id": "s6", "tool_input": {"command": cmd}, "cwd": self.work}
        read_pl = {"session_id": "s6", "tool_input": {"file_path": "foo.py"},
                   "cwd": self.work}
        hook.handle_pre(self.base, bash_pl(), "Bash", self.work, self.salt, "b1")
        # a Read of foo.py posts INSIDE the bash window (Pre+Post)
        hook.handle_pre(self.base, read_pl, "Read", self.work, self.salt, "r1")
        hook.handle_post(self.base, read_pl, "Read", self.work, self.salt, "r1")
        with open(os.path.join(self.work, "foo.py"), "w") as fh:
            fh.write("changed")                      # the Bash genuinely writes foo.py
        hook.handle_post(self.base, bash_pl(), "Bash", self.work, self.salt, "b1")
        evs = hook.read_session_events(self.base, "s6")
        b1 = [e for e in evs if e.get("tool_use_id") == "b1"][0]
        foo = {c["path"]: c for c in b1["changes"]}.get("foo.py")
        self.assertIsNotNone(foo)
        self.assertNotEqual(foo.get("attribution"), "claimed_by_concurrent",
                            "a read-only tool must not disown the Bash write")

    # ---- Finding 7: a deleted process cwd + missing payload cwd fails open ----

    def test_f7_getcwd_failure_fails_open(self):
        import sys

        class FakeStdin:
            def __init__(self, data):
                self.buffer = io.BytesIO(data)

        # payload has NO cwd; force os.getcwd() to raise as if the cwd was deleted.
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Read",
                   "session_id": "s7", "tool_input": {"file_path": "x"}}
        old_stdin, old_getcwd = sys.stdin, os.getcwd
        old_env = os.environ.get("ALOG_DATA")
        os.environ["ALOG_DATA"] = self.base
        try:
            sys.stdin = FakeStdin(json.dumps(payload).encode("utf-8"))
            os.getcwd = lambda: (_ for _ in ()).throw(FileNotFoundError("cwd gone"))
            self.assertEqual(hook.main(), 0, "must return 0, not crash")
        finally:
            sys.stdin, os.getcwd = old_stdin, old_getcwd
            if old_env is None:
                os.environ.pop("ALOG_DATA", None)
            else:
                os.environ["ALOG_DATA"] = old_env

    # ---- Finding 8: a shrunk transcript resets the cursor (no stranding) ----

    def test_f8_shrunk_transcript_resets_offset(self):
        p = os.path.join(self.tmp, "t.jsonl")
        line = json.dumps({"type": "assistant", "message": {
            "id": "m1", "model": "claude-opus-4-8", "usage": {"output_tokens": 5}}}) + "\n"
        with open(p, "w") as fh:
            fh.write(line)
        # a stale cursor far beyond the (now short) file: must not seek past EOF and
        # freeze -- it resets to 0 and re-reads the turn.
        turns, off = hook.parse_transcript_turns(p, 10_000)
        self.assertEqual(len(turns), 1)
        self.assertEqual(turns[0]["message_id"], "m1")
        self.assertLessEqual(off, os.path.getsize(p))

    # ---- Finding 9: handle_stop still records turns (parse moved off-lock) ----

    def test_f9_handle_stop_records_turns_outside_lock(self):
        p = os.path.join(self.tmp, "t9.jsonl")
        with open(p, "w") as fh:
            fh.write(json.dumps({"type": "assistant", "message": {
                "id": "mm", "model": "claude-haiku-4-5",
                "usage": {"input_tokens": 3, "output_tokens": 7}}}) + "\n")
        hook.handle_stop(self.base, {"session_id": "s9", "transcript_path": p})
        turns = [e for e in hook.read_session_events(self.base, "s9")
                 if e.get("kind") == "turn"]
        self.assertEqual(len(turns), 1)
        self.assertEqual(turns[0]["message_id"], "mm")

    # ---- Finding 10: a newline in a path cannot forge a timeline line ----

    def test_f10_newline_in_path_cannot_forge_line(self):
        forged = "notes.txt\n          A prod.env  ⚠ sensitive"
        ev = {"seq": 1, "session": "s", "tool": "Write", "file_path": "notes.txt",
              "had_before": True, "changes": [
                  {"path": forged, "status": "added", "before": None, "after": None,
                   "sensitive": False}]}
        hook._append_event(self.base, "s", ev)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            alog.cmd_show(self.base, "s", False)
        # the forged content stays on ONE physical line (no injected second line)
        change_lines = [ln for ln in buf.getvalue().splitlines() if "prod.env" in ln]
        self.assertTrue(change_lines)
        for ln in change_lines:
            self.assertIn("notes.txt", ln, "the path must not be split across lines")

    def test_f10_safe_inline_collapses_newlines(self):
        self.assertNotIn("\n", alog._safe_inline("a\nb"))
        self.assertNotIn("\r", alog._safe_inline("a\rb"))

    # ---- Finding 11: cmd_cost sanitizes the model name ----

    def test_f11_cost_sanitizes_model(self):
        for mid in ("m1", "m2"):
            hook._append_event(self.base, "s", {
                "seq": 1, "session": "s", "kind": "turn", "message_id": mid,
                "model": "claude-opus\x1b[31m", "input_tokens": 1, "output_tokens": 1,
                "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            alog.cmd_cost(self.base, "s")
        self.assertNotIn("\x1b", buf.getvalue())

    # ---- Finding 12: the empty-state hint names the real settings file ----

    def test_f12_cost_empty_hint_names_real_file(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            alog.cmd_cost(self.base, "s-none")       # no turn events
        out = buf.getvalue()
        self.assertIn("settings-snippet.json", out)
        self.assertNotIn("settings.example.json", out)
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.assertTrue(os.path.exists(os.path.join(repo_root, "settings-snippet.json")))

    # ---- Finding 13: a sensitive file is not double-counted ----

    def test_f13_no_double_count_relative_token(self):
        # './.env' in a command + the change record for '.env' must count ONCE.
        self.wf(".env", b"SECRET=x\n")
        pl = {"session_id": "s13", "tool_input": {"command": "cat ./.env >> ./.env"},
              "cwd": self.work}
        hook.handle_pre(self.base, pl, "Bash", self.work, self.salt, "c1")
        with open(os.path.join(self.work, ".env"), "a") as fh:
            fh.write("MORE=y\n")
        hook.handle_post(self.base, pl, "Bash", self.work, self.salt, "c1")
        evs = hook.read_session_events(self.base, "s13")
        ev = [e for e in evs if e.get("tool_use_id") == "c1"][0]
        # the command-ref marker is normalized to '.env' (matches the change path)
        self.assertIn(".env", ev.get("cmd_sensitive", []))
        self.assertNotIn("./.env", ev.get("cmd_sensitive", []))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            alog.cmd_audit(self.base, "s13", False)
        out = buf.getvalue()
        # exactly one sensitive access for the single file (not 2)
        self.assertIn("1 sensitive access(es)", out)


class TestSecondReviewFindings(StoreTestCase):
    """Regressions for the SECOND adversarial review (wf_f76ad071). Several of these
    target defects introduced by the first-pass fixes; each was confirmed to FAIL on
    the d2dd10c code before the corresponding fix landed."""

    # ---- R1 (CRITICAL): appended secret in a .pub is still withheld ----

    def test_r1_pub_head_appended_token_withheld(self):
        body = (b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexamplekey comment\n"
                + b"# note\n" + b"AKIAIOSFODNN7EXAMPLE0\n")
        p = self.wf("deploy.pub", body)
        rec = hook.snapshot_file(self.base, p, self.salt, hook.is_sensitive("deploy.pub"),
                                 hook.is_sniff_exempt("deploy.pub"))
        self.assertTrue(rec.get("redacted"),
                        "an AWS key appended after a public key head must be withheld")
        for root, _d, files in os.walk(os.path.join(self.base, "objects")):
            for f in files:
                with open(os.path.join(root, f), "rb") as fh:
                    self.assertNotIn(b"AKIAIOSFODNN7EXAMPLE0", fh.read())

    def test_r1_genuine_pubkey_still_stored(self):
        p = self.wf("ok.pub", b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIcleankey user@h\n")
        rec = hook.snapshot_file(self.base, p, self.salt, hook.is_sensitive("ok.pub"),
                                 hook.is_sniff_exempt("ok.pub"))
        self.assertFalse(rec.get("redacted"), "a clean public key is still storable")

    # ---- R2: Google AIza key covered by sniff + redaction ----

    def test_r2_google_key_withheld_at_rest(self):
        key = b"AIza" + b"b" * 35
        p = self.wf("notes.txt", b"google_key " + key + b"\n")
        rec = hook.snapshot_file(self.base, p, self.salt, False, False)
        self.assertTrue(rec.get("redacted"))

    def test_r2_google_key_redacted_in_command(self):
        key = "AIza" + "b" * 35
        out = hook.redact_command("curl https://api?key=" + key)
        self.assertNotIn(key, out)
        self.assertIn("<redacted>", out)

    # ---- R3 (HIGH): content-sniffed secret surfaces in the audit view ----

    def test_r3_content_secret_shows_in_audit(self):
        self.wf("notes.txt", b"token ghp_" + b"a" * 30 + b"\n")
        pl = {"session_id": "s3", "tool_input": {"file_path": "notes.txt"}, "cwd": self.work}
        hook.handle_pre(self.base, pl, "Read", self.work, self.salt, "r1")
        hook.handle_post(self.base, pl, "Read", self.work, self.salt, "r1")
        ev = [e for e in hook.read_session_events(self.base, "s3")
              if e.get("tool_use_id") == "r1"][0]
        ch = ev["changes"][0]
        self.assertTrue(ch.get("redacted"))
        # name is innocuous, but the `sensitive` field now ORs in `redacted` (W4) so
        # it is consistent with the withhold decision.
        self.assertTrue(ch.get("sensitive"))
        self.assertTrue(alog.is_agent_sensitive(ev, ch), "a read secret must count")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = alog.cmd_audit(self.base, "s3", False, fail_on_hit=True)
        self.assertNotIn("(none)", buf.getvalue())
        self.assertEqual(rc, 2, "--fail-on-hit must trip on a content-sniffed secret")

    # ---- R4 (HIGH): a concurrent Bash's whole-tree 'read' must not claim a write ----

    def test_r4_concurrent_bash_read_does_not_claim_write(self):
        self.wf(".env", b"SECRET=v0\n")
        self.wf("y.txt", b"y0\n")

        def pl(cmd="sh s"):
            return {"session_id": "s4", "tool_input": {"command": cmd}, "cwd": self.work}
        hook.handle_pre(self.base, pl(), "Bash", self.work, self.salt, "A")   # window opens
        hook.handle_pre(self.base, pl(), "Bash", self.work, self.salt, "B")
        with open(os.path.join(self.work, "y.txt"), "w") as fh:
            fh.write("y1\n")                       # B modifies only y.txt (observes .env)
        hook.handle_post(self.base, pl(), "Bash", self.work, self.salt, "B")
        with open(os.path.join(self.work, ".env"), "w") as fh:
            fh.write("SECRET=v1\n")                # A genuinely rewrites .env
        hook.handle_post(self.base, pl(), "Bash", self.work, self.salt, "A")
        evs = hook.read_session_events(self.base, "s4")
        a = [e for e in evs if e.get("tool_use_id") == "A"][0]
        env = {c["path"]: c for c in a["changes"]}.get(".env")
        self.assertEqual(env.get("status"), "modified")
        # A genuine concurrent Bash can never PROVE it authored a path (its whole-tree
        # diff only shows the tree changed), so it never claims: A's real .env write
        # must not be disowned via 'claimed_by_concurrent'. Honest outcome is
        # 'ambiguous' (see test_f3_concurrent_bash_write_interleave for the harder
        # interleaving that the earlier read-only gate missed).
        self.assertNotEqual(env.get("attribution"), "claimed_by_concurrent")

    # ---- R5: a relative cwd + deleted process cwd fails open ----

    def test_r5_relative_cwd_getcwd_failure_fails_open(self):
        import sys

        class FakeStdin:
            def __init__(self, data):
                self.buffer = io.BytesIO(data)

        payload = {"hook_event_name": "PreToolUse", "tool_name": "Read",
                   "session_id": "s5", "tool_input": {"file_path": "x"},
                   "cwd": "some/relative/dir"}          # RELATIVE -> abspath calls getcwd
        old_stdin, old_getcwd = sys.stdin, os.getcwd
        old_env = os.environ.get("ALOG_DATA")
        os.environ["ALOG_DATA"] = self.base
        try:
            sys.stdin = FakeStdin(json.dumps(payload).encode("utf-8"))
            os.getcwd = lambda: (_ for _ in ()).throw(FileNotFoundError("cwd gone"))
            self.assertEqual(hook.main(), 0)
        finally:
            sys.stdin, os.getcwd = old_stdin, old_getcwd
            if old_env is None:
                os.environ.pop("ALOG_DATA", None)
            else:
                os.environ["ALOG_DATA"] = old_env

    # ---- R6: corrupt token fields don't crash the reader ----

    def test_r6_render_and_cost_tolerate_corrupt_tokens(self):
        ev = {"seq": 1, "session": "s", "kind": "turn", "message_id": "m",
              "model": "claude-opus-4-8", "input_tokens": float("inf"),
              "output_tokens": float("nan"), "cache_read_input_tokens": "x",
              "cache_creation_input_tokens": 0}
        hook._append_event(self.base, "s6", ev)
        for fn in (lambda: alog.cmd_show(self.base, "s6", False),
                   lambda: alog.cmd_cost(self.base, "s6")):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(fn(), 0)            # renders, does not raise

    # ---- R7: a crafted session id can't inject terminal escapes ----

    def test_r7_session_id_sanitized_in_output(self):
        evil = "evil\x1b[31mX"
        hook._append_event(self.base, evil, {"seq": 1, "session": evil, "changes": []})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            alog.cmd_sessions(self.base)
        self.assertNotIn("\x1b", buf.getvalue())
        self.assertNotIn("\x1b", alog.sess_tag({"session": evil}, True))

    # ---- R8: a malformed session id never aborts all recording ----

    def test_r8_non_string_session_id_no_raise(self):
        self.assertEqual(hook._safe_session(12345), hook._safe_session(12345))  # stable
        self.assertTrue(hook._safe_session([1, 2]))                            # no raise
        self.assertTrue(hook._safe_session("\ud800abc"))                       # surrogate

    def test_r8_int_session_records_events(self):
        pl = {"session_id": 777, "tool_input": {"command": "echo hi"}, "cwd": self.work}
        hook.handle_pre(self.base, pl, "Bash", self.work, self.salt, "x")
        hook.handle_post(self.base, pl, "Bash", self.work, self.salt, "x")
        evs = hook.read_session_events(self.base, 777)
        self.assertTrue(any(e.get("tool") == "Bash" for e in evs))

    # ---- R9: packaging nits ----

    def test_r9_sdist_includes_contributing(self):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(repo_root, "pyproject.toml"), encoding="utf-8") as fh:
            txt = fh.read()
        self.assertIn("CONTRIBUTING.md", txt)

    def test_r9_readme_has_no_invalid_runpip(self):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(repo_root, "README.md"), encoding="utf-8") as fh:
            self.assertNotIn("runpip", fh.read())


class TestThirdReviewFindings(StoreTestCase):
    """Regressions for the THIRD adversarial review (wf_509fbd2a). Includes the
    completion of the R4 concurrent-Bash fix and the R8 injectivity regression; each
    was confirmed to FAIL on the pre-fix tree before its fix landed."""

    # ---- F1 (MUST): URL/connection-string creds in file content withheld ----

    def test_f1_url_cred_in_file_withheld(self):
        p = self.wf("database.yml",
                    b"prod:\n  url: postgres://appuser:Sup3rSecretDbPass@db.internal:5432/prod\n")
        rec = hook.snapshot_file(self.base, p, self.salt, False, False)
        self.assertTrue(rec.get("redacted"), "a connection-string password must not be stored")
        for root, _d, files in os.walk(os.path.join(self.base, "objects")):
            for f in files:
                with open(os.path.join(root, f), "rb") as fh:
                    self.assertNotIn(b"Sup3rSecretDbPass", fh.read())

    def test_f1_plain_url_still_stored(self):
        p = self.wf("readme.md", b"see https://example.com/docs for details\n")
        rec = hook.snapshot_file(self.base, p, self.salt, False, False)
        self.assertFalse(rec.get("redacted"))    # no user:pass@ -> not a credential

    # ---- F2: URL_CRED_RE masks a whole @/:-bearing password ----

    def test_f2_url_password_with_at_fully_masked(self):
        out = hook.redact_command("mongodb+srv://admin:MyP@ssw0rd@cluster0.mongodb.net/db")
        self.assertNotIn("ssw0rd", out)          # the tail after the inner '@' too
        self.assertIn("<redacted>", out)
        self.assertIn("@cluster0.mongodb.net", out)   # host preserved

    def test_f2_url_password_with_colon_masked(self):
        out = hook.redact_command("redis://user:pa:ss@host:6379")
        self.assertNotIn("pa:ss", out)
        self.assertIn("<redacted>", out)

    # ---- F3 (HIGH): complete the R4 fix -- a concurrent Bash never claims ----

    def test_f3_concurrent_bash_write_interleave(self):
        # The harder interleaving the read-only gate missed: A writes .env BEFORE
        # B-Post, so B records .env as 'modified' (an authored status). A concurrent
        # Bash still cannot prove it authored .env, so A's real write must NOT be
        # stamped claimed_by_concurrent.
        self.wf(".env", b"SECRET=v0\n")

        def pl(cmd="sh s"):
            return {"session_id": "s3b", "tool_input": {"command": cmd}, "cwd": self.work}
        hook.handle_pre(self.base, pl(), "Bash", self.work, self.salt, "A")
        hook.handle_pre(self.base, pl(), "Bash", self.work, self.salt, "B")
        with open(os.path.join(self.work, ".env"), "w") as fh:
            fh.write("SECRET=v1\n")               # A is the real author
        hook.handle_post(self.base, pl(), "Bash", self.work, self.salt, "B")  # B sees .env modified
        hook.handle_post(self.base, pl(), "Bash", self.work, self.salt, "A")
        a = [e for e in hook.read_session_events(self.base, "s3b")
             if e.get("tool_use_id") == "A"][0]
        env = {c["path"]: c for c in a["changes"]}.get(".env")
        self.assertEqual(env.get("status"), "modified")
        self.assertNotEqual(env.get("attribution"), "claimed_by_concurrent",
                            "a concurrent Bash's own 'modified' diff is not authorship proof")

    # ---- F4: nseq boundary captured before the snapshot ----

    def test_f4_event_posted_during_snapshot_is_in_window(self):
        # Inject a concurrent single-file Post DURING the Bash before-snapshot. Its
        # seq must fall inside the Bash's overlap window (claimed_by_concurrent), which
        # only holds if nseq_at_pre was captured BEFORE the snapshot (not after).
        self.wf("shared.txt", b"v0\n")
        orig = hook._snapshot
        state = {"injected": False}

        def spy(base, tool, ti, cwd, salt, session):
            if tool == "Bash" and not state["injected"]:
                state["injected"] = True
                hook._append_event(base, session, {
                    "seq": hook.next_seq(base, session), "session": session,
                    "tool": "Edit", "tool_use_id": "e1", "file_path": "shared.txt",
                    # sensitive Edit change whose FINAL state matches the Bash's after
                    # (sha of "v1\n"), so the claim fires: a claim requires same-final-
                    # state + sensitive (W3 + digest-match gates).
                    "changes": [{"path": "shared.txt", "status": "modified",
                                 "sensitive": True, "redacted": True,
                                 "after": sha(b"v1\n")}]})
            return orig(base, tool, ti, cwd, salt, session)

        pl = {"session_id": "s4b", "tool_input": {"command": "sh s"}, "cwd": self.work}
        hook._snapshot = spy
        try:
            hook.handle_pre(self.base, pl, "Bash", self.work, self.salt, "A")
        finally:
            hook._snapshot = orig
        with open(os.path.join(self.work, "shared.txt"), "w") as fh:
            fh.write("v1\n")                       # A modifies the same path
        hook.handle_post(self.base, pl, "Bash", self.work, self.salt, "A")
        a = [e for e in hook.read_session_events(self.base, "s4b")
             if e.get("tool_use_id") == "A"][0]
        sh = {c["path"]: c for c in a["changes"]}.get("shared.txt")
        self.assertEqual(sh.get("attribution"), "claimed_by_concurrent",
                         "an Edit posted during the snapshot must be inside the window")

    # ---- F5: skip-dir blind spot documented ----

    def test_f5_skip_dir_limitation_documented(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "README.md"), encoding="utf-8") as fh:
            self.assertIn(".git/hooks", fh.read())
        with open(os.path.join(root, "hook.py"), encoding="utf-8") as fh:
            self.assertIn("KNOWN LIMITATION", fh.read())

    # ---- F6: a non-ValueError json error fails open ----

    def test_f6_recursionerror_payload_fails_open(self):
        import sys

        class FakeStdin:
            def __init__(self, d):
                self.buffer = io.BytesIO(d)

        real_loads = hook.json.loads

        def boom(*a, **k):
            raise RecursionError("too deep")
        old_stdin = sys.stdin
        try:
            sys.stdin = FakeStdin(b'{"hook_event_name":"PreToolUse"}')
            hook.json.loads = boom
            self.assertEqual(hook.main(), 0)       # must not propagate RecursionError
        finally:
            sys.stdin = old_stdin
            hook.json.loads = real_loads

    # ---- F7: _write_stack removes its tmp on write failure ----

    def test_f7_write_stack_cleans_tmp_on_failure(self):
        path = hook.pending_path(self.base, "s7")
        with self.assertRaises(TypeError):
            hook._write_stack(path, [{"bad": {1, 2, 3}}])   # a set is not JSON-serializable
        self.assertFalse(os.path.exists(path + ".tmp"), "no stray .tmp left behind")

    # ---- F8: cmd_audit tolerates a missing tool + sanitizes it ----

    def test_f8_cmd_audit_missing_tool_no_crash(self):
        hook._append_event(self.base, "s8", {
            "seq": 1, "session": "s8", "changes": [
                {"status": "read", "sensitive": True, "path": ".env"}]})   # no 'tool'
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = alog.cmd_audit(self.base, "s8", False, fail_on_hit=True)
        self.assertEqual(rc, 2)                    # the access is reported, no crash
        self.assertIn(".env", buf.getvalue())

    def test_f8_crafted_tool_name_sanitized(self):
        ev = {"seq": 1, "session": "s8b", "tool": "Bash\x1b[2m", "had_before": True,
              "file_path": "x", "changes": [
                  {"path": "y", "status": "added", "sensitive": False}]}
        hook._append_event(self.base, "s8b", ev)
        for fn in (lambda: alog.cmd_show(self.base, "s8b", False),
                   lambda: alog.cmd_audit(self.base, "s8b", False)):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                fn()
            self.assertNotIn("\x1b", buf.getvalue())

    # ---- F9: load_events survives a non-numeric ts/seq ----

    def test_f9_corrupt_ts_does_not_brick_reader(self):
        path = hook.session_file(self.base, "s9")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"seq": 1, "session": "s9", "ts": 1.0, "tool": "Read",
                                 "changes": []}) + "\n")
            fh.write(json.dumps({"seq": "BAD", "session": "s9", "ts": "BAD",
                                 "tool": "Read", "changes": []}) + "\n")
        evs = alog.load_events(self.base, "s9")    # must not raise TypeError on sort
        self.assertEqual(len(evs), 2)

    # ---- F10: size fields sanitized ----

    def test_f10_size_fields_sanitized(self):
        ev = {"seq": 1, "session": "s10", "tool": "Write", "had_before": True,
              "file_path": "big", "changes": [
                  {"path": "big", "status": "modified", "large": True,
                   "before_size": "0\x1b[31m", "after_size": 1,
                   "before": None, "after": None, "sensitive": False}]}
        hook._append_event(self.base, "s10", ev)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            alog.cmd_show(self.base, "s10", False)
        self.assertNotIn("\x1b", buf.getvalue())

    # ---- F11: is_allowlisted docstring no longer claims it skips the sniff ----

    def test_f11_is_allowlisted_docstring_corrected(self):
        doc = hook.is_allowlisted.__doc__ or ""
        self.assertNotIn("SKIP the content sniff", doc)
        self.assertIn("is_sniff_exempt", doc)

    # ---- F12: reader _num clamps negatives ----

    def test_f12_num_clamps_negative(self):
        self.assertEqual(alog._num(-5), 0)
        self.assertEqual(alog._num(-1.0), 0)
        self.assertEqual(alog.turn_tokens({"input_tokens": -500, "output_tokens": 10}), 10)

    # ---- F13: int and str session ids never collide ----

    def test_f13_int_and_str_session_distinct(self):
        self.assertNotEqual(hook._safe_session(1), hook._safe_session("1"))
        self.assertEqual(hook._safe_session(1), hook._safe_session(1))   # still stable


class TestScopeOneFixes(StoreTestCase):
    """Regressions for the 3-way (Workflow + Codex + AGY) fourth-review fixes."""

    def _withheld(self, name, body):
        p = self.wf(name, body)
        rec = hook.snapshot_file(self.base, p, self.salt, hook.is_sensitive(name),
                                 hook.is_sniff_exempt(name))
        return bool(rec.get("redacted"))

    # ---- L1: GitHub token family ----
    def test_l1_github_token_family_withheld(self):
        for pfx in (b"gho_", b"ghu_", b"ghs_", b"ghr_"):
            self.assertTrue(self._withheld("notes.txt", b"tok " + pfx + b"A" * 30),
                            "{0} must be withheld".format(pfx))
        self.assertNotIn("ghs_" + "A" * 30,
                         hook.redact_command("gh auth ghs_" + "A" * 30))

    # ---- L2: Slack app/config tokens ----
    def test_l2_slack_app_config_tokens_withheld(self):
        self.assertTrue(self._withheld("n.txt", b"xapp-1-" + b"A" * 20))
        self.assertTrue(self._withheld("n.txt", b"xoxe-" + b"A" * 24))

    # ---- L3: unquoted config secret withheld; placeholder / call NOT ----
    def test_l3_unquoted_config_secret_withheld(self):
        self.assertTrue(self._withheld("config.yaml", b"database:\n  password: swordfish\n"))
        self.assertTrue(self._withheld("app.properties", b"api_key=supersecret123\n"))
        self.assertTrue(self._withheld(".envrc", b"export DEPLOY_CREDENTIAL=hunter2xyz\n"))

    def test_l3_call_not_withheld_template_now_withheld(self):
        # `password = get_secret()` source is still spared (function-call guard).
        self.assertFalse(self._withheld("app.py", b"password = get_secret()\n"))
        # The placeholder exemption was REMOVED (it kept leaking real secrets), so a
        # template with a KEY=value placeholder is now WITHHELD -- fail-safe.
        self.assertTrue(self._withheld(".env.example", b"API_KEY=replace_me_example\n"))

    # ---- L4: symlink target redacted ----
    def test_l4_symlink_target_redacted(self):
        link = os.path.join(self.work, "l")
        os.symlink("postgres://alice:hunter2secret@db/prod", link)
        rec = hook.snapshot_file(self.base, link, self.salt, False, False)
        self.assertIn("<redacted>", rec.get("link_target", ""))
        self.assertNotIn("hunter2secret", rec.get("link_target", ""))

    # ---- L5: flag / short-flag credential redaction ----
    def test_l5_multispace_and_short_flags(self):
        self.assertNotIn("hunter2", hook.redact_command("deploy --password    hunter2"))
        self.assertNotIn("hunter2", hook.redact_command("sshpass -p hunter2 ssh host"))
        self.assertNotIn("hunter2", hook.redact_command("curl -u alice:hunter2 https://x"))

    # ---- A1: a real Bash secret write is never disowned by an orphan Pre ----
    def test_a1_orphan_pre_does_not_disown_bash_secret_write(self):
        self.wf("config/secrets.env", b"TOKEN=old\n")
        # an Edit Pre targets the secret but is REJECTED -> never posts (orphan)
        hook.handle_pre(self.base, {"session_id": "sa1", "cwd": self.work,
                                    "tool_input": {"file_path": "config/secrets.env"}},
                        "Edit", self.work, self.salt, "orphan")
        pl = {"session_id": "sa1", "cwd": self.work,
              "tool_input": {"command": "echo LEAK >> config/secrets.env"}}
        hook.handle_pre(self.base, pl, "Bash", self.work, self.salt, "b1")
        with open(os.path.join(self.work, "config/secrets.env"), "a") as fh:
            fh.write("TOKEN=rotated\n")
        hook.handle_post(self.base, pl, "Bash", self.work, self.salt, "b1")
        ev = [e for e in hook.read_session_events(self.base, "sa1")
              if e.get("tool_use_id") == "b1"][0]
        ch = {c["path"]: c for c in ev["changes"]}.get("config/secrets.env")
        self.assertEqual(ch.get("status"), "modified")
        self.assertNotEqual(ch.get("attribution"), "claimed_by_concurrent")
        self.assertTrue(alog.is_agent_sensitive(ev, ch),
                        "an orphan Pre must not drop a real secret write from the audit")

    # ---- A2: chmod (mode-only change) is visible ----
    def test_a2_mode_change_is_modified(self):
        p = self.wf("deploy.sh", b"#!/bin/sh\necho hi\n")
        os.chmod(p, 0o644)
        before = hook.snapshot_file(self.base, p, self.salt, False, False)
        os.chmod(p, 0o755)                       # chmod +x, content unchanged
        after = hook.snapshot_file(self.base, p, self.salt, False, False)
        ch = hook.build_changes({"deploy.sh": before}, {"deploy.sh": after},
                                True, None, False, [])[0]
        self.assertEqual(ch["status"], "modified")
        self.assertEqual(ch.get("mode_change"), [0o644, 0o755])

    # ---- R-a: PEM masking is linear (no ReDoS) and correct ----
    def test_ra_pem_mask_linear_and_correct(self):
        out = hook.mask_pem_blocks(
            "-----BEGIN PRIVATE KEY-----\nSECRETBODY\n-----END PRIVATE KEY-----")
        self.assertNotIn("SECRETBODY", out)
        self.assertIn("<redacted: private key>", out)
        # many headers, no footer: must finish fast (quadratic would hang)
        t0 = time.monotonic()
        big = hook.mask_pem_blocks("-----BEGIN PRIVATE KEY-----x" * 4000)
        self.assertLess(time.monotonic() - t0, 1.0)
        self.assertNotIn("BEGIN PRIVATE KEY", big)

    # ---- R-b: a torn UTF-8 byte doesn't disable session reads ----
    def test_rb_torn_utf8_does_not_break_reads(self):
        path = hook.session_file(self.base, "srb")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(json.dumps({"seq": 1, "kind": "turn", "message_id": "m"}).encode() + b"\n")
            fh.write(b'{"seq":2,"broken":"\xff\xfe bad bytes"}\n')   # invalid UTF-8
        evs = hook.read_session_events(self.base, "srb")   # must not raise
        self.assertTrue(any(e.get("message_id") == "m" for e in evs))

    # ---- RS-a: read_blob rejects a traversal sha ----
    def test_rsa_read_blob_rejects_traversal(self):
        self.assertIsNone(alog.read_blob(self.base, "../../../../etc/hosts"))
        self.assertIsNone(alog.read_blob(self.base, "/etc/hosts"))
        self.assertIsNone(alog.read_blob(self.base, "not-hex"))
        real = hook.store_blob(self.base, b"hi\n")          # a genuine 64-hex id works
        self.assertEqual(alog.read_blob(self.base, real), b"hi\n")

    # ---- RS-b: corrupt seq/ts don't crash the reader ----
    def test_rsb_corrupt_seq_ts_no_crash(self):
        hook._append_event(self.base, "srs", {"seq": "corrupt", "tool": "Bash",
                                              "ts": "notnum", "changes": [
                                                  {"path": ".env", "status": "modified",
                                                   "sensitive": True, "before": None,
                                                   "after": None}]})
        for fn in (lambda: alog.cmd_show(self.base, "srs", True),
                   lambda: alog.cmd_audit(self.base, "srs", True, fail_on_hit=True)):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                fn()                                # must not raise ValueError/TypeError

    # ---- RS-c: a lone surrogate path doesn't crash the reader ----
    def test_rsc_surrogate_path_no_crash(self):
        ev = {"seq": 1, "tool": "Write", "had_before": True, "file_path": "x",
              "changes": [{"path": "bad\udc80name.txt", "status": "added",
                           "before": None, "after": None, "sensitive": False}]}
        hook._append_event(self.base, "ssc", ev)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            alog.cmd_show(self.base, "ssc", False)  # print() must not UnicodeEncodeError
        self.assertNotIn("\udc80", buf.getvalue())

    # ---- RS-d: a null/non-list changes field doesn't crash the reader ----
    def test_rsd_null_changes_no_crash(self):
        path = hook.session_file(self.base, "srd")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"seq": 1, "tool": "Bash", "changes": None,
                                 "cmd_sensitive": None}) + "\n")
        for fn in (lambda: alog.cmd_show(self.base, "srd", False),
                   lambda: alog.cmd_audit(self.base, "srd", False),
                   lambda: alog.cmd_sessions(self.base)):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                fn()                                # must not raise TypeError


class TestRoundSixFixes(StoreTestCase):
    """Regressions for the 3-way (Workflow+Codex+AGY) FIFTH review fixes."""

    def _withheld_abs(self, ap, sensitive=None, exempt=False):
        rec = hook.snapshot_file(self.base, ap, self.salt,
                                 hook.is_sensitive(os.path.abspath(ap)) if sensitive is None
                                 else sensitive, exempt)
        return bool(rec.get("redacted"))

    # ---- S1: cwd-relative classifier bypass (classify by absolute path) ----
    def test_s1_cwd_relative_ssh_config_withheld(self):
        sshdir = os.path.join(self.work, ".ssh")
        os.makedirs(sshdir)
        p = os.path.join(sshdir, "config")
        with open(p, "w") as fh:
            fh.write("Host x\n  User me\n")          # no key shape; name 'config'
        snap = hook.snapshot_set(self.base, [p], sshdir, self.salt)
        self.assertTrue(snap["config"].get("redacted"),
                        ".ssh/ segment must be seen via the absolute path")

    # ---- S2: broad-sniff keyname parity ----
    def test_s2_bare_secret_token_private_key_withheld(self):
        for body in (b'{"secret": "aB3xK9mNpQrStUv012"}',
                     b'{"token": "aB3xK9mNpQrStUv012"}',
                     b"[Interface]\nPrivateKey = AQIDBAUGBwgJCgsMDQ4PEBESExQVFhc= \n",
                     b"session_token = aB3xK9mNpQrStUv012\n"):
            self.assertTrue(hook.content_looks_secret(body), body)
        # command parity too
        self.assertNotIn("aB3xK9mNpQrStUv012",
                         hook.redact_command("run --private-key aB3xK9mNpQrStUv012"))

    # ---- S3: .pub with appended non-token secret is withheld ----
    def test_s3_pub_appended_config_secret_withheld(self):
        p = self.wf("deploy.pub",
                    b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 user@h\npassword: swordfish\n")
        self.assertTrue(self._withheld_abs(p, sensitive=False, exempt=True))

    def test_s3_clean_pub_still_stored(self):
        p = self.wf("ok.pub", b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 user@h\n")
        self.assertFalse(self._withheld_abs(p, sensitive=False, exempt=True))

    # ---- S4/S5: exact names + dir-segment precedence ----
    def test_s4_bare_secrets_name_sensitive(self):
        self.assertTrue(hook.is_sensitive("secrets"))
        self.assertTrue(hook.is_sensitive(".secret"))

    def test_s5_secrets_dir_overrides_allowlist(self):
        self.assertTrue(hook.is_sensitive("secrets/.env.example"))
        self.assertTrue(hook.is_sensitive("/home/u/.ssh/config"))

    # ---- S6: hard link withheld ----
    def test_s6_hardlink_withheld(self):
        env = self.wf(".env", b"correct horse battery staple\n")
        alias = os.path.join(self.work, "notes.txt")
        os.link(env, alias)                          # hard link, non-sensitive name
        rec = hook.snapshot_file(self.base, alias, self.salt, False, False)
        self.assertTrue(rec.get("redacted"), "a multi-linked file must be withheld")

    # ---- S7: symlink alias to a secret is flagged ----
    def test_s7_symlink_alias_read_flagged(self):
        self.wf(".env", b"SECRET=v\n")
        alias = os.path.join(self.work, "alias.txt")
        os.symlink(".env", alias)
        rec = hook.snapshot_file(self.base, alias, self.salt, False, False)
        self.assertTrue(rec.get("target_sensitive"))
        # command-path scan flags the alias (which resolves to a secret target)
        self.assertIn("alias.txt", hook.scan_cmd_for_secrets("cat alias.txt", self.work))

    # ---- R1: curl --user / attached -u ----
    def test_r1_curl_user_forms_redacted(self):
        for cmd in ("curl --user alice:hunter2 https://x",
                    "curl --user=alice:hunter2 https://x",
                    "curl -ualice:hunter2 https://x"):
            self.assertNotIn("hunter2", hook.redact_command(cmd), cmd)

    # ---- R2: dangling PEM header does not swallow the rest ----
    def test_r2_dangling_pem_preserves_command(self):
        out = hook.redact_command('echo "-----BEGIN PRIVATE KEY-----"; rm -rf /tmp/x')
        self.assertIn("rm -rf /tmp/x", out)          # the rm must remain visible
        self.assertIn("<redacted: private key>", out)

    # ---- A1: a no-op Write must not claim a Bash write ----
    def test_a1_noop_write_does_not_claim_bash_write(self):
        self.wf(".env", b"SECRET=v0\n")

        def bpl(cmd="sh s"):
            return {"session_id": "a1b", "cwd": self.work, "tool_input": {"command": cmd}}
        wpl = {"session_id": "a1b", "cwd": self.work, "tool_input": {"file_path": ".env"}}
        hook.handle_pre(self.base, bpl(), "Bash", self.work, self.salt, "B")
        # a Write that writes IDENTICAL bytes (no-op) posts inside the window
        hook.handle_pre(self.base, wpl, "Write", self.work, self.salt, "W")
        hook.handle_post(self.base, wpl, "Write", self.work, self.salt, "W")
        with open(os.path.join(self.work, ".env"), "w") as fh:
            fh.write("SECRET=v1\n")                   # Bash genuinely changes it
        hook.handle_post(self.base, bpl(), "Bash", self.work, self.salt, "B")
        ev = [e for e in hook.read_session_events(self.base, "a1b")
              if e.get("tool_use_id") == "B"][0]
        env = {c["path"]: c for c in ev["changes"]}.get(".env")
        self.assertEqual(env.get("status"), "modified")
        self.assertNotEqual(env.get("attribution"), "claimed_by_concurrent")
        self.assertTrue(alog.is_agent_sensitive(ev, env))

    # ---- A2: coarse-FS (whole-second mtime) forces a re-hash ----
    def test_a2_wholesecond_mtime_rehashes(self):
        p = self.wf("c.conf", b"AAAAAAAAAA")
        os.utime(p, ns=(1_700_000_000_000_000_000, 1_700_000_000_000_000_000))
        calls = {"n": 0}
        orig = hook.snapshot_file

        def counting(*a, **k):
            calls["n"] += 1
            return orig(*a, **k)
        hook.snapshot_file = counting
        try:
            hook.snapshot_tree(self.base, self.work, self.salt, "a2")
            calls["n"] = 0
            hook.snapshot_tree(self.base, self.work, self.salt, "a2")  # warm
        finally:
            hook.snapshot_file = orig
        self.assertGreaterEqual(calls["n"], 1, "whole-second mtime must not be trusted")

    # ---- B1: a FIFO transcript path does not hang / record ----
    def test_b1_fifo_transcript_is_refused(self):
        fifo = os.path.join(self.tmp, "t.fifo")
        os.mkfifo(fifo)
        hook.handle_stop(self.base, {"session_id": "b1", "transcript_path": fifo})
        turns = [e for e in hook.read_session_events(self.base, "b1")
                 if e.get("kind") == "turn"]
        self.assertEqual(turns, [])                  # refused, did not hang/record

    # ---- C2: a directory session file doesn't crash the reader ----
    def test_c2_directory_session_file_no_crash(self):
        os.makedirs(os.path.join(self.base, "sessions", "bad.ndjson"))
        self.assertEqual(alog.load_events(self.base, None), [])   # skipped, no raise

    # ---- C3: a list-valued model doesn't crash cost ----
    def test_c3_list_model_no_crash(self):
        hook._append_event(self.base, "c3", {"seq": 1, "kind": "turn",
                                             "model": ["crafted"], "input_tokens": 1})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(alog.cmd_cost(self.base, "c3"), 0)

    # ---- C4: bidi/format chars are folded ----
    def test_c4_bidi_folded(self):
        self.assertNotIn("‮", alog._safe("prod‮.env"))
        self.assertNotIn("⁦", alog._safe_inline("a⁦b"))

    # ---- D2: legacy claude-3-* prices ----
    def test_d2_legacy_model_priced(self):
        self.assertIsNotNone(alog.price_for("claude-3-5-sonnet-20241022"))
        self.assertIsNotNone(alog.price_for("claude-3-opus-20240229"))

    # ---- AGY6-2: transcript read is bounded (no unbounded slurp) ----
    def test_bounded_transcript_read(self):
        p = os.path.join(self.tmp, "big.jsonl")
        line = json.dumps({"type": "assistant", "message": {
            "id": "m{0}", "model": "claude-opus-4-8",
            "usage": {"output_tokens": 1}}})
        with open(p, "w") as fh:
            for i in range(5):
                fh.write(line.replace("m{0}", "m%d" % i) + "\n")
        orig = hook.MAX_TRANSCRIPT_READ
        hook.MAX_TRANSCRIPT_READ = len(line) + 1     # ~one line per read
        try:
            seen, off, guard = set(), 0, 0
            while guard < 50:
                guard += 1
                turns, off2 = hook.parse_transcript_turns(p, off)
                for t in turns:
                    seen.add(t["message_id"])
                if off2 == off:
                    break
                off = off2
            self.assertEqual(seen, {"m0", "m1", "m2", "m3", "m4"})
        finally:
            hook.MAX_TRANSCRIPT_READ = orig

    # ---- D1: wheel does not ship the generic 'hook' module ----
    def test_d1_wheel_excludes_hook(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "pyproject.toml"), encoding="utf-8") as fh:
            txt = fh.read()
        self.assertIn('only-include = ["alog.py"]', txt)


class TestRoundSixReviewFixes(StoreTestCase):
    """Regressions for the SIXTH (3-way) review, incl. a critical regression the
    round-6 placeholder carve-out introduced."""

    # ---- W1 + Workflow-7 + AGY-4: placeholder exemption removed -> no leak class ----
    def test_w1_no_placeholder_bypass(self):
        # secrets that CONTAIN or START WITH a placeholder word are withheld (the three
        # ways the removed exemption leaked across rounds 6-7)
        self.assertTrue(hook.content_looks_secret(b"DB_PASSWORD=Pr0dPassxxxxK9zQ"))
        self.assertTrue(hook.content_looks_secret(b"db_password=yourPr0dS3cretK9mQ7pL2wZ5"))
        self.assertTrue(hook.content_looks_secret(b"api_key=abcyourdef1234567890"))
        # a template placeholder is now withheld too (fail-safe cost of no exemption)
        self.assertTrue(hook.content_looks_secret(b"API_KEY=replace_me_example"))

    # ---- Codex-2: short high-confidence secret values withheld ----
    def test_codex2_short_password_withheld(self):
        self.assertTrue(hook.content_looks_secret(b"password: abcde"))
        self.assertFalse(hook.content_looks_secret(b"password = get_secret()"))  # source spared

    # ---- Codex-4 (verified): PostToolUseFailure is captured ----
    def test_codex4_posttooluse_failure_records_event(self):
        import sys

        class FakeStdin:
            def __init__(self, d):
                self.buffer = io.BytesIO(d)
        self.wf("f.txt", b"v0\n")
        old, old_env = sys.stdin, os.environ.get("ALOG_DATA")
        os.environ["ALOG_DATA"] = self.base
        try:
            for evn in ("PreToolUse", "PostToolUseFailure"):
                if evn == "PostToolUseFailure":
                    with open(os.path.join(self.work, "f.txt"), "w") as fh:
                        fh.write("partial\n")        # a failed command's partial write
                sys.stdin = FakeStdin(json.dumps({
                    "hook_event_name": evn, "tool_name": "Bash", "session_id": "c4",
                    "cwd": self.work, "tool_use_id": "x",
                    "tool_input": {"command": "sh s"}}).encode())
                hook.main()
        finally:
            sys.stdin = old
            if old_env is None:
                os.environ.pop("ALOG_DATA", None)
            else:
                os.environ["ALOG_DATA"] = old_env
        evs = hook.read_session_events(self.base, "c4")
        post = [e for e in evs if e.get("tool_use_id") == "x" and "changes" in e][0]
        self.assertEqual(post.get("outcome"), "failure")
        self.assertTrue(any(c["path"] == "f.txt" and c["status"] == "modified"
                            for c in post["changes"]), "failed tool's write is captured")

    # ---- Codex-6: an external change during Read is not attributed to Read ----
    def test_codex6_external_change_during_read(self):
        before = {"f": {"sha": "a" * 64, "size": 3}}
        after = {"f": {"sha": "b" * 64, "size": 3}}
        ch = hook.build_changes(before, after, True, "f", False, [], read_only=True)[0]
        self.assertEqual(ch["status"], "read")       # not 'modified' under Read
        self.assertTrue(ch.get("external_change"))

    # ---- Codex-8: a non-string before/after doesn't crash the diff reader ----
    def test_codex8_nonstring_sha_no_crash(self):
        hook._append_event(self.base, "c8", {"seq": 1, "tool": "Write",
                                             "changes": [{"path": "x", "status": "modified",
                                                          "before": 123, "after": None}]})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(alog.cmd_diff(self.base, "c8", None), 0)   # no AttributeError

    # ---- W3: a benign concurrent Write must not suppress a Bash secret write ----
    def test_w3_benign_write_does_not_hide_bash_secret(self):
        self.wf("notes.txt", b"hello\n")

        def bpl():
            return {"session_id": "w3", "cwd": self.work,
                    "tool_input": {"command": "sh s"}}
        wpl = {"session_id": "w3", "cwd": self.work,
               "tool_input": {"file_path": "notes.txt"}}
        hook.handle_pre(self.base, bpl(), "Bash", self.work, self.salt, "B")
        hook.handle_pre(self.base, wpl, "Edit", self.work, self.salt, "E")
        with open(os.path.join(self.work, "notes.txt"), "w") as fh:
            fh.write("just some notes\n")             # Edit writes BENIGN bytes
        hook.handle_post(self.base, wpl, "Edit", self.work, self.salt, "E")
        with open(os.path.join(self.work, "notes.txt"), "w") as fh:
            fh.write("export TOKEN=ghp_" + "a" * 30 + "\n")   # Bash writes a SECRET
        hook.handle_post(self.base, bpl(), "Bash", self.work, self.salt, "B")
        bev = [e for e in hook.read_session_events(self.base, "w3")
               if e.get("tool_use_id") == "B"][0]
        nc = {c["path"]: c for c in bev["changes"]}.get("notes.txt")
        self.assertTrue(nc.get("redacted"))
        self.assertNotEqual(nc.get("attribution"), "claimed_by_concurrent",
                            "a benign Edit must not claim the Bash's secret write")
        self.assertTrue(alog.is_agent_sensitive(bev, nc),
                        "the secret write must surface (no false all-clear)")


class TestSeventhReviewFixes(StoreTestCase):
    """Regressions for the SEVENTH review (AGY) -- three of these were regressions in
    the round-6 fixes themselves (S1 abspath, W1 placeholder $, B1 TOCTOU)."""

    # ---- AGY-4: a real secret on a non-last line is withheld (was a $ / EOF bug) ----
    def test_agy4_multiline_secret_withheld(self):
        self.assertTrue(hook.content_looks_secret(b"API_KEY=Pr0dRealSecretK9zQ\nOTHER=1\n"))

    # ---- AGY-3 (self-introduced): ancestor 'secrets/' must not over-withhold ----
    def test_agy3_ancestor_generic_dir_not_over_withheld(self):
        self.assertFalse(hook.abspath_has_sensitive_dir("/home/u/projects/secrets/repo/app.py"))
        self.assertFalse(hook.is_sensitive("app.py"))
        # but a cwd INSIDE .ssh, and a within-repo secrets/ subdir, are still flagged
        self.assertTrue(hook.abspath_has_sensitive_dir("/home/u/.ssh/config"))
        self.assertTrue(hook.is_sensitive("secrets/db.txt"))

    def test_agy3_end_to_end_repo_under_secrets(self):
        # a repo cloned under an ancestor 'secrets' dir must still store ordinary files
        deep = os.path.join(self.work, "secrets", "repo")
        os.makedirs(deep)
        p = os.path.join(deep, "app.py")
        with open(p, "w") as fh:
            fh.write("print('hi')\n")
        snap = hook.snapshot_set(self.base, [p], deep, self.salt)
        self.assertFalse(snap["app.py"].get("redacted"),
                         "an ordinary file under an ancestor secrets/ must stay stored")

    # ---- AGY-2: byte URL regex catches an @-in-password credential ----
    def test_agy2_url_at_password_withheld(self):
        self.assertTrue(hook.content_looks_secret(b"db: postgres://u:pa@ss@host/prod"))

    # ---- AGY-1 (self-introduced TOCTOU): a FIFO transcript never blocks ----
    def test_agy1_fifo_transcript_nonblocking(self):
        fifo = os.path.join(self.tmp, "t.fifo")
        os.mkfifo(fifo)
        # parse must return immediately (non-blocking open + fstat reject), not hang
        turns, off = hook.parse_transcript_turns(fifo, 0)
        self.assertEqual(turns, [])


class TestSeventhReviewCodexFixes(StoreTestCase):
    """Regressions for the 7th review's Codex/Workflow findings."""

    # ---- Codex-4: a symlinked PARENT dir must not bypass classification ----
    def test_codex4_symlinked_parent_withheld(self):
        secrets = os.path.join(self.work, "secrets")
        os.makedirs(secrets)
        with open(os.path.join(secrets, "opaque.txt"), "w") as fh:
            fh.write("swordfish\n")                # no content-sniff shape
        os.symlink(secrets, os.path.join(self.work, "alias"))
        p = os.path.join(self.work, "alias", "opaque.txt")   # reached via symlinked parent
        snap = hook.snapshot_set(self.base, [p], self.work, self.salt)
        rec = snap[hook.rel_to_cwd(self.work, p)]
        self.assertTrue(rec.get("redacted"),
                        "a file under a symlinked-to-secrets/ parent must be withheld")

    # ---- Codex-5: a concurrent Write with a DIFFERENT final state must not claim ----
    def test_codex5_different_final_state_not_claimed(self):
        self.wf("notes.txt", b"base\n")

        def bpl():
            return {"session_id": "c5", "cwd": self.work, "tool_input": {"command": "sh s"}}
        wpl = {"session_id": "c5", "cwd": self.work, "tool_input": {"file_path": "notes.txt"}}
        hook.handle_pre(self.base, bpl(), "Bash", self.work, self.salt, "B")
        hook.handle_pre(self.base, wpl, "Edit", self.work, self.salt, "E")
        with open(os.path.join(self.work, "notes.txt"), "w") as fh:
            fh.write("password: firstsecret\n")    # Edit's final state
        hook.handle_post(self.base, wpl, "Edit", self.work, self.salt, "E")
        with open(os.path.join(self.work, "notes.txt"), "w") as fh:
            fh.write("password: secondsecret\n")   # Bash's DIFFERENT final state
        hook.handle_post(self.base, bpl(), "Bash", self.work, self.salt, "B")
        bev = [e for e in hook.read_session_events(self.base, "c5")
               if e.get("tool_use_id") == "B"][0]
        nc = {c["path"]: c for c in bev["changes"]}.get("notes.txt")
        self.assertNotEqual(nc.get("attribution"), "claimed_by_concurrent")
        self.assertTrue(alog.is_agent_sensitive(bev, nc))

    # ---- Codex-1: GitLab/Vault tokens + .vault-token/.envrc ----
    def test_codex1_more_tokens_and_names(self):
        self.assertTrue(hook.content_looks_secret(b"tok glpat-" + b"abcdefghij0123456789 x"))
        self.assertTrue(hook.content_looks_secret(b"VAULT hvs." + b"CAESIabcdefghij012345 x"))
        self.assertTrue(hook.is_sensitive(".vault-token"))
        self.assertTrue(hook.is_sensitive(".envrc"))

    # ---- Codex-2 / Workflow-3: a plain-word password in a PROMPT is masked ----
    def test_codex2_prompt_plainword_password_masked(self):
        self.assertNotIn("swordfish", hook.redact_prompt("The password: swordfish"))
        self.assertEqual(hook.redact_prompt("auth: yes"), "auth: yes")   # prose spared

    # ---- Codex-6: a FIFO swapped into the store doesn't hang the hook (write side) ----
    def test_codex6_fifo_lock_does_not_hang(self):
        import sys

        class FakeStdin:
            def __init__(self, d):
                self.buffer = io.BytesIO(d)
        # pre-create the session lock as a FIFO; the O_WRONLY open must fail fast (ENXIO
        # via O_NONBLOCK), not block -> main returns 0, no hang.
        os.makedirs(os.path.join(self.base, "locks"), exist_ok=True)
        os.mkfifo(os.path.join(self.base, "locks",
                               hook._safe_session("cf") + ".lock"))
        old, old_env = sys.stdin, os.environ.get("ALOG_DATA")
        os.environ["ALOG_DATA"] = self.base
        try:
            sys.stdin = FakeStdin(json.dumps({
                "hook_event_name": "PreToolUse", "tool_name": "Read", "session_id": "cf",
                "cwd": self.work, "tool_input": {"file_path": "x"}}).encode())
            self.assertEqual(hook.main(), 0)      # returns, does not hang
        finally:
            sys.stdin = old
            if old_env is None:
                os.environ.pop("ALOG_DATA", None)
            else:
                os.environ["ALOG_DATA"] = old_env

    # ---- Codex-7: malformed session/markers don't crash the reader ----
    def test_codex7_malformed_session_and_markers_no_crash(self):
        path = hook.session_file(self.base, "c7")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"seq": 1, "ts": 1, "session": [], "tool": "Bash",
                                 "had_before": True, "changes": [],
                                 "cmd_sensitive": [{}]}) + "\n")
        for fn in (lambda: alog.cmd_show(self.base, None, False),
                   lambda: alog.cmd_audit(self.base, None, False),
                   lambda: alog.cmd_sessions(self.base)):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                fn()                              # no TypeError on the set/membership


class TestSeventhReviewMediums(StoreTestCase):
    """Regressions for the round-7 MEDIUM findings."""

    # ---- short DB password flags (scoped) ----
    def test_short_db_password_flags(self):
        self.assertNotIn("MyS3cretPass",
                         hook.redact_command("mysql -uroot -pMyS3cretPass -e SELECT"))
        self.assertNotIn("MyRedisPassw0rd",
                         hook.redact_command("redis-cli -h h -a MyRedisPassw0rd ping"))
        # a docker/psql -p is a PORT, must NOT be masked
        self.assertIn("8080", hook.redact_command("docker run -p 8080:80 img"))
        self.assertIn("5432", hook.redact_command("psql -h db -p 5432 -U u"))

    # ---- dangling PEM header no longer swallows trailing command tokens ----
    def test_dangling_pem_keeps_trailing_tokens(self):
        out = hook.redact_command("echo -----BEGIN PRIVATE KEY----- rm file")
        self.assertIn("rm file", out)
        self.assertIn("<redacted: private key>", out)

    # ---- redaction is bounded (a huge command doesn't stall) ----
    def test_redaction_bounded_on_huge_command(self):
        import time
        big = "x" * 5_000_000
        t0 = time.monotonic()
        out = hook.redact_command(big)
        self.assertLess(time.monotonic() - t0, 1.0)
        self.assertIn("truncated", out)

    # ---- U+2028/U+2029 line separators are folded in reader output ----
    def test_line_separators_folded(self):
        self.assertNotIn(" ", alog._safe("a b"))
        self.assertNotIn(" ", alog._safe_inline("a b"))

    # ---- a sensitive Bash 'present' (no-Pre) is surfaced, not a false all-clear ----
    def test_bash_present_sensitive_surfaced(self):
        ev = {"tool": "Bash"}
        # sensitive 'present' (before unknown) -> counts (possible write)
        self.assertTrue(alog.is_agent_sensitive(
            ev, {"sensitive": True, "status": "present"}))
        # non-sensitive 'read'/'missing' under Bash still suppressed
        self.assertFalse(alog.is_agent_sensitive(
            ev, {"sensitive": True, "status": "read"}))


class TestFinalClaudeReviewFixes(unittest.TestCase):
    """Round-8 (Claude-only) review: two robustness/DoS asymmetries where a
    defense applied in one place was missing from its mirror site."""

    # ---- ReDoS: the content-sniff broad KV patterns must not backtrack ----
    # quadratically on a crafted keyword run (KV_SECRET_RE was bounded {0,40}
    # for exactly this reason; the content mirrors at hook.py L313/L320 were not).
    # Run in a SEPARATE PROCESS: re.search holds the GIL for the whole O(n^2)
    # scan, so a thread would freeze the whole interpreter (which is the bug).
    def test_content_sniff_no_redos_on_keyword_run(self):
        import multiprocessing
        try:
            ctx = multiprocessing.get_context("fork")
        except ValueError:
            self.skipTest("no fork start method on this platform")
        # ~256 KiB of the keyword 'auth' with no ':'/'=' -- pre-fix this is
        # O(n^2) (minutes); post-fix the bounded run makes it instant.
        p = ctx.Process(target=_redos_probe, args=(b"auth" * 65536,))
        p.start()
        p.join(4.0)
        alive = p.is_alive()
        if alive:
            p.terminate()
            p.join(2.0)
        self.assertFalse(alive,
                         "content_looks_secret hung on a keyword run (ReDoS)")

    def test_content_sniff_still_detects_unquoted_secret(self):
        # Behaviour preserved: the bound must not stop real secrets matching.
        self.assertTrue(hook.content_looks_secret(b"API_KEY=supersecret\n"))
        self.assertTrue(hook.content_looks_secret(b"password: swordfish\n"))
        self.assertTrue(hook.content_looks_secret(b'DB_PASSWORD: "hunter2"\n'))

    # ---- a FIFO swapped in for a fixed-path store READ must not block the ----
    # hook forever. get_salt() runs on every event BEFORE the session lock, so
    # a blocking O_RDONLY open of a writer-less FIFO wedges the whole session.
    def test_get_salt_survives_fifo_swap(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("no mkfifo on this platform")
        import threading
        tmp = tempfile.mkdtemp(prefix="agent-trail-fifo.")
        try:
            base = os.path.join(tmp, ".alog")
            hook.ensure_dirs(base)
            salt_path = os.path.join(base, "salt")
            with contextlib.suppress(OSError):
                os.remove(salt_path)
            os.mkfifo(salt_path)                 # writer-less FIFO in the store

            result = {}

            def run():
                result["salt"] = hook.get_salt(base)

            t = threading.Thread(target=run, daemon=True)
            t.start()
            self.assertTrue(t.join(2.0) or not t.is_alive(),
                            "get_salt blocked on a FIFO-swapped salt file")
            self.assertFalse(t.is_alive(),
                             "get_salt blocked on a FIFO-swapped salt file")
            self.assertEqual(len(result.get("salt", b"")), 16)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestFinalGateReviewFixes(StoreTestCase):
    """Round-9 (final gate) review: `alog audit` must tolerate a crafted store
    with a non-string `command` -- the CMD-REF line sliced the raw field before
    sanitizing, so a tampered int/dict command crashed the whole audit (and
    silently skipped --fail-on-hit). `show` was immune (it sanitizes first)."""

    def _write_session(self, sess, lines):
        p = hook.session_file(self.base, sess)
        with open(p, "w", encoding="utf-8") as fh:
            for o in lines:
                fh.write(json.dumps(o) + "\n")
        return p

    def test_audit_survives_non_string_command(self):
        # A tampered Bash event: non-string truthy `command` + a sensitive marker.
        # Pre-fix `(command or "")[:50]` -> 12345[:50] -> TypeError aborts audit.
        self._write_session("s", [
            {"tool": "Bash", "seq": 1, "ts": 1, "session": "s",
             "command": 12345, "cmd_sensitive": ["prod.env"]}])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = alog.cmd_audit(self.base, "s", False, fail_on_hit=True)
        self.assertEqual(rc, 2)                     # the sensitive hit still gates
        self.assertIn("prod.env", buf.getvalue())   # and the CMD-REF still prints


if __name__ == "__main__":
    unittest.main(verbosity=2)
