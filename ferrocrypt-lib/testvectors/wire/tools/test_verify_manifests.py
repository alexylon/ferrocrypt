#!/usr/bin/env python3
"""Tests for verify_manifests.py: the committed corpus passes, and a manifest
reference the grammar refuses never reaches the filesystem.

FORMAT.md section 12.3 requires a reference to be validated before the file it
names is read. These tests plant refused spellings into every reference column
and record every path the verifier hands to the filesystem while it runs, so a
reference that is reported as invalid but still opened or examined fails them.

Python 3 standard library only. Run from any directory:

    python3 tools/test_verify_manifests.py
"""

import builtins
import contextlib
import hashlib
import io
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_manifests  # noqa: E402

CORPUS = Path(__file__).resolve().parent.parent

# Spellings the reference grammar refuses (FORMAT.md section 12.3): parent
# traversal, absolute paths, Windows drive and UNC prefixes, backslashes,
# empty and "." components, a trailing separator, an upper-case letter, and a
# space. The tests place "outside.bin" beside the corpus root with a matching
# digest, so the one true traversal, "../outside.bin", would pass an unguarded
# digest check instead of being reported as missing. What proves that no entry
# is reached is the access spy, not the digest.
REJECTED_REFERENCES = [
    "../outside.bin",
    "a/../outside.bin",
    "/etc/passwd",
    "C:/outside.bin",
    "C:outside.bin",
    "a\\outside.bin",
    "\\\\server\\share\\outside.bin",
    "a//outside.bin",
    "a/./outside.bin",
    "./outside.bin",
    "outside.bin/",
    "Outside.bin",
    "out side.bin",
]

# Every reference column, with the row a test plants into: a row the column
# applies to, or for errata a row the test appends, since revision 1 has none.
ERRATUM_ROW = "erratum-test\t{case_id}\t1\t{reference}\t{digest}\t-\t0.3.0"
REFERENCE_COLUMNS = [
    ("diagnostic-classes.tsv", "description_ref", "description_sha3_256", lambda row: True),
    ("credentials.tsv", "primary_ref", "primary_sha3_256", lambda row: row["kind"] == "passphrase"),
    ("credentials.tsv", "secret_ref", "secret_sha3_256", lambda row: row["kind"] == "private_key"),
    ("origins.tsv", "payload_key_ref", "payload_key_sha3_256", lambda row: row["origin_kind"] == "stream_kat"),
    ("cases.tsv", "artifact_ref", "artifact_sha3_256", lambda row: row["case_type"] == "fcr_decrypt"),
    # The anchor of a stream_kat origin: its artifact is also examined for its
    # size when the KAT chunk nonces are checked.
    ("cases.tsv", "artifact_ref", "artifact_sha3_256", lambda row: row["case_type"] == "stream_encrypt_kat"),
    ("cases.tsv", "expected_ref", "expected_sha3_256", lambda row: row["outcome"] == "accept"),
    ("errata.tsv", "rationale_ref", "rationale_sha3_256", None),
]


class AccessSpy:
    """Records every path handed to the os and io functions that pathlib and
    open() are built on while active, so an access is seen however the
    verifier makes it: opened, read, listed, or only examined. The os.path
    predicates are wrapped as well, because pathlib routes its own through
    them, and on Windows those need not reach os.stat."""

    TARGETS = (
        (os, "stat"),
        (os, "lstat"),
        (os, "scandir"),
        (os, "listdir"),
        (os.path, "isfile"),
        (os.path, "isdir"),
        (os.path, "exists"),
        (io, "open"),
        (builtins, "open"),
    )

    def __enter__(self):
        self.paths = []
        self.originals = [(module, name, getattr(module, name)) for module, name in self.TARGETS]
        for module, name, original in self.originals:

            def spy(*args, _original=original, **kwargs):
                path = args[0] if args else kwargs.get("path", kwargs.get("file"))
                if isinstance(path, (str, bytes, os.PathLike)):
                    self.paths.append(Path(os.fsdecode(path)))
                return _original(*args, **kwargs)

            setattr(module, name, spy)
        return self

    def __exit__(self, *exc):
        for module, name, original in self.originals:
            setattr(module, name, original)


def run_verifier(root):
    """Runs the verifier on `root` in this process; returns its exit status
    and everything it printed."""
    output = io.StringIO()
    argv = sys.argv
    sys.argv = ["verify_manifests.py", str(root)]
    try:
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            status = verify_manifests.main()
    finally:
        sys.argv = argv
    return status, output.getvalue()


def table_rows(table_path):
    """The header comment's columns and the lines of a table."""
    lines = table_path.read_text().splitlines()
    columns = lines[0].removeprefix("#").strip().split("\t")
    return columns, lines


def data_rows(table_path):
    """The rows of a table as column-keyed dicts, comment lines skipped."""
    columns, lines = table_rows(table_path)
    return [dict(zip(columns, line.split("\t"))) for line in lines if not line.startswith("#")]


def plant_fields(table_path, choose, fields):
    """Rewrites the first row of the table that `choose` accepts so that each
    column in `fields` holds its value."""
    columns, lines = table_rows(table_path)
    for index, line in enumerate(lines):
        if line.startswith("#"):
            continue
        row = dict(zip(columns, line.split("\t")))
        if choose(row):
            row.update(fields)
            lines[index] = "\t".join(row[name] for name in columns)
            break
    else:
        raise AssertionError(f"{table_path.name}: no row to plant {sorted(fields)} into")
    table_path.write_text("\n".join(lines) + "\n")


def plant_reference(table_path, column, digest_column, choose, reference, digest):
    """Rewrites one row of the table so `column` holds `reference` and its
    digest column holds `digest`: the first row `choose` accepts, or an
    appended erratum where `choose` is None, affecting the corpus's first
    case."""
    if choose is None:
        first_case = data_rows(table_path.parent / "cases.tsv")[0]
        _, lines = table_rows(table_path)
        lines.append(ERRATUM_ROW.format(case_id=first_case["case_id"], reference=reference, digest=digest))
        table_path.write_text("\n".join(lines) + "\n")
    else:
        plant_fields(table_path, choose, {column: reference, digest_column: digest})


class CommittedCorpus(unittest.TestCase):
    def test_the_committed_corpus_is_well_formed(self):
        status, output = run_verifier(CORPUS)
        self.assertEqual(status, 0, output)
        self.assertTrue(output.rstrip().endswith("— OK"), output)


class RejectedReferences(unittest.TestCase):
    """A reference the grammar refuses is reported, fails the run, and is
    never joined onto the corpus root for any filesystem access."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ferrocrypt-verifier-test-")
        parent = Path(self.tmp.name)
        self.root = parent / "wire"
        shutil.copytree(CORPUS, self.root)
        self.outside = parent / "outside.bin"
        self.outside.write_bytes(b"a file beside the corpus root")
        self.digest = hashlib.sha3_256(self.outside.read_bytes()).hexdigest()
        # What the verifier may touch before it has validated every reference.
        self.manifests = {self.root / name for name in verify_manifests.TABLES} | {
            self.root / "SCHEMA-VERSION",
            self.root / "CORPUS-REVISION",
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_rejected_reference_is_reported_and_never_reached(self):
        for table, column, digest_column, choose in REFERENCE_COLUMNS:
            table_path = self.root / table
            original = table_path.read_text()
            for reference in REJECTED_REFERENCES:
                with self.subTest(table=table, column=column, reference=reference):
                    plant_reference(table_path, column, digest_column, choose, reference, self.digest)
                    try:
                        with AccessSpy() as spy:
                            status, output = run_verifier(self.root)
                    finally:
                        table_path.write_text(original)
                    self.assertEqual(status, 1, output)
                    self.assertIn(f"{column} is not a corpus reference", output)
                    self.assertIn(
                        self.root / "cases.tsv",
                        spy.paths,
                        "the spy must see the run's own table reads, or it proves nothing",
                    )
                    self.assertNotIn(self.root / reference, spy.paths)
                    self.assertFalse(
                        any(path.resolve() == self.outside.resolve() for path in spy.paths),
                        "the file outside the corpus was reached",
                    )
                    self.assertLessEqual(
                        set(spy.paths),
                        self.manifests,
                        "a referenced file was reached although a reference was refused",
                    )
                    self.assertIn("before any referenced file was read", output)

    def test_a_valid_reference_to_a_missing_file_is_only_reported_as_missing(self):
        """The refusal above is specific to the grammar: a well-formed
        reference is still resolved, and one that names no file is reported
        as missing rather than as invalid."""
        table_path = self.root / "cases.tsv"
        plant_reference(
            table_path,
            "artifact_ref",
            "artifact_sha3_256",
            lambda row: row["case_type"] == "fcr_decrypt",
            "artifacts/fcr/missing.fcr",
            self.digest,
        )
        status, output = run_verifier(self.root)
        self.assertEqual(status, 1, output)
        self.assertIn("artifacts/fcr/missing.fcr does not exist", output)
        self.assertNotIn("is not a corpus reference", output)

    def test_a_malformed_revision_file_alone_does_not_stop_the_file_checks(self):
        """Only a refused reference stops the run before the referenced files
        are read: a problem found earlier, in a revision file, is reported
        beside the results of every other check."""
        (self.root / "CORPUS-REVISION").write_text("0\n")
        status, output = run_verifier(self.root)
        self.assertEqual(status, 1, output)
        self.assertIn("CORPUS-REVISION: '0' is not a positive integer", output)
        self.assertNotIn("before any referenced file was read", output)
        cases = len(data_rows(self.root / "cases.tsv"))
        self.assertIn(f"{cases} cases", output)

    def test_an_identifier_problem_alone_does_not_stop_the_file_checks(self):
        """A table problem that is not a refused reference, such as an
        identifier that breaks the grammar, is reported together with the
        file checks, which read no reference the grammar refused."""
        plant_fields(
            self.root / "cases.tsv",
            lambda row: row["outcome"] == "reject",
            {"condition_id": "Upper-Case"},
        )
        status, output = run_verifier(self.root)
        self.assertEqual(status, 1, output)
        self.assertIn("condition_id breaks the identifier grammar", output)
        self.assertNotIn("before any referenced file was read", output)
        cases = len(data_rows(self.root / "cases.tsv"))
        self.assertIn(f"{cases} cases", output)

    def test_a_kat_anchor_without_an_artifact_is_reported(self):
        """A case whose artifact_ref is '-' names no artifact. That is a
        corpus defect, reported as such rather than resolved as a file: the
        KAT chunk check reads the anchor's artifact size, and must not resolve
        '-' as a file name."""
        plant_reference(
            self.root / "cases.tsv",
            "artifact_ref",
            "artifact_sha3_256",
            lambda row: row["case_type"] == "stream_encrypt_kat",
            "-",
            "-",
        )
        status, output = run_verifier(self.root)
        self.assertEqual(status, 1, output)
        self.assertIn("a case names its artifact", output)
        self.assertNotIn("does not exist", output)


if __name__ == "__main__":
    unittest.main()
