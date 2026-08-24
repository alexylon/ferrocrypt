#!/usr/bin/env python3
"""Checks the frozen FerroCrypt conformance corpus against FORMAT.md section 12.3.

This verifies the corpus as data: table grammar, identifier grammar, every
committed digest, referential integrity between the tables, the enumerated
values, and the per-outcome column rules. It does not decrypt anything and does
not need FerroCrypt, so an independent implementer can run it before writing a
single line of replay code.

Python 3 standard library only. Run from any directory:

    python3 tools/verify_manifests.py            # verifies the corpus it lives in
    python3 verify_manifests.py /path/to/wire    # or an explicit corpus root

Exit status is 0 when the corpus is well formed and 1 otherwise, with one line
per problem on stderr.
"""

import hashlib
import re
import sys
from pathlib import Path

# The manifest grammar implemented below.
SCHEMA_VERSION = 1

ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
NONCE = re.compile(r"^[0-9a-f]{38}$")

# FORMAT.md §5 plaintext chunk size, which fixes how many chunks a KAT input
# is encrypted in and therefore which counters its transcript uses.
CHUNK_BYTES = 65536
CAPABILITY = re.compile(
    r"^(outer_version|fca_version|public_key_version|private_key_version):0x[0-9A-F]{2}$"
    r"|^(outer_tlv|private_key_tlv|fca_archive_tlv|fca_entry_tlv):0x[0-9A-F]{4}$"
    r"|^(recipient_type|key_type):.+$"
)

TABLES = (
    "baselines.tsv",
    "diagnostic-classes.tsv",
    "credentials.tsv",
    "origins.tsv",
    "cases.tsv",
    "errata.tsv",
)

# The identifier each table is keyed by. Section 12.3 forbids duplicate
# identifiers, so a repeated key is a corpus defect and never a later row
# replacing an earlier one.
KEY_COLUMNS = {
    "baselines.tsv": "baseline_id",
    "diagnostic-classes.tsv": "class_id",
    "credentials.tsv": "credential_id",
    "origins.tsv": "origin_id",
    "cases.tsv": "case_id",
    "errata.tsv": "erratum_id",
}

# Columns holding an identifier, and whether the column may hold '-'. Capability
# identifiers use the structured forms of section 12.2 and are checked apart.
ID_COLUMNS = {
    "baselines.tsv": [("baseline_id", False), ("parent_baseline_id", True)],
    "diagnostic-classes.tsv": [("class_id", False)],
    "credentials.tsv": [("credential_id", False)],
    "origins.tsv": [("origin_id", False), ("anchor_case_id", False)],
    "cases.tsv": [
        ("case_id", False),
        ("first_required_by_baseline", False),
        ("parent_case_id", True),
        ("credential_id", True),
        ("condition_id", True),
        ("diagnostic_class", True),
    ],
    "errata.tsv": [
        ("erratum_id", False),
        ("affected_case_id", False),
        ("replacement_case_id", True),
    ],
}

# Tables recording the corpus revision that appended each row. Errata instead
# record the revision from which they take effect, which may still be ahead.
REVISION_TABLES = (
    "baselines.tsv",
    "diagnostic-classes.tsv",
    "credentials.tsv",
    "origins.tsv",
    "cases.tsv",
)

ENUMS = {
    ("credentials.tsv", "kind"): {"passphrase", "private_key", "none"},
    ("origins.tsv", "origin_kind"): {"fcr_payload", "stream_kat"},
    ("cases.tsv", "case_type"): {
        "fcr_decrypt",
        "public_key_decode",
        "private_key_open",
        "private_key_validate",
        "stream_encrypt_kat",
    },
    ("cases.tsv", "construction"): {"original", "mutation", "fabricated"},
    ("cases.tsv", "payload_transcript_kind"): {"origins", "none", "not_applicable"},
    ("cases.tsv", "outcome"): {"accept", "reject", "transcript_equal"},
    ("cases.tsv", "expectation_scope"): {"invariant", "capability_relative"},
}

# Every `*_ref` column and the digest column beside it. The payload-key
# commitment is handled separately: section 12.3 defines it as a digest of key
# material, which an `.fcr` payload origin records without naming a file.
DIGEST_PAIRS = {
    "diagnostic-classes.tsv": [("description_ref", "description_sha3_256")],
    "credentials.tsv": [
        ("primary_ref", "primary_sha3_256"),
        ("secret_ref", "secret_sha3_256"),
    ],
    "cases.tsv": [
        ("artifact_ref", "artifact_sha3_256"),
        ("expected_ref", "expected_sha3_256"),
    ],
    "errata.tsv": [("rationale_ref", "rationale_sha3_256")],
}

problems = []


def fail(message):
    problems.append(message)


def read_table(root, name):
    """Parses one manifest table into a list of column-keyed dicts."""
    path = root / name
    raw = path.read_bytes()
    if b"\r" in raw:
        fail(f"{name}: must use LF line endings")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        fail(f"{name}: must be UTF-8")
        return []
    columns, rows = None, []
    for number, line in enumerate(text.splitlines(), start=1):
        if line.startswith("#"):
            if columns is None:
                columns = line[1:].strip().split("\t")
            continue
        if columns is None:
            fail(f"{name}:{number}: a row precedes the column header")
            return []
        fields = line.split("\t")
        if len(fields) != len(columns):
            fail(f"{name}:{number}: {len(fields)} fields, expected {len(columns)}")
            continue
        for column, value in zip(columns, fields):
            if value == "":
                fail(f"{name}:{number}: {column} is empty")
            for bad in ("\\", ".."):
                if bad in value:
                    fail(f"{name}:{number}: {column} contains {bad!r}")
            if value.startswith("/"):
                fail(f"{name}:{number}: {column} is an absolute path")
            if (name, column) in ENUMS and value not in ENUMS[(name, column)]:
                fail(f"{name}:{number}: {column} has unknown value {value!r}")
        rows.append(dict(zip(columns, fields)))
    return rows


def index_by(name, rows, column):
    """Keys rows by an identifier, reporting a repeated one instead of dropping
    the earlier row. Section 12.3 requires replay to reject duplicate IDs."""
    indexed = {}
    for row in rows:
        key = row.get(column)
        if key is None:
            fail(f"{name}: a row has no {column}")
            continue
        if key in indexed:
            fail(f"{name}: {key}: duplicate identifier")
            continue
        indexed[key] = row
    return indexed


def check_ids(name, rows):
    for row in rows:
        for column, optional in ID_COLUMNS[name]:
            value = row.get(column)
            if value is None:
                fail(f"{name}: {row_id(name, row)}: no {column} column")
            elif value == "-":
                if not optional:
                    fail(f"{name}: {row_id(name, row)}: {column} is required")
            elif not ID.match(value):
                fail(f"{name}: {row_id(name, row)}: {column} breaks the identifier grammar")


def read_revision(root, name):
    """Reads SCHEMA-VERSION or CORPUS-REVISION as a positive integer."""
    text = (root / name).read_text().strip()
    if not text.isdigit() or int(text) < 1:
        fail(f"{name}: {text!r} is not a positive integer")
        return None
    return int(text)


def revision_field(name, row, column):
    value = row.get(column, "")
    if not value.isdigit() or int(value) < 1:
        fail(f"{name}: {row_id(name, row)}: {column} is not a positive integer")
        return None
    return int(value)


def check_digest(root, name, row, ref_column, digest_column):
    reference, digest = row[ref_column], row[digest_column]
    if reference == "-":
        if digest != "-":
            fail(f"{name}: {row_id(name, row)}: {ref_column} is '-' but {digest_column} is not")
        return
    if not DIGEST.match(digest):
        fail(f"{name}: {row_id(name, row)}: {digest_column} is not 64 lowercase hex characters")
        return
    target = root / reference
    if not target.is_file():
        fail(f"{name}: {row_id(name, row)}: {reference} does not exist")
        return
    actual = hashlib.sha3_256(target.read_bytes()).hexdigest()
    if actual != digest:
        fail(f"{name}: {row_id(name, row)}: {reference} does not match its committed digest")


def check_kat_chunk_nonces(root, row, cases, seen_keys, seen_chunks, nonce_prefix):
    """Rejects a KAT that reuses another KAT's payload key, and any chunk whose
    effective (payload key, full nonce) pair a chunk of an earlier KAT already
    used (FORMAT.md §12.3). The chunk count follows from the committed
    plaintext length, and the full nonce from FORMAT.md §5:
    stream_nonce(19) || counter:u32_be || final_flag:u8."""
    origin_id = row["origin_id"]
    key = row["payload_key_sha3_256"]
    if key in seen_keys:
        fail(f"origins.tsv: {origin_id}: payload key is shared with {seen_keys[key]}")
    seen_keys[key] = origin_id

    anchor = cases.get(row["anchor_case_id"])
    if anchor is None:
        return
    plaintext = root / anchor["artifact_ref"]
    if not plaintext.is_file():
        return
    length = plaintext.stat().st_size
    # An empty plaintext is one tag-only final chunk, and a length that is an
    # exact multiple of the chunk size ends on a full final chunk with no empty
    # trailer (FORMAT.md §5).
    chunks = max(1, (length + CHUNK_BYTES - 1) // CHUNK_BYTES)
    for counter in range(chunks):
        final_flag = 1 if counter == chunks - 1 else 0
        pair = (key, f"{nonce_prefix}{counter:08x}{final_flag:02x}")
        if pair in seen_chunks:
            fail(
                f"origins.tsv: {origin_id}: chunk {counter} reuses the payload key and "
                f"full nonce of {seen_chunks[pair]}"
            )
        seen_chunks[pair] = f"{origin_id} chunk {counter}"


def row_id(name, row):
    """The identifier a message names a row by: its own table's key, because
    several tables carry another table's key column as a reference."""
    return row.get(KEY_COLUMNS[name], "<row>")


CONTROL_FILES = {"SCHEMA-VERSION", "CORPUS-REVISION", "README.md"}


def is_structural_file(relative):
    """Whether a corpus-relative path carries the corpus rather than being
    carried by it, so no row names it. A rule rather than a list of names:
    "tools/" is matched by prefix, so adding a tool needs no edit here nor in
    the two other checkers that apply the same rule. Everything else must be
    reachable from a manifest, or nothing commits a digest for it and a change
    would go unnoticed."""
    return (
        relative in TABLES
        or relative in CONTROL_FILES
        or relative.startswith("tools/")
    )


def check_every_file_is_referenced(root, tables):
    """Reports any file the manifests do not name. A corpus is frozen and
    append-only, so an unreferenced file would be committed forever with no
    digest behind it."""
    referenced = set()
    for name, pairs in DIGEST_PAIRS.items():
        for row in tables[name]:
            for ref_column, _ in pairs:
                if row[ref_column] != "-":
                    referenced.add(row[ref_column])
    for row in tables["origins.tsv"]:
        if row["payload_key_ref"] != "-":
            referenced.add(row["payload_key_ref"])

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if is_structural_file(relative) or relative in referenced:
            continue
        fail(f"{relative}: no manifest row references this file")


def main():
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
    if not (root / "cases.tsv").is_file():
        print(f"no corpus at {root}", file=sys.stderr)
        return 1

    schema = read_revision(root, "SCHEMA-VERSION")
    # The column names and rules below are the schema 1 grammar. A later
    # schema may add, rename, or reorder columns, so refuse it rather than
    # report a corpus this tool did not actually check.
    if schema is not None and schema != SCHEMA_VERSION:
        print(
            f"SCHEMA-VERSION {schema}: this tool implements schema "
            f"{SCHEMA_VERSION}; use the verifier shipped with that corpus",
            file=sys.stderr,
        )
        return 1
    revision = read_revision(root, "CORPUS-REVISION")

    tables = {name: read_table(root, name) for name in TABLES}

    for name, pairs in DIGEST_PAIRS.items():
        for row in tables[name]:
            for ref_column, digest_column in pairs:
                check_digest(root, name, row, ref_column, digest_column)

    for name in TABLES:
        check_ids(name, tables[name])

    indexed = {name: index_by(name, tables[name], KEY_COLUMNS[name]) for name in TABLES}
    baselines = indexed["baselines.tsv"]
    classes = indexed["diagnostic-classes.tsv"]
    credentials = indexed["credentials.tsv"]
    origins = indexed["origins.tsv"]
    cases = indexed["cases.tsv"]

    # A row is appended by some revision at or before the current one. Rows from
    # earlier revisions stay, so this is a bound rather than an equality.
    for name in REVISION_TABLES:
        for row in tables[name]:
            introduced = revision_field(name, row, "introduced_in_corpus_revision")
            if introduced is not None and revision is not None and introduced > revision:
                fail(
                    f"{name}: {row_id(name, row)}: introduced_in_corpus_revision {introduced} "
                    f"is ahead of CORPUS-REVISION {revision}"
                )

    for row in tables["baselines.tsv"]:
        parent = row["parent_baseline_id"]
        if parent != "-" and parent not in baselines:
            fail(f"baselines.tsv: {row_id('baselines.tsv', row)}: parent baseline is not declared")

    for row in tables["credentials.tsv"]:
        kind, primary, secret = row["kind"], row["primary_ref"], row["secret_ref"]
        if kind == "passphrase" and (primary == "-" or secret != "-"):
            fail(f"credentials.tsv: {row_id('credentials.tsv', row)}: a passphrase names primary_ref and no secret_ref")
        if kind == "private_key" and (primary == "-" or secret == "-"):
            fail(f"credentials.tsv: {row_id('credentials.tsv', row)}: a private key names both refs")
        if kind == "none" and (primary != "-" or secret != "-"):
            fail(f"credentials.tsv: {row_id('credentials.tsv', row)}: a 'none' credential names no material")

    # §12.3 requires four duplicate checks over encryption inputs: the nonce
    # prefix of every origin, the payload key of every KAT, and the effective
    # (payload key, full nonce) pair of every KAT chunk. A repeat of the last
    # is nonce reuse under one key, which a published corpus must never show.
    seen_nonces = {}
    seen_kat_keys = {}
    seen_kat_chunks = {}
    for row in tables["origins.tsv"]:
        origin_id = row["origin_id"]
        if row["anchor_case_id"] not in cases:
            fail(f"origins.tsv: {origin_id}: anchor case is not declared")
        if not NONCE.match(row["stream_nonce_hex"]):
            fail(f"origins.tsv: {origin_id}: stream_nonce_hex is not a 19-byte prefix")
        nonce_prefix = row["stream_nonce_hex"]
        if nonce_prefix in seen_nonces:
            fail(
                f"origins.tsv: {origin_id}: nonce prefix is shared with "
                f"{seen_nonces[nonce_prefix]}"
            )
        seen_nonces[nonce_prefix] = origin_id
        if row["origin_kind"] == "stream_kat":
            if row["payload_key_ref"] == "-":
                fail(f"origins.tsv: {origin_id}: a stream_kat origin names its payload key")
            else:
                check_digest(root, "origins.tsv", row, "payload_key_ref", "payload_key_sha3_256")
            check_kat_chunk_nonces(
                root, row, cases, seen_kat_keys, seen_kat_chunks, nonce_prefix
            )
        elif not DIGEST.match(row["payload_key_sha3_256"]):
            fail(f"origins.tsv: {origin_id}: payload key commitment is not a digest")

    for row in tables["cases.tsv"]:
        case_id = row["case_id"]
        if row["first_required_by_baseline"] not in baselines:
            fail(f"cases.tsv: {case_id}: baseline is not declared")

        outcome = row["outcome"]
        if outcome == "reject":
            if row["condition_id"] == "-":
                fail(f"cases.tsv: {case_id}: a rejected case needs a condition identifier")
            if row["diagnostic_class"] not in classes:
                fail(f"cases.tsv: {case_id}: diagnostic class is not declared")
            if row["expected_ref"] != "-":
                fail(f"cases.tsv: {case_id}: a rejected case carries no expected result")
        else:
            if row["expected_ref"] == "-":
                fail(f"cases.tsv: {case_id}: a non-rejected case needs a byte-exact result")
            if row["diagnostic_class"] != "-":
                fail(f"cases.tsv: {case_id}: a non-rejected case uses diagnostic_class '-'")

        if row["expectation_scope"] == "invariant":
            if row["capability_id"] != "-":
                fail(f"cases.tsv: {case_id}: an invariant case uses capability_id '-'")
        elif not CAPABILITY.match(row["capability_id"]):
            fail(f"cases.tsv: {case_id}: capability identifier form")

        transcript = row["payload_transcript_kind"]
        if row["case_type"] == "fcr_decrypt":
            if transcript == "not_applicable":
                fail(f"cases.tsv: {case_id}: an .fcr case uses 'origins' or 'none'")
        elif transcript != "not_applicable":
            fail(f"cases.tsv: {case_id}: a non-.fcr case uses 'not_applicable'")

        if transcript == "origins":
            listed = row["payload_origin_ids"].split(",")
            if len(set(listed)) != len(listed):
                fail(f"cases.tsv: {case_id}: origin list has duplicates")
            for origin_id in listed:
                if not ID.match(origin_id):
                    fail(f"cases.tsv: {case_id}: origin {origin_id!r} breaks the list form")
                elif origin_id not in origins:
                    fail(f"cases.tsv: {case_id}: origin {origin_id} is not declared")
        elif row["payload_origin_ids"] != "-":
            fail(f"cases.tsv: {case_id}: only an 'origins' case lists origins")

        if row["construction"] == "mutation":
            if row["parent_case_id"] not in cases:
                fail(f"cases.tsv: {case_id}: a mutation names an existing parent case")
        elif row["parent_case_id"] != "-":
            fail(f"cases.tsv: {case_id}: only a mutation names a parent")

        if row["credential_id"] != "-" and row["credential_id"] not in credentials:
            fail(f"cases.tsv: {case_id}: credential is not declared")

    check_every_file_is_referenced(root, tables)

    # An erratum withdraws its affected case from replay at or after the
    # revision it takes effect from, and never by removing the row.
    withdrawn = set()
    for row in tables["errata.tsv"]:
        erratum_id = row["erratum_id"]
        if row["affected_case_id"] not in cases:
            fail(f"errata.tsv: {erratum_id}: affected case is not declared")
        replacement = row["replacement_case_id"]
        if replacement != "-" and replacement not in cases:
            fail(f"errata.tsv: {erratum_id}: replacement case is not declared")
        if row["rationale_ref"] == "-":
            fail(f"errata.tsv: {erratum_id}: an erratum states its rationale")
        effective = revision_field("errata.tsv", row, "effective_corpus_revision")
        if effective is not None and revision is not None and effective <= revision:
            withdrawn.add(row["affected_case_id"])

    for message in problems:
        print(message, file=sys.stderr)
    print(
        f"corpus at {root}: schema {schema}, revision {revision}, "
        f"{len(cases)} cases ({len(withdrawn)} withdrawn by errata), {len(origins)} origins, "
        f"{len(credentials)} credentials, {len(classes)} diagnostic classes, "
        f"{len(tables['errata.tsv'])} errata — "
        f"{'OK' if not problems else str(len(problems)) + ' problem(s)'}"
    )
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
