# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Shared point-in-time-recovery primitives — ONE implementation for BOTH the
weekly restore drill and the live restore.

The bash carried near-duplicate copies of the dump-anchor parser, the
system-schema stream filter, and the binlog-selection loop in verify_restore
and restore_pitr; it had already unified the anchor parser after a real
divergence (only the drill accepted the newer `CHANGE REPLICATION SOURCE TO`
spelling, so a DB_IMAGE bump would have kept the drill green while a real
restore silently skipped binlog replay). This module finishes that
unification: a behavior change here changes the drill and the restore
together, so they can never drift again."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator, List, NamedTuple, Optional, Tuple

# Both anchor spellings: `CHANGE MASTER TO` (older) and
# `CHANGE REPLICATION SOURCE TO` (mariadb/mysql successor).
_ANCHOR_RE = re.compile(r"CHANGE (MASTER|REPLICATION SOURCE) TO")
_LOG_FILE_RE = re.compile(r"_LOG_FILE='([^']*)'")
_LOG_POS_RE = re.compile(r"_LOG_POS=([0-9]+)")

# Schemas that must never be loaded over a target server: reloading
# production account rows over the target's own root breaks subsequent auth
# (drill) or clobbers the live server's accounts (restore).
_SYSTEM_SCHEMAS = frozenset({"mysql", "sys", "performance_schema", "information_schema"})

_CURRENT_DB_RE = re.compile(r"^-- Current Database: `([^`]*)`")
_USE_RE = re.compile(r"^USE `([^`]*)`")


class Anchor(NamedTuple):
    """Binlog coordinates recorded by a --master-data=2 dump."""

    log_file: str
    log_pos: str


def dump_anchor(dump_path: Path, scan_limit: int = 200) -> Optional[Anchor]:
    """The PITR anchor from the dump header (the commented CHANGE ... TO line
    --master-data=2 writes). The anchor sits in the first few header lines;
    the scan is bounded so a multi-GB dump is never read whole."""
    with open(dump_path, errors="replace") as f:
        for i, line in enumerate(f):
            if i >= scan_limit:
                break
            if _ANCHOR_RE.search(line):
                fm = _LOG_FILE_RE.search(line)
                pm = _LOG_POS_RE.search(line)
                if fm and pm and fm.group(1):
                    return Anchor(fm.group(1), pm.group(1))
                return None
    return None


def filter_system_schemas(
    lines: Iterable[str],
    *,
    drop_user_schemas: bool = False,
    stats: Optional[dict] = None,
) -> Iterator[str]:
    """Stream-filter an --all-databases dump, dropping the mysql/sys/
    performance_schema/information_schema sections. Keys off the
    `-- Current Database:` comment (which PRECEDES the CREATE DATABASE line)
    as well as USE, so an empty-target restore keeps the CREATE DATABASE for
    user schemas — the toggle-on-USE-only form dropped it.

    drop_user_schemas=True injects `DROP DATABASE IF EXISTS \\`db\\`;` right
    after each user schema's FIRST `-- Current Database:` comment (before the
    dump's own CREATE DATABASE ... IF NOT EXISTS), so the load recreates each
    dumped schema from scratch instead of merging over the live one — a merge
    leaves post-dump tables in place, and the binlog replay's re-executed
    CREATE TABLE then aborts the whole restore (error 1050). FIRST occurrence
    only: mariadb-dump emits a SECOND `-- Current Database:` section per
    schema at the end of the dump when the schema contains views (the
    temp-table -> view fixup pass) — injecting there would drop the database
    AFTER its data was loaded.

    stats (optional mutable dict) reports what was injected: the caller warns
    when a drop was requested but the dump carried no recognizable schema
    sections (a generator cannot return a count to its for-loop consumer).
    """
    skip = False
    dropped: List[str] = []
    if stats is not None:
        stats["dropped"] = dropped
    for line in lines:
        m = _CURRENT_DB_RE.match(line)
        if m:
            db = m.group(1)
            skip = db in _SYSTEM_SCHEMAS
            if drop_user_schemas and not skip and db not in dropped:
                dropped.append(db)
                yield line
                yield f"DROP DATABASE IF EXISTS `{db}`;\n"
                continue
        else:
            m = _USE_RE.match(line)
            if m:
                skip = m.group(1) in _SYSTEM_SCHEMAS
        if not skip:
            yield line


_BINLOG_NAME_RE = re.compile(r"binlog\.([0-9]+)")


def _binlog_seq(name: str) -> Optional[int]:
    m = _BINLOG_NAME_RE.fullmatch(name)
    return int(m.group(1)) if m else None


def binlog_seq(name: str) -> Optional[int]:
    """Public: numeric sequence of a `binlog.NNNNNN` basename, or None when the
    name is not a binlog file. Numeric (not lexical) so the 7-digit rollover
    after binlog.999999 orders correctly."""
    return _binlog_seq(name)


def newest_local_binlog_seq(binlog_dir: Path) -> Optional[int]:
    """Highest `binlog.NNNNNN` sequence present in a local binlog dir, or None
    when the dir is absent or holds no binlog files. Used by the live restore
    to decide whether the LOCAL binlogs genuinely continue a dump's chain
    (newest local sequence past the dump anchor) versus belong to an unrelated
    server — e.g. the fresh MariaDB a disaster-recovery `play` starts, whose
    binlog.000001 must NOT be shipped as the chain's new 'latest'."""
    if not binlog_dir.is_dir():
        return None
    seqs = [seq for p in binlog_dir.iterdir()
            if (seq := _binlog_seq(p.name)) is not None]
    return max(seqs) if seqs else None


def select_replay_binlogs(binlog_dir: Path, anchor_file: str) -> List[str]:
    """Basenames of the shipped binlogs to replay: binlog.NNNNNN files whose
    NUMERIC sequence is at/after the anchor's. Numeric, not lexical: MariaDB
    grows the suffix to 7 digits after binlog.999999, and lexically
    'binlog.1000000' < 'binlog.999999' — a string compare silently drops the
    post-rollover files from the chain. binlog.index is excluded by the name
    regex — fed to mariadb-binlog it is a guaranteed parse error."""
    out: List[str] = []
    anchor_seq = _binlog_seq(anchor_file)
    if anchor_seq is None or not binlog_dir.is_dir():
        return out
    for p in binlog_dir.iterdir():
        seq = _binlog_seq(p.name)
        if seq is None or seq < anchor_seq:
            continue
        out.append(p.name)
    out.sort(key=lambda n: _binlog_seq(n) or 0)
    return out


def select_replay_chain(binlog_dir: Path, anchor_file: str) -> Tuple[List[str], str]:
    """Validated replay selection shared by the drill AND the live restore:
    ([files], "") when the chain is sound, ([], problem) otherwise.

    Two silent-corruption modes make the validation load-bearing:
      - ANCHOR ABSENT: dumps are retained ~12 months but binlogs only ~9 days,
        so an older dump's anchor file has been pruned. `--start-position`
        applies only to the FIRST file on the mariadb-binlog command line —
        with the anchor gone it would seek into the wrong (later) file and
        replay a bogus slice of much-later transactions.
      - MID-CHAIN GAP: a missing middle file would be skipped wordlessly and
        every transaction it held silently lost from the replayed range.
    Both must degrade to a refused replay, never a wrong one."""
    files = select_replay_binlogs(binlog_dir, anchor_file)
    if not files or files[0] != anchor_file:
        oldest = files[0] if files else "none"
        return [], (
            f"the dump's anchor binlog ({anchor_file}) is not in the shipped set "
            f"(oldest at/after it: {oldest}) — it was pruned by binlog retention, so "
            f"point-in-time replay for this dump is IMPOSSIBLE (dumps are kept far "
            f"longer than binlogs; older dumps restore to their exact instant only)"
        )
    seqs = [_binlog_seq(f) for f in files]
    for prev, cur, name in zip(seqs, seqs[1:], files[1:]):
        if prev is not None and cur is not None and cur != prev + 1:
            return [], (
                f"the shipped binlog chain has a GAP before {name} (previous file is "
                f"sequence {prev}, expected {prev + 1}) — replaying across the gap "
                f"would silently lose every transaction in the missing file(s)"
            )
    return files, ""


_SERVER_UUID_RE = re.compile(r"^-- carlos-server-uuid: ([0-9a-f-]{36})\s*$")
IDENTITY_SIDECAR = ".carlos-server-identity"


def dump_server_identity(dump_path: Path, scan_limit: int = 10) -> str:
    """The originating server's @@server_uuid, from the `-- carlos-server-uuid:`
    comment the backup writes as the dump's first line. '' when absent (a
    pre-identity dump — legacy semantics, warn-don't-fail) or unreadable."""
    try:
        with open(dump_path, errors="replace") as f:
            for i, line in enumerate(f):
                if i >= scan_limit:
                    break
                m = _SERVER_UUID_RE.match(line)
                if m:
                    return m.group(1)
    except OSError:
        return ""
    return ""


def read_identity_sidecar(binlog_dir: Path) -> str:
    """The shipping server's identity, read from the sidecar file that rides
    INSIDE each binlog restic snapshot (so replay learns it from the restored
    files themselves — no restic-JSON parsing). '' = pre-identity snapshot."""
    try:
        val = (binlog_dir / IDENTITY_SIDECAR).read_text().strip().lower()
    except OSError:
        return ""
    return val if re.fullmatch(r"[0-9a-f-]{36}", val) else ""


_COMPLETED_RE = re.compile(
    r"-- Dump completed on\s+(\d{4}-\d{2}-\d{2})\s+(\d{1,2}:\d{2}:\d{2})"
)


def normalize_stop_datetime(stop: str) -> str:
    """Canonicalize an already-shape-validated --stop-datetime to
    'YYYY-MM-DD HH:MM:SS': ISO 'T' separator → space (mariadb-binlog does not
    parse the 'T' form), bare date → midnight, minutes-only → :00 seconds.
    The result string-compares against dump_completed_at() and is what the
    replay interpolates into mariadb-binlog's --stop-datetime."""
    stop = stop.replace("T", " ")
    if len(stop) == 10:
        stop += " 00:00:00"
    elif len(stop) == 16:
        stop += ":00"
    return stop


def dump_completed_at(dump_path: Path) -> Optional[str]:
    """The dump's completion instant from the mariadb-dump footer, normalized
    to 'YYYY-MM-DD HH:MM:SS' (mariadb-dump prints a space-padded hour) so it
    string-compares against a --stop-datetime of the same shape. None when
    the footer is absent/unreadable."""
    try:
        with open(dump_path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 256))
            tail = f.read().decode(errors="replace")
    except OSError:
        return None
    m = _COMPLETED_RE.search(tail)
    if not m:
        return None
    date, clock = m.group(1), m.group(2)
    hh, mm, ss = clock.split(":")
    return f"{date} {int(hh):02d}:{mm}:{ss}"


def dump_has_content(dump_path: Path, chunk_size: int = 1 << 20) -> bool:
    """Content floor for a staged dump: True when the dump defines or fills
    at least one table (CREATE TABLE / INSERT INTO). A dump can carry a
    perfectly valid '-- Dump completed' footer yet be semantically EMPTY
    (every schema skipped/filtered, a wrong --databases list, a server that
    answered with nothing) — committing that as the nightly full would
    stamp .last-full-ok on a backup that cannot restore anything. Chunked
    scan with an overlap so a marker straddling a chunk boundary still hits;
    unreadable → False (fail closed)."""
    markers = (b"CREATE TABLE", b"INSERT INTO")
    overlap = max(len(m) for m in markers) - 1
    try:
        with open(dump_path, "rb") as f:
            tail = b""
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    return False
                window = tail + chunk
                if any(m in window for m in markers):
                    return True
                tail = window[-overlap:]
    except OSError:
        return False


def dump_footer_complete(dump_path: Path) -> bool:
    """mariadb-dump writes a '-- Dump completed' footer on success; its
    absence means a truncated dump that must never be committed or loaded
    (restic backup --stdin cannot know the stream was complete)."""
    try:
        with open(dump_path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 256))
            return b"-- Dump completed" in f.read()
    except OSError:
        return False
