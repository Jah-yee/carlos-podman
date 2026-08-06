# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Unit tests for the shared PITR primitives — the module exists so the
weekly drill and the live restore can never drift; these tests pin the
contract for both at once."""

from pathlib import Path

from carlos_ctl.pitr import (
    IDENTITY_SIDECAR,
    dump_anchor,
    dump_completed_at,
    dump_footer_complete,
    dump_has_content,
    dump_server_identity,
    filter_system_schemas,
    normalize_stop_datetime,
    read_identity_sidecar,
    select_replay_binlogs,
    select_replay_chain,
)


class TestDumpCompletedAt:
    def test_parses_and_zero_pads_the_hour(self, tmp_path: Path) -> None:
        # mariadb-dump space-pads single-digit hours; normalize so the value
        # string-compares against a --stop-datetime.
        f = tmp_path / "dump.sql"
        f.write_text("data\n-- Dump completed on 2026-07-08  1:23:45\n")
        assert dump_completed_at(f) == "2026-07-08 01:23:45"

    def test_padded_hour_passes_through(self, tmp_path: Path) -> None:
        f = tmp_path / "dump.sql"
        f.write_text("data\n-- Dump completed on 2026-07-08 14:30:00\n")
        assert dump_completed_at(f) == "2026-07-08 14:30:00"

    def test_missing_footer_is_none(self, tmp_path: Path) -> None:
        f = tmp_path / "dump.sql"
        f.write_text("no footer here\n")
        assert dump_completed_at(f) is None


class TestDumpAnchor:
    def test_change_master_to_spelling(self, tmp_path: Path) -> None:
        f = tmp_path / "dump.sql"
        f.write_text(
            "-- MariaDB dump\n"
            "-- CHANGE MASTER TO MASTER_LOG_FILE='binlog.000042', MASTER_LOG_POS=1234;\n"
            "CREATE DATABASE oscar;\n"
        )
        a = dump_anchor(f)
        assert a is not None
        assert a.log_file == "binlog.000042"
        assert a.log_pos == "1234"

    def test_change_replication_source_spelling(self, tmp_path: Path) -> None:
        # The newer spelling — the divergence that motivated unification: the
        # drill accepted it while the live restore did not.
        f = tmp_path / "dump.sql"
        f.write_text(
            "-- CHANGE REPLICATION SOURCE TO SOURCE_LOG_FILE='binlog.000007', "
            "SOURCE_LOG_POS=99;\n"
        )
        a = dump_anchor(f)
        assert a is not None
        assert a.log_file == "binlog.000007"
        assert a.log_pos == "99"

    def test_no_anchor_returns_none(self, tmp_path: Path) -> None:
        f = tmp_path / "dump.sql"
        f.write_text("-- MariaDB dump\nCREATE DATABASE oscar;\n")
        assert dump_anchor(f) is None

    def test_scan_is_bounded(self, tmp_path: Path) -> None:
        # An anchor buried past the header scan limit is treated as absent —
        # a multi-GB dump is never read whole.
        f = tmp_path / "dump.sql"
        f.write_text("\n" * 500 + "-- CHANGE MASTER TO MASTER_LOG_FILE='x', "
                     "MASTER_LOG_POS=1;\n")
        assert dump_anchor(f) is None


class TestFilterSystemSchemas:
    DUMP = """\
-- Current Database: `oscar`
CREATE DATABASE `oscar`;
USE `oscar`;
INSERT INTO provider VALUES (1);
-- Current Database: `mysql`
CREATE DATABASE `mysql`;
USE `mysql`;
INSERT INTO user VALUES ('root');
-- Current Database: `drugref2`
CREATE DATABASE `drugref2`;
USE `drugref2`;
INSERT INTO drugs VALUES (1);
"""

    def test_drops_system_keeps_user_schemas(self) -> None:
        out = "".join(filter_system_schemas(self.DUMP.splitlines(keepends=True)))
        assert "CREATE DATABASE `oscar`" in out
        assert "CREATE DATABASE `drugref2`" in out
        assert "INSERT INTO provider" in out
        assert "INSERT INTO drugs" in out
        # Reloading production account rows would clobber the target's auth.
        assert "mysql" not in out.replace("-- Current Database: `mysql`", "")
        assert "INSERT INTO user" not in out

    def test_keeps_create_database_for_user_schemas(self) -> None:
        # Keys off `-- Current Database:` (which PRECEDES CREATE DATABASE),
        # so an empty-target restore keeps CREATE DATABASE — the
        # toggle-on-USE-only form dropped it.
        out = "".join(filter_system_schemas(self.DUMP.splitlines(keepends=True)))
        assert out.index("CREATE DATABASE `oscar`") < out.index("USE `oscar`")

    # A dump whose schema contains views carries a SECOND `-- Current
    # Database:` section per schema at the END (mariadb-dump's temp-table ->
    # view fixup pass) — the drop injection must fire on the FIRST only, or
    # the database is dropped again AFTER its data loaded.
    DUMP_WITH_VIEW_FIXUP = DUMP + """\
-- Current Database: `oscar`
USE `oscar`;
CREATE VIEW v_providers AS SELECT * FROM provider;
"""  # noqa: S608 — dump-shaped test fixture, not query construction

    def test_injects_drop_before_create_for_user_schemas(self) -> None:
        stats: dict = {}
        out = "".join(filter_system_schemas(
            self.DUMP.splitlines(keepends=True), drop_user_schemas=True, stats=stats,
        ))
        for db in ("oscar", "drugref2"):
            drop = f"DROP DATABASE IF EXISTS `{db}`;\n"
            # Present, `;`-terminated + own newline (the pipe writes verbatim),
            # and strictly between the section comment and CREATE DATABASE.
            assert drop in out
            assert out.index(f"-- Current Database: `{db}`") < out.index(drop)
            assert out.index(drop) < out.index(f"CREATE DATABASE `{db}`")
        assert stats["dropped"] == ["oscar", "drugref2"]

    def test_injects_no_drop_for_system_schemas(self) -> None:
        out = "".join(filter_system_schemas(
            self.DUMP.splitlines(keepends=True), drop_user_schemas=True,
        ))
        assert "DROP DATABASE IF EXISTS `mysql`" not in out

    def test_injects_no_drop_when_flag_off(self) -> None:
        out = "".join(filter_system_schemas(self.DUMP.splitlines(keepends=True)))
        assert "DROP DATABASE IF EXISTS" not in out

    def test_injects_drop_once_for_duplicate_schema_sections(self) -> None:
        out = "".join(filter_system_schemas(
            self.DUMP_WITH_VIEW_FIXUP.splitlines(keepends=True),
            drop_user_schemas=True,
        ))
        assert out.count("DROP DATABASE IF EXISTS `oscar`;") == 1
        # ...and that one drop precedes the data, never the view-fixup tail.
        assert out.index("DROP DATABASE IF EXISTS `oscar`;") \
            < out.index("INSERT INTO provider")
        assert "CREATE VIEW v_providers" in out

    def test_reports_empty_dropped_when_dump_has_no_sections(self) -> None:
        stats: dict = {}
        "".join(filter_system_schemas(
            ["INSERT INTO provider VALUES (1);\n"],
            drop_user_schemas=True, stats=stats,
        ))
        assert stats["dropped"] == []


class TestSelectReplayBinlogs:
    def _mk(self, tmp_path: Path, names) -> Path:
        d = tmp_path / "binlog"
        d.mkdir()
        for n in names:
            (d / n).write_text("x")
        return d

    def test_selects_at_and_after_anchor(self, tmp_path: Path) -> None:
        d = self._mk(tmp_path, ["binlog.000001", "binlog.000002", "binlog.000003"])
        assert select_replay_binlogs(d, "binlog.000002") == [
            "binlog.000002", "binlog.000003",
        ]

    def test_excludes_binlog_index(self, tmp_path: Path) -> None:
        # binlog.index sorts AFTER the numeric names and would be fed to
        # mariadb-binlog as if it were a binlog (guaranteed parse error).
        d = self._mk(tmp_path, ["binlog.000001", "binlog.index"])
        assert select_replay_binlogs(d, "binlog.000001") == ["binlog.000001"]

    def test_missing_dir_is_empty(self, tmp_path: Path) -> None:
        assert select_replay_binlogs(tmp_path / "nope", "binlog.000001") == []

    def test_numeric_sort_survives_digit_rollover(self, tmp_path: Path) -> None:
        # MariaDB grows the suffix to 7 digits after binlog.999999; lexically
        # 'binlog.1000000' < 'binlog.999999', so a string compare silently
        # drops the post-rollover files from the chain.
        d = self._mk(tmp_path, ["binlog.999998", "binlog.999999", "binlog.1000000"])
        assert select_replay_binlogs(d, "binlog.999999") == [
            "binlog.999999", "binlog.1000000",
        ]


class TestSelectReplayChain:
    def _mk(self, tmp_path: Path, names) -> Path:
        d = tmp_path / "binlog"
        d.mkdir()
        for n in names:
            (d / n).write_text("x")
        return d

    def test_sound_chain_passes(self, tmp_path: Path) -> None:
        d = self._mk(tmp_path, ["binlog.000002", "binlog.000003", "binlog.000004"])
        files, problem = select_replay_chain(d, "binlog.000002")
        assert problem == ""
        assert files == ["binlog.000002", "binlog.000003", "binlog.000004"]

    def test_absent_anchor_refuses(self, tmp_path: Path) -> None:
        # The dumps-outlive-binlogs case: a >9-day-old dump's anchor file was
        # pruned. --start-position applies only to the FIRST file on the
        # command line — replaying from a later file would apply the position
        # to the wrong file and corrupt the restored database.
        d = self._mk(tmp_path, ["binlog.000040", "binlog.000041"])
        files, problem = select_replay_chain(d, "binlog.000012")
        assert files == []
        assert "binlog.000012" in problem
        assert "IMPOSSIBLE" in problem

    def test_empty_dir_refuses(self, tmp_path: Path) -> None:
        d = self._mk(tmp_path, [])
        files, problem = select_replay_chain(d, "binlog.000012")
        assert files == []
        assert problem != ""

    def test_mid_chain_gap_refuses(self, tmp_path: Path) -> None:
        # A missing middle file would be skipped wordlessly and every
        # transaction it held silently lost from the replayed range.
        d = self._mk(tmp_path, ["binlog.000002", "binlog.000003", "binlog.000005"])
        files, problem = select_replay_chain(d, "binlog.000002")
        assert files == []
        assert "GAP" in problem
        assert "binlog.000005" in problem

    def test_rollover_chain_is_contiguous(self, tmp_path: Path) -> None:
        d = self._mk(tmp_path, ["binlog.999999", "binlog.1000000"])
        files, problem = select_replay_chain(d, "binlog.999999")
        assert problem == ""
        assert files == ["binlog.999999", "binlog.1000000"]


class TestNormalizeStopDatetime:
    def test_iso_t_separator_becomes_space(self) -> None:
        # mariadb-binlog does not parse the ISO 'T' form — a raw 'T' passed
        # to --stop-datetime would fail AFTER the destructive load.
        assert normalize_stop_datetime("2026-07-08T14:30:00") == "2026-07-08 14:30:00"

    def test_bare_date_pads_to_midnight(self) -> None:
        assert normalize_stop_datetime("2026-07-08") == "2026-07-08 00:00:00"

    def test_minutes_only_pads_seconds(self) -> None:
        assert normalize_stop_datetime("2026-07-08T14:30") == "2026-07-08 14:30:00"

    def test_canonical_form_passes_through(self) -> None:
        assert normalize_stop_datetime("2026-07-08 14:30:00") == "2026-07-08 14:30:00"


class TestDumpHasContent:
    def test_create_table_passes(self, tmp_path: Path) -> None:
        f = tmp_path / "dump.sql"
        f.write_text("CREATE TABLE demographic (i int);\n-- Dump completed\n")
        assert dump_has_content(f)

    def test_insert_into_passes(self, tmp_path: Path) -> None:
        f = tmp_path / "dump.sql"
        f.write_text("INSERT INTO provider VALUES (1);\n")
        assert dump_has_content(f)

    def test_footer_only_dump_is_empty(self, tmp_path: Path) -> None:
        # A footer-complete but semantically EMPTY dump must not be committed
        # as the nightly full — it restores nothing.
        f = tmp_path / "dump.sql"
        f.write_text("-- MariaDB dump\nCREATE DATABASE oscar;\n-- Dump completed\n")
        assert not dump_has_content(f)

    def test_marker_straddling_chunk_boundary_is_found(self, tmp_path: Path) -> None:
        f = tmp_path / "dump.sql"
        f.write_bytes(b"x" * 10 + b"CREATE TABLE t (i int);\n")
        assert dump_has_content(f, chunk_size=16)  # marker spans the 16-byte boundary

    def test_missing_file_fails_closed(self, tmp_path: Path) -> None:
        assert not dump_has_content(tmp_path / "nope.sql")


class TestDumpFooter:
    def test_complete_dump_passes(self, tmp_path: Path) -> None:
        f = tmp_path / "dump.sql"
        f.write_text("CREATE DATABASE x;\n" * 100 + "-- Dump completed on 2026-07-08\n")
        assert dump_footer_complete(f)

    def test_truncated_dump_fails(self, tmp_path: Path) -> None:
        f = tmp_path / "dump.sql"
        f.write_text("CREATE DATABASE x;\nINSERT INTO t VAL")
        assert not dump_footer_complete(f)

    def test_missing_file_fails(self, tmp_path: Path) -> None:
        assert not dump_footer_complete(tmp_path / "nope.sql")


class TestChainIdentity:
    """The server-identity capture the replay guard compares: dump header
    comment vs the sidecar riding inside the binlog snapshot."""

    UUID = "11111111-2222-3333-4444-555555555555"

    def test_dump_identity_parses_the_header_comment(self, tmp_path: Path) -> None:
        f = tmp_path / "dump.sql"
        f.write_text(f"-- carlos-server-uuid: {self.UUID}\n-- MariaDB dump\n")
        assert dump_server_identity(f) == self.UUID

    def test_pre_identity_dump_is_unknown(self, tmp_path: Path) -> None:
        f = tmp_path / "dump.sql"
        f.write_text("-- MariaDB dump 10.19\nCREATE DATABASE x;\n")
        assert dump_server_identity(f) == ""

    def test_identity_beyond_the_scan_limit_is_unknown(self, tmp_path: Path) -> None:
        f = tmp_path / "dump.sql"
        f.write_text("-- filler\n" * 20 + f"-- carlos-server-uuid: {self.UUID}\n")
        assert dump_server_identity(f) == ""

    def test_missing_dump_is_unknown(self, tmp_path: Path) -> None:
        assert dump_server_identity(tmp_path / "nope.sql") == ""

    def test_sidecar_roundtrip(self, tmp_path: Path) -> None:
        (tmp_path / IDENTITY_SIDECAR).write_text(self.UUID.upper() + "\n")
        assert read_identity_sidecar(tmp_path) == self.UUID  # normalized lower

    def test_absent_sidecar_is_unknown(self, tmp_path: Path) -> None:
        assert read_identity_sidecar(tmp_path) == ""

    def test_mangled_sidecar_is_unknown_not_trusted(self, tmp_path: Path) -> None:
        (tmp_path / IDENTITY_SIDECAR).write_text("not-a-uuid\n")
        assert read_identity_sidecar(tmp_path) == ""
