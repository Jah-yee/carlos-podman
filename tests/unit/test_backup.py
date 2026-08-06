# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Unit tests for BackupContext credential/tunable resolution — the fail-
closed guards that decide WHERE backups go and WHAT retention applies."""

import os
import subprocess
import time
from pathlib import Path

import pytest

from carlos_ctl.backup import (
    _PITR_UNCONVERTIBLE_TABLES,
    BackupContext,
    _backup_status,
    _is_pitr_unconvertible,
    cmd_backup,
)
from carlos_ctl.util import CtlError


class TestBackupModeArgumentContract:
    """Only `restore` takes arguments. Every other mode used to DROP whatever
    followed it, so `backup full --dry-run` — a flag the usage line advertises
    two words later — silently ran the REAL nightly tier (multi-GB plaintext
    PHI staged, restic snapshot committed, retention advanced) instead of the
    preview the operator asked for."""

    @pytest.mark.parametrize("mode", ["full", "binlogs", "docs", "verify", "status"])
    def test_refuses_trailing_arguments_for_every_non_restore_mode(
        self, mk_runner, mode: str
    ) -> None:
        r = mk_runner()
        with pytest.raises(CtlError, match="takes no arguments"):
            cmd_backup(r, [mode, "--dry-run"])

    def test_refusal_names_the_dropped_arguments_and_the_one_mode_with_flags(
        self, mk_runner
    ) -> None:
        r = mk_runner()
        with pytest.raises(CtlError) as e:
            cmd_backup(r, ["full", "--dry-run", "--bogus", "extra"])
        msg = str(e.value)
        assert "--dry-run --bogus extra" in msg
        assert "backup restore" in msg

    def test_refusal_fires_before_the_repo_lock_and_credential_lookup(
        self, mk_runner
    ) -> None:
        # No restic.env exists here; a refusal that ran AFTER ensure_repo()
        # would surface the credential error instead of the argument one.
        r = mk_runner()
        with pytest.raises(CtlError, match="takes no arguments"):
            cmd_backup(r, ["full", "--dry-run"])

    def test_bare_status_still_runs(self, mk_runner) -> None:
        # The guard must not break the argument-less forms.
        r = mk_runner()
        assert _backup_status(r) == 1
        assert cmd_backup(r, ["status"]) == 1

    def test_unknown_mode_still_reports_usage(self, mk_runner) -> None:
        r = mk_runner()
        with pytest.raises(CtlError, match="usage: carlos-ctl backup"):
            cmd_backup(r, ["bogus"])


class TestBackupStatus:
    def test_missing_stamps_report_and_exit_nonzero(self, mk_runner, capsys) -> None:
        r = mk_runner()
        assert _backup_status(r) == 1
        out = capsys.readouterr().out
        assert "MISSING" in out
        assert "restore drill" in out

    def test_fresh_stamps_read_green(self, mk_runner, capsys) -> None:
        r = mk_runner()
        d = r.settings.emr_home / "backup"
        d.mkdir(parents=True, exist_ok=True)
        for stamp in (".last-full-ok", ".last-binlog-ok", ".last-docs-ok",
                      ".last-verify-ok"):
            (d / stamp).touch()
        (d / ".repo-posture").write_text("offsite\n")
        assert _backup_status(r) == 0
        out = capsys.readouterr().out
        assert "OFFSITE" in out
        assert "STALE" not in out


def _write_restic_env(runner, lines: str) -> Path:
    d = runner.settings.conf_dir / "restic"
    d.mkdir(parents=True, exist_ok=True)
    f = d / "restic.env"
    f.write_text(lines)
    return f


class TestRepositoryResolution:
    def test_missing_repository_refuses_despite_settings_default(self, mk_runner) -> None:
        # Settings ALWAYS injects a local default for RESTIC_REPOSITORY, so a
        # tunable()-style fallback would make this guard dead and silently
        # retarget a sealed install (bundle lost the line) to a fresh LOCAL
        # repo — stamps green while the real offsite repository rots.
        r = mk_runner()
        _write_restic_env(r, "RESTIC_PASSWORD=pw\n")
        with pytest.raises(CtlError, match="no RESTIC_REPOSITORY"):
            BackupContext(r)

    def test_repository_comes_from_restic_env_only(self, mk_runner) -> None:
        r = mk_runner()
        _write_restic_env(r, "RESTIC_PASSWORD=pw\nRESTIC_REPOSITORY=s3:bucket/repo\n")
        ctx = BackupContext(r)
        assert ctx.repository == "s3:bucket/repo"
        assert ctx.repo_mount == []  # remote backend: no bind mount
        ctx.close()

    def test_empty_restic_password_refuses(self, mk_runner) -> None:
        # A blank RESTIC_PASSWORD (the template-variable-mismatch regression)
        # makes restic block on an interactive prompt that never comes — fail
        # loudly with the provisioning cause, not an obscure restic error.
        r = mk_runner()
        _write_restic_env(r, "RESTIC_REPOSITORY=s3:bucket/repo\nRESTIC_PASSWORD=\n")
        with pytest.raises(CtlError, match="RESTIC_PASSWORD is empty"):
            BackupContext(r)


class TestTunablePrecedence:
    def test_restic_env_wins_over_settings(self, mk_runner) -> None:
        r = mk_runner("BACKUP_KEEP=--keep-daily 30\n")
        _write_restic_env(
            r,
            "RESTIC_PASSWORD=pw\nRESTIC_REPOSITORY=s3:bucket/repo\n"
            "BACKUP_KEEP=--keep-daily 99\n",
        )
        ctx = BackupContext(r)
        assert ctx.keep == ["--keep-daily", "99"]
        ctx.close()

    def test_settings_win_over_builtin_default(self, mk_runner) -> None:
        # The regression the tunable() helper fixed: reading restic.env only
        # would silently revert site-set retention (carlos-app.env / process
        # env) to the 7-day default and restic forget would expire dumps the
        # operator believed retained.
        r = mk_runner("BACKUP_KEEP=--keep-daily 30\n")
        _write_restic_env(r, "RESTIC_PASSWORD=pw\nRESTIC_REPOSITORY=s3:bucket/repo\n")
        ctx = BackupContext(r)
        assert ctx.keep == ["--keep-daily", "30"]
        ctx.close()

    def test_builtin_default_when_unset_everywhere(self, mk_runner) -> None:
        r = mk_runner()
        _write_restic_env(r, "RESTIC_PASSWORD=pw\nRESTIC_REPOSITORY=s3:bucket/repo\n")
        ctx = BackupContext(r)
        assert ctx.keep == "--keep-daily 7 --keep-weekly 5 --keep-monthly 12".split()
        ctx.close()


class TestVerifyMemLimit:
    def test_default_derives_from_tmpfs_size(self, mk_runner) -> None:
        # The drill's tmpfs pages count against ITS cgroup: an unset cap lets
        # an oversized dump pressure host RAM (and OOM a live pod) instead of
        # OOMing the drill. Default = tmpfs + 2 GiB of mariadbd overhead.
        r = mk_runner()
        _write_restic_env(r, "RESTIC_PASSWORD=pw\nRESTIC_REPOSITORY=s3:bucket/repo\n")
        ctx = BackupContext(r)
        assert ctx.verify_tmpfs_size == "4g"
        assert ctx.verify_mem_limit == "6144m"
        ctx.close()

    def test_explicit_limit_wins(self, mk_runner) -> None:
        r = mk_runner()
        _write_restic_env(
            r,
            "RESTIC_PASSWORD=pw\nRESTIC_REPOSITORY=s3:bucket/repo\n"
            "VERIFY_TMPFS_SIZE=8g\nVERIFY_MEM_LIMIT=12g\n",
        )
        ctx = BackupContext(r)
        assert ctx.verify_mem_limit == "12g"
        ctx.close()

    def test_zero_disables_the_cap(self, mk_runner) -> None:
        r = mk_runner()
        _write_restic_env(
            r,
            "RESTIC_PASSWORD=pw\nRESTIC_REPOSITORY=s3:bucket/repo\nVERIFY_MEM_LIMIT=0\n",
        )
        ctx = BackupContext(r)
        assert ctx.verify_mem_limit == ""
        ctx.close()

    def test_unparseable_tmpfs_size_leaves_cap_unset(self, mk_runner) -> None:
        r = mk_runner()
        _write_restic_env(
            r,
            "RESTIC_PASSWORD=pw\nRESTIC_REPOSITORY=s3:bucket/repo\n"
            "VERIFY_TMPFS_SIZE=weird%\n",
        )
        ctx = BackupContext(r)
        assert ctx.verify_mem_limit == ""
        ctx.close()


class TestVerifyDrillServer:
    def test_drill_server_mirrors_the_1g_packet_ceiling(self, mk_runner) -> None:
        # Finding M4: the live server's max_allowed_packet was raised to 1G
        # (hex-blob dumps double blob bytes; the reload client's 1G cannot
        # exceed the server cap). The drill's throwaway server mounts no
        # zz-carlos.cnf, so it must mirror that ceiling or a dump the LIVE
        # server reloads fine fails only in the drill (false alarm).
        from carlos_ctl.backup import _verify_restore

        r = mk_runner(env_lines="CARLOS_DOCS_MIN_FILES=0\n")
        _write_restic_env(r, "RESTIC_PASSWORD=pw\nRESTIC_REPOSITORY=s3:bucket/repo\n")
        ctx = BackupContext(r)
        # Fail the drill at the throwaway-server start: the argv is recorded
        # before the returncode is inspected, which is all this test needs.
        r.script("podman", "run", "-d", rc=1)
        assert _verify_restore(ctx) is False
        run_calls = [c for c in r.calls if c[:3] == ["podman", "run", "-d"]]
        assert run_calls, "the drill never attempted to start the throwaway server"
        assert "--max-allowed-packet=1G" in run_calls[0]
        assert not any("--max-allowed-packet=256M" in c for c in r.calls)
        ctx.close()

    def test_readiness_gate_is_not_a_bare_socket_ping(self, mk_runner) -> None:
        # Tenth-pass finding: `mariadb-admin ping` over the UNIX SOCKET is
        # satisfied by the mariadb image entrypoint's INITIALIZATION temp
        # server, which is then shut down before the real server starts —
        # measured live: socket ping OK at 3.6 s, socket gone 4.5-6.4 s, real
        # server at 6.5 s. The drill broke out of the wait on that false
        # ready and failed the load with a raw "ERROR 2002 ... (2)" under the
        # misleading VERIFY_TMPFS_SIZE message, on EVERY run. The temp server
        # runs --skip-networking, so the gate must be the image healthcheck
        # or a TCP ping (what the pod specs' db readinessProbe already uses).
        from carlos_ctl.backup import _verify_restore

        r = mk_runner(env_lines="CARLOS_DOCS_MIN_FILES=0\n")
        _write_restic_env(r, "RESTIC_PASSWORD=pw\nRESTIC_REPOSITORY=s3:bucket/repo\n")
        ctx = BackupContext(r)
        # First exec (the readiness probe) succeeds; stop the drill right
        # after by failing the restic dump — the probe argv is all we need.
        r.script("restic", rc=1)
        assert _verify_restore(ctx) is False
        probes = [
            c for c in r.calls
            if c[:2] == ["podman", "exec"] and any("-verify-" in a for a in c)
        ]
        assert probes, "the drill never probed the throwaway server"
        probe = " ".join(probes[0])
        assert "healthcheck.sh --connect" in probe or "--protocol=tcp" in probe, probe
        # The bare socket ping must not be the gate on its own.
        assert not any(
            c[-3:] == ["mariadb-admin", "--user=root", "ping"] for c in probes
        ), probes[0]
        ctx.close()

    def test_never_ready_scratch_server_fails_with_the_right_message(
            self, mk_runner, monkeypatch, capsys) -> None:
        # Pass-8 L1: ping-loop exhaustion used to fall through into the dump
        # load, whose failure message blames VERIFY_TMPFS_SIZE — a misleading
        # diagnosis for a scratch server that never came up (seen live under
        # image-pull contention). Exhaustion must be terminal, with a message
        # naming the real condition.
        from carlos_ctl.backup import _verify_restore

        r = mk_runner(env_lines="CARLOS_DOCS_MIN_FILES=0\n")
        _write_restic_env(r, "RESTIC_PASSWORD=pw\nRESTIC_REPOSITORY=s3:bucket/repo\n")
        ctx = BackupContext(r)
        # `podman run -d` succeeds (default rc=0) but every exec — the ping
        # loop included — fails: the 60x2s wait must not sleep for real.
        r.script("podman", "exec", rc=1)
        monkeypatch.setattr(time, "sleep", lambda _s: None)
        assert _verify_restore(ctx) is False
        err = capsys.readouterr().err
        assert "never became ready" in err
        # The old, misleading dump-load diagnosis must be gone...
        assert "could not load carlos-databases.sql" not in err
        # ...because it fails BEFORE any restore/load attempt against the
        # dead server.
        assert not any("carlos-databases.sql" in " ".join(c) for c in r.calls)
        ctx.close()


class TestRestoreToLatestOrdering:
    """Finding M5: the final binlog ship must run AFTER the confirm gate and
    AFTER the carlos/drugref stop, so writes made during the confirmation
    prompt are captured; the chain fetch+validation follows the ship."""

    def _wire(self, r, monkeypatch, *, chain_problem=None):
        import carlos_ctl.backup as backup_mod
        from carlos_ctl.backup import BackupContext
        from carlos_ctl.pitr import Anchor

        pitr_mod = backup_mod.pitr
        monkeypatch.setattr(pitr_mod, "dump_footer_complete", lambda p: True)
        monkeypatch.setattr(
            pitr_mod, "dump_anchor", lambda p, scan_limit=200: Anchor("binlog.000002", "4")
        )
        monkeypatch.setattr(pitr_mod, "dump_completed_at", lambda p: "2026-01-01 00:00:00")
        monkeypatch.setattr(pitr_mod, "dump_server_identity", lambda p: "srv-A")
        monkeypatch.setattr(pitr_mod, "newest_local_binlog_seq", lambda d: 3)
        monkeypatch.setattr(pitr_mod, "read_identity_sidecar", lambda d: "srv-A")
        monkeypatch.setattr(
            pitr_mod, "select_replay_chain",
            lambda bdir, log_file: (
                ([], chain_problem) if chain_problem
                else (["binlog.000002", "binlog.000003"], None)
            ),
        )
        # The dump load pipes through raw Popen (unrunnable here) — spy it
        # with a recognizable marker call so ordering is assertable, and
        # record the kwargs so the drop-and-recreate flag is pinnable.
        load_kwargs: list = []

        def _load_spy(runner, dump, args, env, **kwargs):
            load_kwargs.append({"args": list(args), **kwargs})
            return bool(runner.run(["dump-load-marker"]))

        monkeypatch.setattr(backup_mod, "_pipe_filtered_dump", _load_spy)
        _write_restic_env(r, "RESTIC_PASSWORD=pw\nRESTIC_REPOSITORY=s3:bucket/repo\n")
        props = r.settings.properties_file
        props.parent.mkdir(parents=True, exist_ok=True)
        props.write_text("db_username=root\ndb_password=apppw\n")
        pod = r.settings.app_pod
        r.script("podman", "ps",
                 out=f"{pod}-db\n{pod}-carlos\n{pod}-drugref\n")
        ctx = BackupContext(r)
        # Ship spy: a marker call in r.calls marks WHEN the ship happened.
        ctx.ship_binlogs = lambda: bool(r.run(["ship-binlogs-marker"]))  # type: ignore[method-assign]
        ctx.test_load_kwargs = load_kwargs  # type: ignore[attr-defined]
        return ctx

    @staticmethod
    def _idx(r, *parts):
        for i, c in enumerate(r.calls):
            if all(p in c for p in parts):
                return i
        return None

    def test_live_restore_stops_confirms_then_ships_then_fetches_then_loads(
        self, mk_runner, monkeypatch
    ) -> None:
        from carlos_ctl.backup import _restore_pitr

        r = mk_runner(
            env_lines="CARLOS_DB_ROOT_PASSWORD=rootpw\n"
                      "CARLOS_RESTORE_CONFIRMED=carlos\n"
        )
        ctx = self._wire(r, monkeypatch)
        assert _restore_pitr(ctx, []) is True
        # The live load must request drop-and-recreate semantics (merge-load
        # left post-dump tables in place and the replayed CREATE aborted).
        assert ctx.test_load_kwargs, "the dump load never ran"
        assert ctx.test_load_kwargs[0].get("drop_user_schemas") is True
        stop_i = self._idx(r, "stop", "-t", "20")
        ship_i = self._idx(r, "ship-binlogs-marker")
        fetch_i = self._idx(r, "restore", "latest", "binlog")
        load_i = self._idx(r, "dump-load-marker")
        assert None not in (stop_i, ship_i, fetch_i, load_i), r.calls
        assert stop_i < ship_i < fetch_i < load_i, (
            f"expected stop({stop_i}) < ship({ship_i}) < fetch({fetch_i}) "
            f"< load({load_i})"
        )

    def test_dry_run_never_stops_ships_or_loads(self, mk_runner, monkeypatch) -> None:
        from carlos_ctl.backup import _restore_pitr

        # No confirmation env: --dry-run must succeed without one.
        r = mk_runner(env_lines="CARLOS_DB_ROOT_PASSWORD=rootpw\n")
        ctx = self._wire(r, monkeypatch)
        assert _restore_pitr(ctx, ["--dry-run"]) is True
        assert self._idx(r, "stop", "-t", "20") is None
        assert self._idx(r, "ship-binlogs-marker") is None
        assert self._idx(r, "dump-load-marker") is None
        # The dry plan still fetches the chain for an exact replay count.
        assert self._idx(r, "restore", "latest", "binlog") is not None

    def test_post_stop_chain_failure_aborts_before_load(
        self, mk_runner, monkeypatch, capsys
    ) -> None:
        from carlos_ctl.backup import _restore_pitr

        r = mk_runner(
            env_lines="CARLOS_DB_ROOT_PASSWORD=rootpw\n"
                      "CARLOS_RESTORE_CONFIRMED=carlos\n"
        )
        ctx = self._wire(r, monkeypatch, chain_problem="binlog anchor pruned")
        assert _restore_pitr(ctx, []) is False
        assert self._idx(r, "stop", "-t", "20") is not None
        assert self._idx(r, "dump-load-marker") is None
        err = capsys.readouterr().err
        assert "STOPPED" in err and "carlos-ctl play" in err

    def test_failed_final_ship_refuses_before_load(
        self, mk_runner, monkeypatch, capsys
    ) -> None:
        # M2: restore-to-latest exists to capture EVERY committed write. If the
        # final ship fails, the fetched chain is stale — refuse before the drop.
        from carlos_ctl.backup import _restore_pitr

        r = mk_runner(
            env_lines="CARLOS_DB_ROOT_PASSWORD=rootpw\nCARLOS_RESTORE_CONFIRMED=carlos\n"
        )
        ctx = self._wire(r, monkeypatch)
        ctx.ship_binlogs = lambda: False  # type: ignore[method-assign]
        assert _restore_pitr(ctx, []) is False
        assert self._idx(r, "dump-load-marker") is None
        err = capsys.readouterr().err
        assert "final binlog ship FAILED" in err
        assert "CARLOS_RESTORE_ACCEPT_UNSHIPPED" in err

    def test_failed_final_ship_proceeds_with_override(
        self, mk_runner, monkeypatch
    ) -> None:
        from carlos_ctl.backup import _restore_pitr

        r = mk_runner(
            env_lines="CARLOS_DB_ROOT_PASSWORD=rootpw\nCARLOS_RESTORE_CONFIRMED=carlos\n"
                      "CARLOS_RESTORE_ACCEPT_UNSHIPPED=1\n"
        )
        ctx = self._wire(r, monkeypatch)
        ctx.ship_binlogs = lambda: False  # type: ignore[method-assign]
        assert _restore_pitr(ctx, []) is True
        assert self._idx(r, "dump-load-marker") is not None


class TestDrEnvAllowlist:
    """Finding S10: the DR site-identity copy keeps only KNOWN, non-secret
    keys — an operator's custom secret with an unrecognizable name must be
    dropped (and warned), never ride into the backup."""

    def _stage(self, r, env_text: str):
        from carlos_ctl.backup import _stage_dr_env

        r.settings.env_file.write_text(env_text)
        _stage_dr_env(r.settings)
        return (r.settings.emr_home / "container" / "carlos-app.env.dr").read_text()

    def test_identity_kept_secrets_and_unknowns_dropped(
        self, mk_runner, capsys
    ) -> None:
        r = mk_runner()
        out = self._stage(
            r,
            "# site\n"
            "SERVER_NAME=emr.clinic.ca\n"
            "BIND_IP=192.0.2.10\n"
            "CARLOS_DB_ROOT_PASSWORD=supersecret\n"
            "ALERT_WEBHOOK=https://hooks/capability\n"
            "SMTP_AUTH=user:hunter2\n",
        )
        assert "SERVER_NAME=emr.clinic.ca" in out
        assert "BIND_IP=192.0.2.10" in out
        assert "supersecret" not in out
        assert "hooks/capability" not in out
        assert "hunter2" not in out
        err = capsys.readouterr().err
        assert "SMTP_AUTH" in err  # dropped-unknown warned by name
        assert "supersecret" not in err  # values never echoed

    def test_comments_and_blanks_survive(self, mk_runner) -> None:
        r = mk_runner()
        out = self._stage(r, "# a comment\n\nSERVER_NAME=x.ca\n")
        assert "# a comment" in out
        assert "SERVER_NAME=x.ca" in out

    def test_stagedCopyIsWorldReadable_forRootlessResticRead(
        self, mk_runner, monkeypatch
    ) -> None:
        # The .dr copy exists to ride in the rootless `files` snapshot; a
        # root-0600 file is unreadable there (root is unmapped in the service
        # user's userns) and fails every nightly full. Non-secret by
        # construction, so 0644 — regardless of the caller's umask.
        import os as _os

        old = _os.umask(0o077)
        try:
            r = mk_runner()
            self._stage(r, "SERVER_NAME=x.ca\n")
            dr = r.settings.emr_home / "container" / "carlos-app.env.dr"
            assert dr.stat().st_mode & 0o777 == 0o644
        finally:
            _os.umask(old)


class TestVerifyDrillTmpfsPreflight:
    def test_oversize_snapshot_warns_but_drill_continues(
        self, mk_runner, capsys
    ) -> None:
        # C23: the drill loads the whole DB into a RAM tmpfs; outgrowing it
        # must warn ahead of time instead of failing every week unexplained.
        from carlos_ctl.backup import _verify_restore

        r = mk_runner(env_lines="CARLOS_DOCS_MIN_FILES=0\n")
        _write_restic_env(r, "RESTIC_PASSWORD=pw\nRESTIC_REPOSITORY=s3:bucket/repo\n")
        ctx = BackupContext(r)
        # 8 GiB restore size vs the 4g default tmpfs.
        r.script("stats", rc=0, out='{"total_size": 8589934592}\n')
        r.script("podman", "run", "-d", rc=1)  # stop the drill after preflight
        assert _verify_restore(ctx) is False
        err = capsys.readouterr().err
        assert "VERIFY_TMPFS_SIZE" in err
        ctx.close()


class TestPerModeRetention:
    def test_binlog_mode_applies_its_own_forget(self, mk_runner, monkeypatch) -> None:
        # C23: binlog/docs snapshots must not depend on the nightly full for
        # retention (failing fulls let 15-min snapshots grow unbounded).
        from carlos_ctl.backup import BackupContext, cmd_backup

        r = mk_runner()
        _write_restic_env(r, "RESTIC_PASSWORD=pw\nRESTIC_REPOSITORY=s3:bucket/repo\n")
        monkeypatch.setattr(BackupContext, "ensure_repo", lambda self: None)
        monkeypatch.setattr(
            BackupContext, "ship_binlogs",
            lambda self: setattr(self, "binlog_shipped", True) or True,
        )
        # Binlog forget only runs while nightly fulls are FRESH (review
        # finding: age-expiring binlogs during a full-backup outage would
        # erode the only chain that can roll a stale dump forward).
        stamp_dir = r.settings.emr_home / "backup"
        stamp_dir.mkdir(parents=True, exist_ok=True)
        (stamp_dir / ".last-full-ok").touch()
        assert cmd_backup(r, ["binlogs"]) == 0
        forgets = [c for c in r.calls if "forget" in c and "binlog" in c]
        assert forgets, "binlog mode never ran its own forget"
        assert not any("--prune" in c for c in forgets)  # prune stays nightly

    def test_binlog_forget_deferred_while_fulls_are_stale(
        self, mk_runner, monkeypatch, capsys
    ) -> None:
        from carlos_ctl.backup import BackupContext, cmd_backup

        r = mk_runner()
        _write_restic_env(r, "RESTIC_PASSWORD=pw\nRESTIC_REPOSITORY=s3:bucket/repo\n")
        monkeypatch.setattr(BackupContext, "ensure_repo", lambda self: None)
        monkeypatch.setattr(
            BackupContext, "ship_binlogs",
            lambda self: setattr(self, "binlog_shipped", True) or True,
        )
        # No .last-full-ok at all: the replay chain must be preserved.
        assert cmd_backup(r, ["binlogs"]) == 0
        assert not any("forget" in c for c in r.calls)
        assert "retention deferred" in capsys.readouterr().out


class TestNoShipRestoreValidatesPreConfirm:
    def test_stop_datetime_chain_failure_refuses_before_any_disruption(
        self, mk_runner, monkeypatch, capsys
    ) -> None:
        # A NO-SHIP restore (local binlogs do not continue this dump's
        # chain — a DR rebuild) validates the chain BEFORE the confirmation
        # gate — refusals then happen with the app still serving (no stop,
        # no confirm needed, no "STOPPED" hint).
        import carlos_ctl.backup as backup_mod
        from carlos_ctl.backup import _restore_pitr

        r = mk_runner(env_lines="CARLOS_DB_ROOT_PASSWORD=rootpw\n")
        helper = TestRestoreToLatestOrdering()
        ctx = helper._wire(r, monkeypatch, chain_problem="binlog anchor pruned")
        # Fresh-server local binlogs (seq 1 < anchor seq 2): nothing to ship.
        monkeypatch.setattr(backup_mod.pitr, "newest_local_binlog_seq", lambda d: 1)
        assert _restore_pitr(ctx, ["--stop-datetime", "2026-02-01 00:00:00"]) is False
        assert helper._idx(r, "stop", "-t", "20") is None
        assert helper._idx(r, "dump-load-marker") is None
        err = capsys.readouterr().err
        assert "STOPPED" not in err


class TestStopDatetimePostdatesChain:
    """M3: a --stop-datetime after the newest shipped binlog cannot be honored
    (the events between the last ship and the target live only in the
    unshipped active binlog). Refuse in the pre-confirm path — app still
    serving — rather than replay short and report success."""

    def _wire_with_binlogs(self, r, monkeypatch, *, close_epoch):
        helper = TestRestoreToLatestOrdering()
        ctx = helper._wire(r, monkeypatch)
        real = ctx.run_restic

        def spy(args, **kw):
            if list(args)[:2] == ["restore", "latest"]:
                scratch = Path(ctx.extra_mount[1].split(":")[0])
                bdir = scratch / "binlog" / "backup" / "binlog"
                bdir.mkdir(parents=True, exist_ok=True)
                for name in ("binlog.000002", "binlog.000003"):
                    f = bdir / name
                    f.write_text("x")
                    os.utime(f, (close_epoch, close_epoch))
                return subprocess.CompletedProcess(args, 0, "", "")
            return real(args, **kw)

        ctx.run_restic = spy  # type: ignore[method-assign]
        return ctx, helper

    def test_stop_past_chain_end_refuses_pre_confirm(
        self, mk_runner, monkeypatch, capsys
    ) -> None:
        import carlos_ctl.backup as backup_mod
        from carlos_ctl.backup import _restore_pitr

        r = mk_runner(env_lines="CARLOS_DB_ROOT_PASSWORD=rootpw\n")
        old = time.time() - 86400  # newest shipped binlog closed a day ago
        ctx, helper = self._wire_with_binlogs(r, monkeypatch, close_epoch=old)
        # No-ship scenario (fresh-server local binlogs, seq 1 < anchor seq 2):
        # a stop restore whose local binlogs DO continue the chain ships them
        # after the confirm/app-stop instead, extending the chain to now — the
        # pre-confirm M3 refusal is specifically the no-ship path's guard.
        monkeypatch.setattr(backup_mod.pitr, "newest_local_binlog_seq", lambda d: 1)
        future = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() + 86400))
        assert _restore_pitr(ctx, ["--stop-datetime", future]) is False
        assert helper._idx(r, "stop", "-t", "20") is None  # app never stopped
        assert helper._idx(r, "dump-load-marker") is None
        err = capsys.readouterr().err
        assert "POSTDATES the newest shipped binlog" in err
        assert "STOPPED" not in err

    def test_stop_past_chain_end_proceeds_with_override(
        self, mk_runner, monkeypatch, capsys
    ) -> None:
        from carlos_ctl.backup import _restore_pitr

        r = mk_runner(
            env_lines="CARLOS_DB_ROOT_PASSWORD=rootpw\n"
                      "CARLOS_RESTORE_CONFIRMED=carlos\n"
                      "CARLOS_STOP_PAST_CHAIN_END_OK=1\n"
        )
        old = time.time() - 86400
        ctx, helper = self._wire_with_binlogs(r, monkeypatch, close_epoch=old)
        future = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() + 86400))
        assert _restore_pitr(ctx, ["--stop-datetime", future]) is True
        assert helper._idx(r, "dump-load-marker") is not None
        assert "POSTDATES" not in capsys.readouterr().err


class TestDryRunWillShipDoesNotFalselyRefuse:
    """Ninth-pass: a --dry-run that WILL ship (local binlogs continue the
    dump's chain) must not refuse a past --stop-datetime — the real run ships
    the active binlog and reaches it, so the dry-run must reflect that plan
    rather than coach CARLOS_STOP_PAST_CHAIN_END_OK for a refusal the live run
    would never make."""

    def test_dry_run_will_ship_plans_instead_of_refusing(
        self, mk_runner, monkeypatch, capsys
    ) -> None:
        from carlos_ctl.backup import _restore_pitr

        r = mk_runner(env_lines="CARLOS_DB_ROOT_PASSWORD=rootpw\n")
        helper = TestRestoreToLatestOrdering()
        ctx = helper._wire(r, monkeypatch)  # default wiring = local continues chain
        future = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() + 86400))
        assert _restore_pitr(ctx, ["--dry-run", "--stop-datetime", future]) is True
        err = capsys.readouterr().err
        assert "REFUSING" not in err
        assert "past the currently shipped chain" in err
        # A dry-run never stops the app.
        assert helper._idx(r, "stop", "-t", "20") is None


class TestStopDatetimeRestoreShips:
    def test_shipsLocalBinlogs_whenChainContinues_soStopInstantIsReachable(
        self, mk_runner, monkeypatch
    ) -> None:
        # The repo chain ends at the last 15-minute timer fire; a stop
        # instant PAST that end replays to the chain's end and exits 0
        # (mariadb-binlog never errors on an unreached --stop-datetime) —
        # silent under-restore. With local binlogs continuing the dump's
        # chain, the restore must SHIP them (after the app-stop) so the
        # chain reaches the requested instant; the replay's --stop-datetime
        # clause still cuts precisely.
        from carlos_ctl.backup import _restore_pitr

        r = mk_runner(
            env_lines="CARLOS_DB_ROOT_PASSWORD=rootpw\n"
                      "CARLOS_RESTORE_CONFIRMED=carlos\n"
        )
        helper = TestRestoreToLatestOrdering()
        ctx = helper._wire(r, monkeypatch)
        assert _restore_pitr(ctx, ["--stop-datetime", "2026-02-01 00:00:00"]) is True
        stop_i = helper._idx(r, "stop", "-t", "20")
        ship_i = helper._idx(r, "ship-binlogs-marker")
        replay_i = next(
            (i for i, c in enumerate(r.calls)
             if any("--stop-datetime='2026-02-01 00:00:00'" in part for part in c)),
            None,
        )
        assert None not in (stop_i, ship_i, replay_i), r.calls
        assert stop_i < ship_i < replay_i


class TestStopDatetimeEpoch:
    """The past-chain-end guard's stop instant must be interpreted in the DB
    CONTAINER's timezone (mariadb-binlog evaluates --stop-datetime there),
    not the host's — a UTC host with a Toronto container was off by 4-5h,
    silently passing targets the guard exists to refuse."""

    def test_epoch_is_container_zone_not_host_zone(self) -> None:
        from carlos_ctl.backup import stop_datetime_epoch

        # 2026-08-01 12:00 Toronto (EDT, UTC-4) == 16:00:00Z
        assert stop_datetime_epoch("2026-08-01 12:00:00", "America/Toronto") == 1785600000.0

    def test_epoch_utc(self) -> None:
        from carlos_ctl.backup import stop_datetime_epoch

        assert stop_datetime_epoch("2026-08-01 12:00:00", "UTC") == 1785585600.0

    def test_unusable_inputs_return_zero_for_guard_skip(self) -> None:
        from carlos_ctl.backup import stop_datetime_epoch

        assert stop_datetime_epoch("not-a-date", "UTC") == 0.0
        assert stop_datetime_epoch("2026-08-01 12:00:00", "Not/AZone") == 0.0


class TestServerIdentity:
    """The binlog chain-pollution defense keys ENTIRELY on a non-empty
    server_identity(): the ship-time gate, the snapshot sidecar, the drill's
    identity check and the restore's mismatch refusal all short-circuit on ''.
    The original probe asked for @@server_uuid — a MySQL variable MariaDB
    answers with `ERROR 1193 Unknown system variable` — so every CARLOS
    deployment ran with that whole defense silently inert. These pin the
    datadir-resident fallback that keeps it working on MariaDB."""

    def _ctx(self, mk_runner, tmp_path):
        r = mk_runner()
        d = r.settings.conf_dir / "restic"
        d.mkdir(parents=True, exist_ok=True)
        (d / "restic.env").write_text(
            f"RESTIC_REPOSITORY={r.settings.emr_home}/backup/repo\nRESTIC_PASSWORD=x\n"
        )
        return BackupContext(r), r

    def _init_datadir(self, runner) -> None:
        (runner.settings.data_dir / "mariadb-mnt" / "mysql").mkdir(parents=True, exist_ok=True)

    def test_mysql_server_uuid_is_used_when_the_server_has_one(
        self, mk_runner, tmp_path
    ) -> None:
        ctx, r = self._ctx(mk_runner, tmp_path)
        ctx._server_identity = None
        r.script("SELECT @@server_uuid", out="3fa1c0de-1111-4222-8333-444455556666\n")
        assert ctx.server_identity() == "3fa1c0de-1111-4222-8333-444455556666"

    def test_mariadb_unknown_variable_falls_back_to_a_minted_datadir_id(
        self, mk_runner, tmp_path
    ) -> None:
        ctx, r = self._ctx(mk_runner, tmp_path)
        self._init_datadir(r)
        ctx._server_identity = None
        r.script("SELECT @@server_uuid", rc=1, out="")
        ident = ctx.server_identity()
        assert len(ident) == 36, ident
        marker = r.settings.data_dir / "mariadb-mnt" / ".carlos-server-identity"
        assert marker.read_text().strip() == ident
        # 0644 so mariadb-backup and the rootless restic userns can read it.
        assert oct(marker.stat().st_mode)[-3:] == "644"

    def test_minted_id_is_stable_across_runs(self, mk_runner, tmp_path) -> None:
        ctx, r = self._ctx(mk_runner, tmp_path)
        self._init_datadir(r)
        r.script("SELECT @@server_uuid", rc=1, out="")
        ctx._server_identity = None
        first = ctx.server_identity()
        ctx._server_identity = None
        assert ctx.server_identity() == first

    def test_uninitialized_datadir_mints_nothing(self, mk_runner, tmp_path) -> None:
        """An unmounted/blank data volume must NOT be handed a lineage id —
        that would fabricate a continuation for a datadir that is not there."""
        ctx, r = self._ctx(mk_runner, tmp_path)
        ctx._server_identity = None
        r.script("SELECT @@server_uuid", rc=1, out="")
        assert ctx.server_identity() == ""
        assert not (r.settings.data_dir / "mariadb-mnt" / ".carlos-server-identity").exists()


class TestPitrUnconvertibleAllowlist:
    """The engine audit must not refuse over a table that CANNOT be made
    InnoDB — formRourke2009 has 1227 columns, past InnoDB's 1017 hard limit,
    so `ALTER TABLE ... ENGINE=InnoDB` fails with errno 185 under every
    ROW_FORMAT (verified live 2026-08-02). Refusing on every fresh ON/BC
    install for a condition with no remedy just trains operators to set the
    blanket CARLOS_ALLOW_NON_INNODB=1, which would then also mask a table
    that COULD have been converted."""

    def test_recognises_the_known_unconvertible_table(self) -> None:
        assert _is_pitr_unconvertible("oscar.formRourke2009 [Aria]")

    def test_is_schema_agnostic(self) -> None:
        # A site may not name the schema `oscar`.
        assert _is_pitr_unconvertible("legacyemr.formRourke2009 [Aria]")

    def test_is_case_insensitive(self) -> None:
        # MariaDB table names are case-sensitive on Linux and the upstream
        # DDL casing has drifted across migrations.
        assert _is_pitr_unconvertible("oscar.FORMROURKE2009 [Aria]")
        assert _is_pitr_unconvertible("oscar.formrourke2009 [MyISAM]")

    def test_an_ordinary_table_is_not_allowlisted(self) -> None:
        # This one is convertible, so it must keep BLOCKING the dump.
        assert not _is_pitr_unconvertible("oscar.legacy [MyISAM]")
        assert not _is_pitr_unconvertible("oscar.demographic [MyISAM]")

    def test_a_lookalike_name_is_not_allowlisted(self) -> None:
        # Substring matching would wrongly accept a different, convertible
        # table; the match is on the whole bare table name.
        assert not _is_pitr_unconvertible("oscar.formRourke2009_archive [Aria]")
        assert not _is_pitr_unconvertible("oscar.myformRourke2009 [Aria]")

    def test_the_other_rourke_versions_are_not_allowlisted(self) -> None:
        # 2006 is 627 columns — it FITS in InnoDB, so it must be converted,
        # not folded into the permanent exception list.
        assert not _is_pitr_unconvertible("oscar.formRourke2006 [Aria]")
        assert not _is_pitr_unconvertible("oscar.formRourke2020 [Aria]")

    def test_the_allowlist_stays_short(self) -> None:
        # Every entry is a permanently accepted PITR gap; growth here should
        # be a deliberate, reviewed act rather than a convenient dumping
        # ground for whatever the audit happens to flag.
        assert len(_PITR_UNCONVERTIBLE_TABLES) == 1


class TestBinlogRuntimeLatch:
    """MariaDB latches binary logging OFF for the rest of the server process
    the first time it cannot open a new binlog file (a full binlog volume, or
    an ownership/permission change on the dedicated mariadb-binlog mount):

        [ERROR] Could not use /var/lib/mysql-binlog/binlog.000006 for logging
        (error 13). Turning logging off for the whole duration of the MariaDB
        server process.

    After that latch `@@log_bin` STILL reads 1 (reproduced live against the
    pinned mariadb:11.4.12), so the constructor's `SELECT @@log_bin` probe —
    the only binlog-health signal this module had — reported PITR healthy
    while the chain had stopped advancing. `FLUSH BINARY LOGS` becomes a
    no-op returning 0 and the already-closed binlogs are all still on disk,
    so the 15-minute ship ran clean and stamped `.last-binlog-ok` FOREVER
    while the RPO guarantee was gone; the nightly full was the only signal,
    up to a day later, and it blamed 'db down or credentials wrong?'.

    These pin the runtime-authoritative probe and both refusals."""

    def _ctx(self, mk_runner):
        r = mk_runner()
        d = r.settings.conf_dir / "restic"
        d.mkdir(parents=True, exist_ok=True)
        (d / "restic.env").write_text(
            f"RESTIC_REPOSITORY={r.settings.emr_home}/backup/repo\nRESTIC_PASSWORD=x\n"
        )
        return BackupContext(r), r

    def test_a_row_from_show_binlog_status_means_OPEN(self, mk_runner) -> None:
        ctx, r = self._ctx(mk_runner)
        ctx._binlog_runtime_open = None
        r.script("SHOW BINLOG STATUS", out="binlog.000005\t379\t\t\n")
        assert ctx.binlog_runtime_open() is True

    def test_an_empty_result_means_CLOSED(self, mk_runner) -> None:
        # The whole point: rc 0 with NO row is how a latched-off server
        # answers — it is not an error, so an rc-only check misses it.
        ctx, r = self._ctx(mk_runner)
        ctx._binlog_runtime_open = None
        r.script("SHOW BINLOG STATUS", out="\n")
        assert ctx.binlog_runtime_open() is False

    def test_it_falls_back_to_the_pre_11_4_spelling(self, mk_runner) -> None:
        ctx, r = self._ctx(mk_runner)
        ctx._binlog_runtime_open = None
        r.script("SHOW BINLOG STATUS", rc=1, out="")
        r.script("SHOW MASTER STATUS", out="binlog.000005\t379\t\t\n")
        assert ctx.binlog_runtime_open() is True

    def test_a_probe_that_cannot_answer_is_UNKNOWN_not_closed(self, mk_runner) -> None:
        """None, never False: inventing a refusal on a database we could not
        interrogate would take the nightly full down for a credential blip."""
        ctx, r = self._ctx(mk_runner)
        ctx._binlog_runtime_open = None
        r.script("SHOW BINLOG STATUS", rc=1, out="")
        r.script("SHOW MASTER STATUS", rc=1, out="")
        assert ctx.binlog_runtime_open() is None

    def test_latched_off_needs_BOTH_startup_on_and_runtime_closed(self, mk_runner) -> None:
        ctx, r = self._ctx(mk_runner)
        ctx.binlog_on = True
        ctx._binlog_runtime_open = False
        assert ctx.binlog_latched_off() is True
        # Deliberately off at startup is a different, already-handled state.
        ctx.binlog_on = False
        assert ctx.binlog_latched_off() is False
        ctx.binlog_on = True
        ctx._binlog_runtime_open = True
        assert ctx.binlog_latched_off() is False

    def test_an_unanswerable_probe_does_not_trip_the_latch(self, mk_runner) -> None:
        """UNKNOWN must leave the pre-existing guards in charge: refusing the
        nightly full because a probe could not run would turn a credential
        blip into a missed backup."""
        ctx, r = self._ctx(mk_runner)
        ctx.binlog_on = True
        ctx._binlog_runtime_open = None
        r.script("SHOW BINLOG STATUS", rc=1, out="")
        r.script("SHOW MASTER STATUS", rc=1, out="")
        assert ctx.binlog_runtime_open() is None
        assert ctx.binlog_latched_off() is False

    def test_ship_binlogs_REFUSES_and_never_flushes_when_latched_off(
        self, mk_runner
    ) -> None:
        """The refusal is what keeps `.last-binlog-ok` honest — cmd_backup
        only stamps on a True return, so the monitor's BINLOG_MAX_AGE_MIN
        check pages within ~35 minutes instead of never."""
        ctx, r = self._ctx(mk_runner)
        ctx.binlog_probe_ok = True
        ctx.binlog_on = True
        ctx._binlog_runtime_open = False
        assert ctx.ship_binlogs() is False
        assert ctx.binlog_shipped is False
        # It must bail BEFORE mutating anything or storing a snapshot.
        flat = [" ".join(c) for c in r.calls]
        assert not any("FLUSH BINARY LOGS" in c for c in flat), flat
        assert not any("--tag binlog" in c for c in flat), flat

    def test_ship_binlogs_still_ships_when_the_binlog_is_open(self, mk_runner) -> None:
        ctx, r = self._ctx(mk_runner)
        ctx.binlog_probe_ok = True
        ctx.binlog_on = True
        ctx._binlog_runtime_open = True
        ctx.binlog_dir.mkdir(parents=True, exist_ok=True)
        (ctx.binlog_dir / "binlog.index").write_text("./binlog.000002\n")
        (ctx.binlog_dir / "binlog.000001").write_text("x")
        (ctx.binlog_dir / "binlog.000002").write_text("y")
        assert ctx.ship_binlogs() is True
        flat = [" ".join(c) for c in r.calls]
        assert any("FLUSH BINARY LOGS" in c for c in flat), flat

    def test_full_backup_refuses_BEFORE_running_the_dump(
        self, mk_runner, monkeypatch
    ) -> None:
        """mariadb-dump would otherwise run the entire multi-GB dump and only
        then die resolving the --master-data anchor (error 1381), after which
        the generic handler blamed 'db down or credentials wrong?'."""
        from carlos_ctl import backup as backup_mod

        ctx, r = self._ctx(mk_runner)
        ctx.binlog_probe_ok = True
        ctx.binlog_on = True
        ctx._binlog_runtime_open = False
        monkeypatch.setattr(backup_mod, "_reap_orphaned_stagings", lambda _c: None)
        r.script("mariadb", out="")  # engine audit: no non-InnoDB tables
        assert backup_mod._full_backup(ctx) is False
        flat = [" ".join(c) for c in r.calls]
        assert not any("mariadb-dump" in c for c in flat), flat
