# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Unit tests for the monitor's throttle state machine and mode selection."""

import time

from carlos_ctl import monitor as monitor_mod
from carlos_ctl.monitor import MonitorRun


class TestAlertThrottle:
    def test_first_fire_delivers_and_records(self, mk_runner) -> None:
        r = mk_runner()
        r.tools = {"logger"}
        m = MonitorRun(r)
        m.alert("low disk", "disk-x")
        assert m.fail
        assert (m.state_dir / "disk-x").is_file()

    def test_within_window_throttles_but_stays_failed(self, mk_runner) -> None:
        r = mk_runner()
        r.tools = {"logger"}
        m = MonitorRun(r)
        (m.state_dir / "disk-x").touch()
        logger_calls_before = len([c for c in r.calls if c and c[0] == "logger"])
        m.alert("low disk", "disk-x")
        # fail stays set (exit code / heartbeat still show the condition)…
        assert m.fail
        # …but the page was journal-only (no webhook dispatch attempted).
        assert not any(c[0] == "curl" for c in r.calls if c)
        assert len([c for c in r.calls if c and c[0] == "logger"]) > logger_calls_before

    def test_expired_window_repages(self, mk_runner) -> None:
        r = mk_runner("", {"ALERT_REMIND_HOURS": "1"})
        r.tools = {"logger"}
        m = MonitorRun(r)
        sf = m.state_dir / "disk-x"
        sf.touch()
        import os

        os.utime(sf, (time.time() - 7200, time.time() - 7200))
        m.alert("low disk", "disk-x")
        # Re-delivered (state refreshed to now).
        assert time.time() - sf.stat().st_mtime < 60

    def test_failed_delivery_does_not_start_window(self, mk_runner) -> None:
        # A webhook blip at first occurrence must not silence the condition
        # for a full reminder window.
        r = mk_runner("ALERT_WEBHOOK=https://hooks/x\n")
        r.tools = {"logger", "curl"}
        r.script("curl", rc=22)
        m = MonitorRun(r)
        m.alert("low disk", "disk-x")
        assert not (m.state_dir / "disk-x").is_file()

    def test_recovery_sweep_clears_unfired_keys(self, mk_runner) -> None:
        r = mk_runner()
        r.tools = {"logger"}
        m = MonitorRun(r)
        (m.state_dir / "recovered-cond").touch()
        m.alert("still bad", "still-bad")
        m.recovery_sweep()
        assert not (m.state_dir / "recovered-cond").is_file()
        assert (m.state_dir / "still-bad").is_file()

    def test_recovery_sweep_leaves_onfailure_stamps(self, mk_runner) -> None:
        # H2: `carlos-ctl alert` throttle stamps live in the same state dir but
        # are self-expired by mtime — the monitor sweep must NOT delete them
        # (doing so re-armed a still-failing unit every run and flooded pages).
        r = mk_runner()
        r.tools = {"logger"}
        m = MonitorRun(r)
        (m.state_dir / "onfailure-carlos-binlog.service").touch()
        (m.state_dir / "recovered-cond").touch()
        m.recovery_sweep()  # nothing fired this run
        assert (m.state_dir / "onfailure-carlos-binlog.service").is_file()
        assert not (m.state_dir / "recovered-cond").is_file()


class TestCheckIsolation:
    def test_crashing_check_pages_and_continues(self, mk_runner) -> None:
        # A crash inside one check must not abort the sweep: the crash pages
        # (fail set, keyed alert recorded) and execution continues.
        r = mk_runner()
        r.tools = {"logger"}
        m = MonitorRun(r)
        ran_after = []
        with m.isolated("boom"):
            raise RuntimeError("unexpected podman output")
        ran_after.append(True)  # reached: the crash did not propagate
        assert ran_after
        assert m.fail
        assert "monitor-check-crash-boom" in m.fired

    def test_healthy_check_leaves_fail_unset(self, mk_runner) -> None:
        r = mk_runner()
        r.tools = {"logger"}
        m = MonitorRun(r)
        with m.isolated("fine"):
            pass
        assert not m.fail


class TestChannelConfigCheck:
    def _deployed(self, r) -> None:
        d = r.settings.emr_home / "container"
        d.mkdir(parents=True, exist_ok=True)
        (d / ".deployed").touch()

    def test_no_channels_on_deployed_instance_alerts(self, mk_runner) -> None:
        # play gates go-live on a channel, but carlos-app.env can lose it
        # AFTER go-live (edit, DR restore) with no re-play — the monitor is
        # the recurring nag that catches the drift.
        r = mk_runner("HEARTBEAT_URL=https://hc/ping\n")
        r.tools = {"logger"}
        self._deployed(r)
        m = MonitorRun(r)
        monitor_mod._check_channel_config(m)
        assert "alert-channel-unset" in m.fired

    def test_journal_only_ack_is_respected(self, mk_runner) -> None:
        r = mk_runner("HEARTBEAT_URL=https://hc/ping\nALERT_JOURNAL_ONLY=1\n")
        r.tools = {"logger"}
        self._deployed(r)
        m = MonitorRun(r)
        monitor_mod._check_channel_config(m)
        assert "alert-channel-unset" not in m.fired

    def test_webhook_satisfies(self, mk_runner) -> None:
        r = mk_runner("HEARTBEAT_URL=https://hc/ping\nALERT_WEBHOOK=https://hooks/x\n")
        r.tools = {"logger"}
        self._deployed(r)
        m = MonitorRun(r)
        monitor_mod._check_channel_config(m)
        assert "alert-channel-unset" not in m.fired

    def test_missing_heartbeat_on_deployed_instance_alerts(self, mk_runner) -> None:
        r = mk_runner("ALERT_WEBHOOK=https://hooks/x\n")
        r.tools = {"logger"}
        self._deployed(r)
        m = MonitorRun(r)
        monitor_mod._check_channel_config(m)
        assert "heartbeat-unset" in m.fired

    def test_undeployed_instance_is_quiet(self, mk_runner) -> None:
        r = mk_runner()
        r.tools = {"logger"}
        m = MonitorRun(r)
        monitor_mod._check_channel_config(m)
        assert not m.fired

    def test_no_heartbeat_ack_suppresses_the_nag(self, mk_runner) -> None:
        # CARLOS_NO_HEARTBEAT=1 is the documented go-live ack; the monitor must
        # honor it instead of nagging every reminder window forever.
        r = mk_runner("ALERT_WEBHOOK=https://hooks/x\nCARLOS_NO_HEARTBEAT=1\n")
        r.tools = {"logger"}
        self._deployed(r)
        m = MonitorRun(r)
        monitor_mod._check_channel_config(m)
        assert "heartbeat-unset" not in m.fired


class TestModeSelection:
    def test_obs_enabled_polls_vmalert(self, mk_runner) -> None:
        r = mk_runner("OBS_ENABLED=1\n")
        r.tools = {"logger", "curl", "podman", "systemctl"}
        s = r.settings
        # vmalert LISTED running (else container-down covers it and the
        # unreachable probe is deliberately skipped), but curl fails.
        r.script("podman", rc=0, out=f"{s.obs_pod}-vmalert\n")
        r.script("curl", rc=22)  # vmalert unreachable
        m = MonitorRun(r)
        monitor_mod._check_vmalert(m)
        assert m.fail  # a dead alerting engine must not read as "no alerts"
        assert "vmalert-unreachable" in m.fired

    def test_vmalert_probe_skipped_when_container_down(self, mk_runner) -> None:
        # container-down-<obs>-vmalert already pages from the liveness sweep;
        # a second unreachable page would be duplicate noise.
        r = mk_runner("OBS_ENABLED=1\n")
        r.tools = {"logger", "curl", "podman"}
        r.script("podman", rc=0, out="")  # nothing running
        r.script("curl", rc=22)
        m = MonitorRun(r)
        monitor_mod._check_vmalert(m)
        assert "vmalert-unreachable" not in m.fired

    def test_wedged_victoriametrics_alerts(self, mk_runner) -> None:
        # VM container up, /health dead: vmalert stays reachable but every
        # rule evaluates against a dead datasource — the bash's vm-wedged
        # blind-spot check must survive the vmalert migration.
        r = mk_runner("OBS_ENABLED=1\n")
        r.tools = {"logger", "curl", "podman"}
        s = r.settings
        r.script("podman", rc=0, out=f"{s.obs_pod}-victoria-metrics\n{s.obs_pod}-vmalert\n")
        # The URL rides the -K stdin config now (store_curl) — matched there.
        r.script(f"http://127.0.0.1:{s.get('VICTORIAMETRICS_PORT')}/health", rc=22)
        m = MonitorRun(r)
        monitor_mod._check_vmalert(m)
        assert "vm-wedged" in m.fired

    def test_vmalert_firing_rules_are_relayed(self, mk_runner) -> None:
        r = mk_runner()
        r.tools = {"logger", "curl", "podman"}
        s = r.settings
        r.script("podman", rc=0, out=f"{s.obs_pod}-vmalert\n")
        body = (
            '{"data":{"alerts":[{"name":"MysqlDown","state":"firing","value":"0",'
            '"annotations":{"summary":"mysql_up != 1"}}]}}'
        )
        r.script("curl", rc=0, out=body)
        m = MonitorRun(r)
        monitor_mod._check_vmalert(m)
        assert m.fail
        assert "vmalert-MysqlDown" in m.fired

    def test_waf_5xx_burst_alerts(self, mk_runner) -> None:
        r = mk_runner("OBS_ENABLED=1\n")
        r.tools = {"logger", "curl"}
        # vl_count reads the "n" field from the stats response.
        r.script("curl", rc=0, out='{"n":99}\n')
        m = MonitorRun(r)
        monitor_mod._check_waf_5xx(m)
        assert "waf-5xx-burst" in m.fired

    def test_waf_5xx_under_threshold_quiet(self, mk_runner) -> None:
        r = mk_runner("OBS_ENABLED=1\n")
        r.tools = {"logger", "curl"}
        r.script("curl", rc=0, out='{"n":1}\n')
        m = MonitorRun(r)
        monitor_mod._check_waf_5xx(m)
        assert "waf-5xx-burst" not in m.fired

    def test_relay_key_carries_identifying_labels(self, mk_runner) -> None:
        # DiskLow fires PER MOUNTPOINT: one shared key would journal-throttle
        # a NEW mountpoint filling up inside another's reminder window.
        r = mk_runner()
        r.tools = {"logger", "curl", "podman"}
        s = r.settings
        r.script("podman", rc=0, out=f"{s.obs_pod}-vmalert\n")
        body = (
            '{"data":{"alerts":['
            '{"name":"DiskLow","state":"firing","labels":{"mountpoint":"/var"}},'
            '{"name":"DiskLow","state":"firing","labels":{"mountpoint":"/home"}}'
            "]}}"
        )
        r.script("curl", rc=0, out=body)
        m = MonitorRun(r)
        monitor_mod._check_vmalert(m)
        assert "vmalert-DiskLow-_var" in m.fired
        assert "vmalert-DiskLow-_home" in m.fired

    def test_obs_disabled_liveness_covers_obs_free_set(self, mk_runner) -> None:
        # With the obs pod disabled the sweep expects ONLY the core containers.
        r = mk_runner("OBS_ENABLED=0\n")
        r.tools = {"logger", "podman", "systemctl"}
        s = r.settings
        r.script("podman", rc=0, out=f"{s.app_pod}-db\n{s.app_pod}-carlos\n"
                                     f"{s.app_pod}-drugref\n{s.waf_pod}-waf\n")
        m = MonitorRun(r)
        monitor_mod._check_liveness(m)
        assert not any(k.startswith("container-down-") for k in m.fired)

    def test_missing_core_container_alerts(self, mk_runner) -> None:
        r = mk_runner("OBS_ENABLED=0\n")
        r.tools = {"logger", "podman", "systemctl"}
        s = r.settings
        r.script("podman", rc=0, out=f"{s.app_pod}-db\n{s.app_pod}-carlos\n"
                                     f"{s.waf_pod}-waf\n")
        m = MonitorRun(r)
        monitor_mod._check_liveness(m)
        assert f"container-down-{s.app_pod}-drugref" in m.fired

    def test_failed_pod_unit_alerts_despite_nonzero_rc(self, mk_runner) -> None:
        # `systemctl is-active` PRINTS 'failed' but exits 3 — an rc-gated
        # capture turns that into '' and the bridge alert can never fire.
        r = mk_runner("OBS_ENABLED=0\n")
        r.tools = {"logger", "podman", "systemctl"}
        s = r.settings
        r.script("podman", rc=0, out=f"{s.app_pod}-db\n{s.app_pod}-carlos\n"
                                     f"{s.app_pod}-drugref\n{s.waf_pod}-waf\n")
        r.script("systemctl", rc=3, out="failed\n")
        m = MonitorRun(r)
        monitor_mod._check_liveness(m)
        assert f"pod-unit-failed-{s.instance}.service" in m.fired


class TestKnobResilience:
    def test_malformed_numeric_knobs_degrade_not_crash(self, mk_runner) -> None:
        # Bash degraded PER CHECK on a garbage knob; a ValueError here would
        # kill the whole sweep before any check runs (no alerts, no heartbeat).
        r = mk_runner(
            "DISK_MIN_FREE=10%\nALERT_REMIND_HOURS=daily\nBOOT_GRACE_SECONDS=15m\n"
        )
        r.tools = {"logger"}
        m = MonitorRun(r)  # ALERT_REMIND_HOURS parse happens here
        assert m.remind_hours == 24
        assert m.within_boot_grace() in (True, False)  # no raise
        monitor_mod._check_disk(m)  # DISK_MIN_FREE parse happens here


class TestSystemdFailedSweep:
    def test_failed_units_page_and_self_plus_secrets_are_skipped(
        self, mk_runner
    ) -> None:
        # Finding S21a: OnFailure pages once at failure time; a unit that
        # STAYS failed (or a failed alert@ dispatch itself) was invisible
        # afterwards. The sweep nags per failed unit, skipping the secrets
        # unit (dedicated check) and the monitor itself.
        r = mk_runner()
        r.tools = {"logger", "systemctl"}
        r.script(
            "systemctl", "--failed",
            out="carlos-backup.service loaded failed failed\n"
                "carlos-alert@carlos-backup.service.service loaded failed failed\n"
                "carlos-secrets.service loaded failed failed\n"
                "carlos-monitor.service loaded failed failed\n",
        )
        m = MonitorRun(r)
        monitor_mod._check_systemd_failed(m)
        assert "failed-unit-carlos-backup.service" in m.fired
        assert "failed-unit-carlos-alert_carlos-backup.service.service" in m.fired
        assert not any("secrets" in k for k in m.fired)
        assert not any("monitor.service" in k for k in m.fired)

    def test_no_failed_units_is_quiet(self, mk_runner) -> None:
        r = mk_runner()
        r.tools = {"logger", "systemctl"}
        r.script("systemctl", "--failed", out="")
        m = MonitorRun(r)
        monitor_mod._check_systemd_failed(m)
        assert not m.fail


class TestHostfwCheck:
    def test_missing_table_alerts_when_expected(
        self, mk_runner, monkeypatch, live_host_probe
    ) -> None:
        # Finding S12: the nft apply unit is fail-open — a host that expects
        # the default-deny table but lost it must page every sweep.
        r = mk_runner("HOSTFW_ENABLED=1\n")
        r.tools = {"logger", "nft"}
        live_host_probe(r)
        monkeypatch.setattr("os.geteuid", lambda: 0)
        r.script("nft", "list", "table", rc=1)
        m = MonitorRun(r)
        monitor_mod._check_nft_hostfw(m)
        assert "hostfw-table-missing" in m.fired

    def test_table_without_default_deny_alerts(
        self, mk_runner, monkeypatch, live_host_probe
    ) -> None:
        r = mk_runner("HOSTFW_ENABLED=1\n")
        r.tools = {"logger", "nft"}
        live_host_probe(r)
        monkeypatch.setattr("os.geteuid", lambda: 0)
        r.script("nft", "list", "table", rc=0,
                 out="table inet carlos-hostfw {\n  chain input {\n"
                     "    type filter hook input priority 0; policy accept;\n  }\n}\n")
        m = MonitorRun(r)
        monitor_mod._check_nft_hostfw(m)
        assert "hostfw-table-missing" in m.fired

    def test_loaded_default_deny_table_is_quiet(
        self, mk_runner, monkeypatch, live_host_probe
    ) -> None:
        r = mk_runner("HOSTFW_ENABLED=1\n")
        r.tools = {"logger", "nft"}
        live_host_probe(r)
        monkeypatch.setattr("os.geteuid", lambda: 0)
        r.script("nft", "list", "table", rc=0,
                 out="table inet carlos-hostfw {\n  chain input {\n"
                     "    type filter hook input priority 0; policy drop;\n  }\n}\n")
        m = MonitorRun(r)
        monitor_mod._check_nft_hostfw(m)
        assert not m.fail

    def test_disabled_expectation_never_probes(self, mk_runner, monkeypatch) -> None:
        # Pre-existing env files lack the key (default 0): no behavior change
        # until the playbook re-renders HOSTFW_ENABLED=1.
        r = mk_runner()
        r.tools = {"logger", "nft"}
        monkeypatch.setattr("os.geteuid", lambda: 0)
        m = MonitorRun(r)
        monitor_mod._check_nft_hostfw(m)
        assert not any(c and c[0] == "nft" for c in r.calls)
        assert not m.fail

    def test_hermetic_harness_is_suppressed(self, mk_runner, monkeypatch) -> None:
        r = mk_runner("HOSTFW_ENABLED=1\n", {"CARLOS_SYSTEMD_DIR": "/x"})
        r.tools = {"logger", "nft"}
        monkeypatch.setattr("os.geteuid", lambda: 0)
        m = MonitorRun(r)
        monitor_mod._check_nft_hostfw(m)
        assert not m.fail


class TestDbIsolationCheck:
    def test_edge_reaching_3306_alerts(self, mk_runner) -> None:
        # Finding S21c: the WAF/DB boundary was only asserted at play/check;
        # the monitor now re-probes it every sweep.
        r = mk_runner()
        r.tools = {"logger", "podman"}
        r.script("podman", "ps", out=f"{r.settings.waf_pod}-waf\n")
        # exec probe default rc=0 => the waf CAN open 3306.
        m = MonitorRun(r)
        monitor_mod._check_db_isolation(m)
        assert "waf-db-isolation-broken" in m.fired

    def test_isolated_db_is_quiet(self, mk_runner) -> None:
        r = mk_runner()
        r.tools = {"logger", "podman"}
        r.script("podman", "ps", out=f"{r.settings.waf_pod}-waf\n")
        r.script("podman", "exec", rc=1)
        m = MonitorRun(r)
        monitor_mod._check_db_isolation(m)
        assert not m.fail

    def test_waf_down_cannot_probe_and_stays_quiet(self, mk_runner) -> None:
        r = mk_runner()
        r.tools = {"logger", "podman"}
        r.script("podman", "ps", out="")
        m = MonitorRun(r)
        monitor_mod._check_db_isolation(m)
        assert not m.fail
        assert not any("exec" in c for c in r.calls)


class TestWafStreamSilence:
    def _deployed(self, r) -> None:
        d = r.settings.emr_home / "container"
        d.mkdir(parents=True, exist_ok=True)
        (d / ".deployed").touch()

    def test_two_consecutive_zero_sweeps_alert(self, mk_runner) -> None:
        # Finding S8: a log-format/stream-label drift makes the 5xx regex
        # read a silent 0 forever — the match-all companion catches it.
        # TWO consecutive zero sweeps are required (the first sweep after a
        # >60min maintenance window legitimately sees an empty window).
        r = mk_runner("OBS_ENABLED=1\n")
        r.tools = {"logger", "curl"}
        self._deployed(r)
        r.script("curl", rc=0, out='{"n":0}\n')
        m = MonitorRun(r)
        monitor_mod._check_waf_5xx(m)
        assert "waf-access-stream-silent" not in m.fired  # first strike arms
        m2 = MonitorRun(r)
        monitor_mod._check_waf_5xx(m2)
        assert "waf-access-stream-silent" in m2.fired

    def test_recovered_stream_resets_the_strike(self, mk_runner) -> None:
        r = mk_runner("OBS_ENABLED=1\n")
        r.tools = {"logger", "curl"}
        self._deployed(r)
        r.script("curl", rc=0, out='{"n":0}\n')
        monitor_mod._check_waf_5xx(MonitorRun(r))  # strike armed
        r.results.clear()
        r.script("curl", rc=0, out='{"n":3}\n')
        monitor_mod._check_waf_5xx(MonitorRun(r))  # traffic seen: reset
        r.results.clear()
        r.script("curl", rc=0, out='{"n":0}\n')
        m = MonitorRun(r)
        monitor_mod._check_waf_5xx(m)  # first zero AFTER reset: no alert
        assert "waf-access-stream-silent" not in m.fired

    def test_flowing_stream_is_quiet(self, mk_runner) -> None:
        r = mk_runner("OBS_ENABLED=1\n")
        r.tools = {"logger", "curl"}
        self._deployed(r)
        r.script("curl", rc=0, out='{"n":7}\n')
        m = MonitorRun(r)
        monitor_mod._check_waf_5xx(m)
        assert "waf-access-stream-silent" not in m.fired

    def test_undeployed_instance_is_quiet(self, mk_runner) -> None:
        r = mk_runner("OBS_ENABLED=1\n")
        r.tools = {"logger", "curl"}
        r.script("curl", rc=0, out='{"n":0}\n')
        m = MonitorRun(r)
        monitor_mod._check_waf_5xx(m)
        assert "waf-access-stream-silent" not in m.fired


class TestNoHeartbeatWeeklyReminder:
    def _deployed(self, r) -> None:
        d = r.settings.emr_home / "container"
        d.mkdir(parents=True, exist_ok=True)
        (d / ".deployed").touch()

    def test_acked_instance_gets_a_nonfailing_weekly_reminder(
        self, mk_runner
    ) -> None:
        # Finding S21b: the ack must not fade from memory, but it also must
        # not fail the sweep (an accepted posture exiting 1 every 15 min
        # would mark the monitor unit failed on a healthy stack).
        r = mk_runner("ALERT_JOURNAL_ONLY=1\nCARLOS_NO_HEARTBEAT=1\n")
        r.tools = {"logger"}
        self._deployed(r)
        m = MonitorRun(r)
        monitor_mod._check_channel_config(m)
        assert not m.fail
        assert "no-heartbeat-configured" in m.fired
        assert (m.state_dir / "no-heartbeat-configured").is_file()

    def test_reminder_respects_the_weekly_window(self, mk_runner) -> None:
        import os as _os
        import time as _time

        r = mk_runner("ALERT_JOURNAL_ONLY=1\nCARLOS_NO_HEARTBEAT=1\n")
        r.tools = {"logger"}
        self._deployed(r)
        m = MonitorRun(r)
        monitor_mod._check_channel_config(m)
        sf = m.state_dir / "no-heartbeat-configured"
        two_days_ago = _time.time() - 48 * 3600
        _os.utime(sf, (two_days_ago, two_days_ago))
        m2 = MonitorRun(r)
        monitor_mod._check_channel_config(m2)
        # 48h old is inside the 168h window: no re-dispatch, mtime unchanged.
        assert abs(sf.stat().st_mtime - two_days_ago) < 5

    def test_remind_hours_override_widens_the_alert_window(self, mk_runner) -> None:
        import os as _os
        import time as _time

        r = mk_runner("ALERT_JOURNAL_ONLY=1\n")
        r.tools = {"logger"}
        m = MonitorRun(r)
        m.alert("posture", "some-key", remind_hours=168)
        sf = m.state_dir / "some-key"
        two_days_ago = _time.time() - 48 * 3600
        _os.utime(sf, (two_days_ago, two_days_ago))
        m2 = MonitorRun(r)
        m2.alert("posture", "some-key", remind_hours=168)
        # Throttled at 48h under a 168h window (the daily default would have
        # re-paged and refreshed the mtime).
        assert abs(sf.stat().st_mtime - two_days_ago) < 5


class TestFindingsReachTheOperator:
    """`monitor` is an operator verb ("run the health checks now"), but every
    finding used to go only to journald + the alert channel — a hand-run
    sweep printed NOTHING and exited 1. Findings must reach stderr too, the
    way `check` prints its FAILs."""

    def test_alert_prints_the_finding_to_stderr(self, mk_runner, capsys) -> None:
        from carlos_ctl.monitor import MonitorRun

        m = MonitorRun(mk_runner())
        m.alert("disk 3% free on /opt/emr", "disk-emr")
        err = capsys.readouterr().err
        assert "disk 3% free on /opt/emr" in err
        assert m.fail is True

    def test_throttled_repeat_still_prints(self, mk_runner, capsys) -> None:
        from carlos_ctl.monitor import MonitorRun

        r = mk_runner()
        m = MonitorRun(r)
        m.alert("cert expires in 3 days", "tls-expiry")
        capsys.readouterr()
        m2 = MonitorRun(r)
        m2.alert("cert expires in 3 days", "tls-expiry")
        assert "cert expires in 3 days" in capsys.readouterr().err
