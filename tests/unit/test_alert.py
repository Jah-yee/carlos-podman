# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Unit tests for the alert dispatcher's argument handling and throttle.

`carlos-ctl alert` is the OnFailure= paging path: whatever it assembles here
is the entire content a human gets at 3am, so a silently-dropped word is a
silently-degraded page."""

import json

import pytest

from carlos_ctl.alert import cmd_alert


def _webhook_bodies(runner) -> list:
    """The JSON bodies POSTed by dispatch(): the URL rides `curl -K -` on
    stdin, the body rides `-d` on argv."""
    out = []
    for argv in runner.calls:
        if argv and argv[0] == "curl" and "-d" in argv:
            out.append(json.loads(argv[argv.index("-d") + 1])["text"])
    return out


class TestAlertDetailAssembly:
    """An UNQUOTED detail used to be truncated to its first word: cmd_alert
    read args[1] alone and dropped args[2:] wordlessly, so
    `carlos-ctl alert backup db is down` paged "backup — db"."""

    def test_unquoted_multiword_detail_is_not_truncated(self, mk_runner) -> None:
        r = mk_runner("ALERT_WEBHOOK=https://hook.example/x\n")
        assert cmd_alert(r, ["myunit", "db", "is", "down"]) == 0
        bodies = _webhook_bodies(r)
        assert bodies, "no webhook POST was made"
        assert "db is down" in bodies[0]

    def test_quoted_detail_is_unchanged_by_the_join(self, mk_runner) -> None:
        r = mk_runner("ALERT_WEBHOOK=https://hook.example/x\n")
        assert cmd_alert(r, ["myunit", "db is down"]) == 0
        assert "db is down" in _webhook_bodies(r)[0]

    def test_subject_still_leads_the_page(self, mk_runner) -> None:
        r = mk_runner("ALERT_WEBHOOK=https://hook.example/x\n")
        cmd_alert(r, ["carlos-backup.service", "repo", "unreachable"])
        body = _webhook_bodies(r)[0]
        assert "carlos-backup.service" in body
        assert "repo unreachable" in body

    def test_bare_subject_sends_an_empty_detail(self, mk_runner) -> None:
        # `OnFailure=` passes only %n; the join must degrade to "" and not
        # append a stray separator.
        r = mk_runner("ALERT_WEBHOOK=https://hook.example/x\n")
        cmd_alert(r, ["carlos-binlog.service"])
        body = _webhook_bodies(r)[0]
        assert body.endswith("carlos-binlog.service")

    def test_no_arguments_reports_unspecified(self, mk_runner) -> None:
        r = mk_runner("ALERT_WEBHOOK=https://hook.example/x\n")
        cmd_alert(r, [])
        assert "unspecified" in _webhook_bodies(r)[0]


class TestAlertThrottle:
    def test_second_occurrence_inside_the_window_is_not_redelivered(
        self, mk_runner
    ) -> None:
        r = mk_runner("ALERT_WEBHOOK=https://hook.example/x\n")
        cmd_alert(r, ["dupunit", "first"])
        cmd_alert(r, ["dupunit", "second"])
        bodies = _webhook_bodies(r)
        assert len(bodies) == 1, f"throttle leaked a second page: {bodies}"
        assert "first" in bodies[0]

    def test_stamp_older_than_the_window_repages(self, mk_runner) -> None:
        import os
        import time

        r = mk_runner("ALERT_WEBHOOK=https://hook.example/x\n"
                      "ALERT_REMIND_HOURS=1\n")
        cmd_alert(r, ["dupunit", "first"])
        stamp = r.settings.emr_home / "monitor" / "state" / "onfailure-dupunit"
        old = time.time() - 2 * 3600
        os.utime(stamp, (old, old))
        cmd_alert(r, ["dupunit", "second"])
        assert len(_webhook_bodies(r)) == 2

    def test_undelivered_page_does_not_start_the_throttle_window(
        self, mk_runner
    ) -> None:
        # A webhook blip at first occurrence must not silence the condition
        # for a full ALERT_REMIND_HOURS.
        r = mk_runner("ALERT_WEBHOOK=https://hook.example/x\n")
        r.script("curl", rc=1)
        assert cmd_alert(r, ["dupunit", "first"]) == 1
        stamp = r.settings.emr_home / "monitor" / "state" / "onfailure-dupunit"
        assert not stamp.is_file()

    @pytest.mark.parametrize(
        "subject", ["carlos-backup@x.service", "unit with spaces", "a/b"]
    )
    def test_throttle_key_is_filesystem_safe(self, mk_runner, subject: str) -> None:
        r = mk_runner("ALERT_WEBHOOK=https://hook.example/x\n")
        assert cmd_alert(r, [subject, "detail"]) == 0
        state = r.settings.emr_home / "monitor" / "state"
        stamps = [p.name for p in state.iterdir()]
        assert len(stamps) == 1
        assert "/" not in stamps[0]
