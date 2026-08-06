# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Unit tests for cert-renew's restart-failure handling (finding S11): a
renewed cert whose consumer restart fails must page (nonzero + marker) and
be retried on the next run instead of self-concealing until expiry."""

from pathlib import Path

import pytest

from carlos_ctl import monitor as monitor_mod
from carlos_ctl.monitor import MonitorRun
from carlos_ctl.tlsops import (
    _cert_is_self_issued_for,
    _certs_dir,
    cert_restart_marker,
    cmd_cert_renew,
    ensure_selfsigned_cert,
)
from carlos_ctl.util import CtlError

_ACME_ENV = (
    "CARLOS_TLS_MODE=acme\n"
    "ACME_EMAIL=ops@example.ca\n"
    "SERVER_NAME=emr.example.ca\n"
)


def _stage_live_cert(r, content: bytes = b"CERT") -> None:
    """Pre-create the certbot live pair (the certbot run itself is faked)."""
    live = r.settings.conf_dir / "waf" / "acme" / "etc" / "live" / "emr.example.ca"
    live.mkdir(parents=True, exist_ok=True)
    (live / "fullchain.pem").write_bytes(content)
    (live / "privkey.pem").write_bytes(b"KEY")


def _deploy(r) -> None:
    d = r.settings.emr_home / "container"
    d.mkdir(parents=True, exist_ok=True)
    (d / ".deployed").touch()


class TestCertRenewRestartFailure:
    def test_failed_restart_returns_nonzero_and_writes_marker(
        self, mk_runner, capsys
    ) -> None:
        r = mk_runner(env_lines=_ACME_ENV)
        _deploy(r)
        _stage_live_cert(r)
        r.script("systemctl", "--user", rc=1)  # every consumer restart fails
        assert cmd_cert_renew(r) == 1
        marker = cert_restart_marker(r)
        assert marker.is_file()
        assert f"{r.settings.waf_pod}.service" in marker.read_text()
        assert "OLD cert" in capsys.readouterr().err

    def test_not_due_run_retries_and_clears_the_marker(self, mk_runner) -> None:
        r = mk_runner(env_lines=_ACME_ENV)
        _deploy(r)
        _stage_live_cert(r)
        # First run: install + failed restart -> marker.
        r.script("systemctl", "--user", rc=1)
        assert cmd_cert_renew(r) == 1
        # Second run: cert unchanged ("not due") but the marker demands a
        # retry; restarts now succeed -> marker cleared, exit 0.
        marker = cert_restart_marker(r)
        assert marker.is_file()
        r.results.clear()
        r.script("systemctl", "--user", rc=0)
        calls_before_retry = len(r.calls)
        assert cmd_cert_renew(r) == 0
        assert not marker.is_file()
        # The restart must have happened IN the retry run — matching across
        # both runs would let a regression that merely unlinks the marker
        # pass on the first run's restart attempts (review finding).
        assert any(
            "restart" in " ".join(c) for c in r.calls[calls_before_retry:]
        )

    def test_successful_restart_leaves_no_marker(self, mk_runner) -> None:
        r = mk_runner(env_lines=_ACME_ENV)
        _deploy(r)
        _stage_live_cert(r)
        assert cmd_cert_renew(r) == 0  # FakeRunner default rc=0
        assert not cert_restart_marker(r).is_file()

    def test_undeployed_instance_skips_restarts_and_stays_green(
        self, mk_runner, capsys
    ) -> None:
        # First-time acme issuance (README quick start step 4 runs BEFORE the
        # first play): the consumer units don't exist yet — a failed restart
        # there is the expected state, not an incident (review finding).
        r = mk_runner(env_lines=_ACME_ENV)
        _stage_live_cert(r)
        r.script("systemctl", "--user", rc=1)  # would fail if attempted
        assert cmd_cert_renew(r) == 0
        assert not cert_restart_marker(r).is_file()
        assert "not yet deployed" in capsys.readouterr().out
        assert not any("restart" in " ".join(c) for c in r.calls)

    def test_monitor_nags_while_marker_present(self, mk_runner) -> None:
        r = mk_runner()
        r.tools = {"logger"}
        marker = cert_restart_marker(r)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("carlos-waf.service\n")
        m = MonitorRun(r)
        monitor_mod._check_cert_restart_marker(m)
        assert "cert-restart-needed" in m.fired

    def test_monitor_quiet_without_marker(self, mk_runner) -> None:
        r = mk_runner()
        r.tools = {"logger"}
        m = MonitorRun(r)
        monitor_mod._check_cert_restart_marker(m)
        assert not m.fail


class TestSelfSignedHalfPlacedRefusal:
    """M5: selfsigned mode must never overwrite a HALF-placed operator cert
    (exactly one of fullchain/privkey present)."""

    def _certs(self, r):
        c = _certs_dir(r)
        c.mkdir(parents=True, exist_ok=True)
        return c

    @pytest.mark.parametrize("present", ["fullchain.pem", "privkey.pem"])
    def test_one_file_present_refuses_without_clobbering(self, mk_runner, present) -> None:
        r = mk_runner("SERVER_NAME=emr.example.ca\n")
        r.tools = {"openssl"}
        c = self._certs(r)
        (c / present).write_bytes(b"OPERATOR-PLACED")
        with pytest.raises(CtlError, match="half-placed operator certificate"):
            ensure_selfsigned_cert(r)
        assert (c / present).read_bytes() == b"OPERATOR-PLACED"  # untouched


class TestCertSelfIssuedAnchoring:
    """L9: the self-issued CN check must be an anchored whole-RDN match, not a
    substring — else CN=<server>.evil or an empty SERVER_NAME classifies an
    operator cert as ours and regenerates over it."""

    def _wire(self, r, subject: str, issuer: str) -> None:
        r.tools = {"openssl"}
        r.script("openssl", "x509", rc=0, out=f"subject={subject}\nissuer={issuer}\n")

    def test_exact_cn_is_ours(self, mk_runner) -> None:
        r = mk_runner()
        self._wire(r, "CN = emr.example.ca, O = x", "CN = emr.example.ca, O = x")
        assert _cert_is_self_issued_for(r, Path("/c"), "emr.example.ca") is True

    def test_legacy_slash_form_is_ours(self, mk_runner) -> None:
        r = mk_runner()
        self._wire(r, "/CN=emr.example.ca/O=x", "/CN=emr.example.ca/O=x")
        assert _cert_is_self_issued_for(r, Path("/c"), "emr.example.ca") is True

    def test_suffixed_cn_is_not_ours(self, mk_runner) -> None:
        r = mk_runner()
        self._wire(r, "CN = emr.example.ca.evil, O = x",
                   "CN = emr.example.ca.evil, O = x")
        assert _cert_is_self_issued_for(r, Path("/c"), "emr.example.ca") is False

    def test_empty_server_never_matches(self, mk_runner) -> None:
        r = mk_runner()
        self._wire(r, "CN = anything, O = x", "CN = anything, O = x")
        assert _cert_is_self_issued_for(r, Path("/c"), "") is False
