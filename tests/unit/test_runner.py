# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Unit tests for carlos_ctl.runner.Runner — the real subprocess chokepoint.

Most of the suite drives the scripted FakeRunner, which overrides run(); these
tests exercise the ACTUAL subprocess path so the timeout contract (a hang reads
as a failure, not a crash) is proven, not mocked."""

from __future__ import annotations

import inspect
import os

import pytest

from carlos_ctl.runner import Runner
from carlos_ctl.util import CtlError


class TestRunTimeout:
    def test_bounded_call_exceeding_timeout_returns_rc124(self, mk_settings) -> None:
        runner = Runner(mk_settings())
        cp = runner.run(["sleep", "5"], timeout=0.2)
        # A hang on a bounded call is a FAILURE, not an exception: ok()/output()
        # must see nonzero so the caller's fail-closed path runs.
        assert cp.returncode == 124
        assert cp.stdout == ""

    def test_ok_helper_returns_false_on_timeout(self, mk_settings) -> None:
        runner = Runner(mk_settings())
        assert runner.ok(["sleep", "5"], timeout=0.2) is False

    def test_checked_call_raises_ctlerror_on_timeout(self, mk_settings) -> None:
        runner = Runner(mk_settings())
        with pytest.raises(CtlError):
            runner.run(["sleep", "5"], check=True, timeout=0.2)

    def test_call_finishing_inside_timeout_completes(self, mk_settings) -> None:
        runner = Runner(mk_settings())
        cp = runner.run(["true"], timeout=5)
        assert cp.returncode == 0

    def test_default_none_timeout_does_not_bound(self, mk_settings) -> None:
        # The default (unbounded) path must never pass timeout= to subprocess —
        # a legitimately long db dump / image pull / restic restore must run to
        # completion. A brief real sleep with no timeout stands in for that.
        runner = Runner(mk_settings())
        cp = runner.run(["sleep", "0.3"])
        assert cp.returncode == 0


class TestCrossUserCwd:
    """`runuser` keeps the CALLER's cwd and hard-fails when the service user
    cannot enter it — and /root (0700) is the cwd of every `sudo -i` root
    shell. Measured live: from /root every podman call died with 'cannot chdir
    to /root: Permission denied', so `check` reported the networks and pods
    missing on a healthy host and `down` exited 0 with everything still
    running. The crossing therefore runs from a directory that is always
    traversable."""

    def _spawn_cwd(self, runner: Runner, argv0: str, tmp_path) -> str:
        # Run from a directory that EXISTS but is not "/" so the assertion
        # distinguishes "inherited the caller's cwd" from "pinned".
        here = os.getcwd()
        os.chdir(tmp_path)
        try:
            return runner.run([argv0, "-c", "pwd"], capture=True).stdout.strip()
        finally:
            os.chdir(here)

    def test_non_runuser_calls_keep_the_callers_cwd(self, mk_settings, tmp_path) -> None:
        # Only the cross-user boundary is pinned: a plain local command must
        # still observe the caller's directory (nothing in the tree depends on
        # it today, and silently relocating every child is a bigger change).
        runner = Runner(mk_settings())
        assert self._spawn_cwd(runner, "sh", tmp_path) == str(tmp_path)

    def test_runuser_boundary_is_pinned_not_inherited(self, mk_settings, tmp_path) -> None:
        # A fake `runuser` on PATH that just execs its trailing argv proves the
        # child really is spawned from "/" and not from the caller's cwd.
        fake = tmp_path / "bin"
        fake.mkdir()
        (fake / "runuser").write_text("#!/bin/sh\nexec pwd\n")
        (fake / "runuser").chmod(0o755)
        old_path = os.environ["PATH"]
        os.environ["PATH"] = f"{fake}:{old_path}"
        try:
            runner = Runner(mk_settings())
            assert self._spawn_cwd(runner, "runuser", tmp_path) == "/"
        finally:
            os.environ["PATH"] = old_path

    def test_wrapped_runuser_is_pinned_too(self, mk_settings) -> None:
        # `pma` wraps the crossing in `timeout -k 10 <ttl>m runuser …`, so the
        # rule must be membership, not argv[0].
        from carlos_ctl.runner import _crosses_user_boundary

        assert _crosses_user_boundary(
            ["timeout", "-k", "10", "120m", "runuser", "-u", "carlos", "--", "podman", "run"]
        )
        assert _crosses_user_boundary(["runuser", "-u", "carlos", "--", "podman", "ps"])
        assert not _crosses_user_boundary(["podman", "ps"])


def test_runner_run_signature_accepts_timeout() -> None:
    # Guards against a refactor dropping the param the bounded call sites rely on.
    assert "timeout" in inspect.signature(Runner.run).parameters
    assert "timeout" in inspect.signature(Runner.podman_user).parameters


class TestSystemdRunning:
    """`have("systemctl")` answers "is the binary on PATH", which is NOT the
    question every no-systemd fallback in this tree is asking. Debian/Ubuntu
    ship /usr/bin/systemctl inside container images, WSL distributions and
    chroots where systemd never booted; there the binary resolves and every
    call exits nonzero. Measured on such a host: `seal` ingested both DB
    credentials, rewrote both properties files to __SEALED__, shredded the
    plaintext restic.env and then died on `systemctl daemon-reload` with zero
    /run fragments rendered — the inline-render fallback never ran. The
    predicate therefore adds sd_booted(3)'s own test."""

    def test_true_when_binary_present_and_manager_running(self, mk_settings, tmp_path) -> None:
        rt = tmp_path / "systemd-system"
        rt.mkdir()
        runner = Runner(mk_settings(extra_env={"CARLOS_SYSTEMD_RUNTIME_DIR": str(rt)}))
        if not runner.have("systemctl"):
            import pytest

            pytest.skip("no systemctl on this machine's PATH")
        assert runner.systemd_running() is True

    def test_false_when_the_manager_never_booted(self, mk_settings, tmp_path) -> None:
        # The binary may well be present — that is the whole point of the case.
        missing = tmp_path / "no-such-run-systemd-system"
        runner = Runner(mk_settings(extra_env={"CARLOS_SYSTEMD_RUNTIME_DIR": str(missing)}))
        assert runner.systemd_running() is False

    def test_false_when_the_binary_is_absent(self, mk_settings, tmp_path) -> None:
        rt = tmp_path / "systemd-system"
        rt.mkdir()
        runner = Runner(mk_settings(extra_env={"CARLOS_SYSTEMD_RUNTIME_DIR": str(rt)}))
        old_path = os.environ["PATH"]
        os.environ["PATH"] = str(tmp_path / "empty-bin")
        try:
            assert runner.systemd_running() is False
        finally:
            os.environ["PATH"] = old_path

    def test_default_probe_path_is_sd_booted(self, mk_settings) -> None:
        # The default must stay /run/systemd/system — the knob exists only so
        # the suites can model both host shapes.
        from carlos_ctl.config import Settings

        assert str(Settings({"EMR_HOME": "/nonexistent", "ENV_FILE": "/nonexistent"})
                   .systemd_runtime_dir) == "/run/systemd/system"
