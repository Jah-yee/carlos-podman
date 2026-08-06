# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Unit tests for carlos_ctl.uninstall — the #12 sibling-glob guard.

Uninstalling instance 'carlos' must never touch a prefix-overlapping sibling
'carlos-test' whose units also match the bare `carlos-*` glob."""

from __future__ import annotations

from carlos_ctl import uninstall


def _touch(p) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("")


class TestInstanceUnitPaths:
    def test_excludes_prefix_overlapping_sibling_units(self, mk_settings, tmp_path) -> None:
        s = mk_settings()
        # Point systemd + registry dirs at the tmp tree.
        s.systemd_dir = tmp_path / "systemd"
        s.instance_registry_dir = tmp_path / "registry"
        s.systemd_dir.mkdir()
        s.instance_registry_dir.mkdir()
        # Register a sibling whose name extends this instance's with a hyphen.
        (s.instance_registry_dir / "carlos-test.conf").write_text("INSTANCE=carlos-test\n")
        (s.instance_registry_dir / "carlos.conf").write_text("INSTANCE=carlos\n")
        # Units for BOTH instances (all match the bare `carlos-*` glob).
        _touch(s.systemd_dir / "carlos-backup.service")
        _touch(s.systemd_dir / "carlos-monitor.timer")
        _touch(s.systemd_dir / "carlos-backup.service.d")  # drop-in dir
        _touch(s.systemd_dir / "carlos-test-backup.service")
        _touch(s.systemd_dir / "carlos-test-monitor.timer")

        units, dropins = uninstall._instance_unit_paths(s)
        names = {p.name for p in units}
        assert names == {"carlos-backup.service", "carlos-monitor.timer"}
        assert all("carlos-test-" not in p.name for p in units)
        assert all("carlos-test-" not in p.name for p in dropins)

    def test_keeps_all_units_when_no_sibling(self, mk_settings, tmp_path) -> None:
        s = mk_settings()
        s.systemd_dir = tmp_path / "systemd"
        s.instance_registry_dir = tmp_path / "registry"
        s.systemd_dir.mkdir()
        s.instance_registry_dir.mkdir()
        (s.instance_registry_dir / "carlos.conf").write_text("INSTANCE=carlos\n")
        _touch(s.systemd_dir / "carlos-backup.service")
        _touch(s.systemd_dir / "carlos-binlog.timer")
        units, _ = uninstall._instance_unit_paths(s)
        assert {p.name for p in units} == {"carlos-backup.service", "carlos-binlog.timer"}


class TestPersistedConfirmationWarning:
    """Ninth-pass: a confirmation pair PERSISTED in the env file pre-confirms
    every future uninstall with no prompt. cmd_uninstall must warn about it,
    mirroring the restore path's persisted-confirmation warning."""

    def test_persisted_confirmation_warns(self, mk_runner, capsys) -> None:
        r = mk_runner(
            "CARLOS_UNINSTALL_CONFIRMED=1\nCARLOS_UNINSTALL_INSTANCE=carlos\n"
        )
        # Drive it far enough to emit the warning; let it fail afterwards (no
        # real host wiring in the hermetic runner) — we only assert the warn.
        import contextlib

        # The hermetic runner has no host wiring, so cmd_uninstall fails after
        # the warning — we only assert the warning fired.
        with contextlib.suppress(Exception):
            uninstall.cmd_uninstall(r)
        assert "PERSISTED" in capsys.readouterr().err
