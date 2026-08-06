# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Unit tests for `carlos-ctl instances [--prune]` — the confirmation gate that
protects the shared cross-instance registry (finding 37/43)."""

from __future__ import annotations

import io

import pytest

from carlos_ctl.lifecycle import cmd_instances
from carlos_ctl.util import CtlError


def _reg(mk_runner, tmp_path):
    reg = tmp_path / "registry"
    reg.mkdir()
    r = mk_runner("", {"CARLOS_INSTANCE_REGISTRY_DIR": str(reg)})
    return r, reg


def _write_entry(reg, name: str, home: str) -> None:
    (reg / f"{name}.conf").write_text(f"INSTANCE={name}\nEMR_HOME={home}\n")


class TestInstancesPrune:
    def test_lists_without_touching_registry(self, mk_runner, tmp_path) -> None:
        r, reg = _reg(mk_runner, tmp_path)
        _write_entry(reg, "carlos", str(tmp_path))  # home exists
        assert cmd_instances(r, []) == 0
        assert (reg / "carlos.conf").is_file()

    def test_prune_refuses_non_interactive_without_yes(
        self, mk_runner, tmp_path, monkeypatch
    ) -> None:
        r, reg = _reg(mk_runner, tmp_path)
        _write_entry(reg, "stale", str(tmp_path / "gone"))
        monkeypatch.setattr("sys.stdin", io.StringIO(""))  # not a tty
        with pytest.raises(CtlError, match="non-interactively"):
            cmd_instances(r, ["--prune"])
        assert (reg / "stale.conf").is_file()  # untouched

    def test_prune_with_yes_removes_stale(self, mk_runner, tmp_path) -> None:
        r, reg = _reg(mk_runner, tmp_path)
        _write_entry(reg, "stale", str(tmp_path / "gone"))
        _write_entry(reg, "carlos", str(tmp_path))  # live
        assert cmd_instances(r, ["--prune", "--yes"]) == 0
        assert not (reg / "stale.conf").is_file()
        assert (reg / "carlos.conf").is_file()

    def test_prune_leaves_live_entries(self, mk_runner, tmp_path, capsys) -> None:
        r, reg = _reg(mk_runner, tmp_path)
        _write_entry(reg, "carlos", str(tmp_path))  # every home exists
        assert cmd_instances(r, ["--prune", "--yes"]) == 0
        assert (reg / "carlos.conf").is_file()
        assert "no stale" in capsys.readouterr().err

    def test_rejects_unknown_flag(self, mk_runner, tmp_path) -> None:
        r, reg = _reg(mk_runner, tmp_path)
        _write_entry(reg, "carlos", str(tmp_path))
        with pytest.raises(CtlError, match="usage"):
            cmd_instances(r, ["--nope"])
