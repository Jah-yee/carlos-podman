# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Shared fixtures: a hermetic Settings factory and a scripted FakeRunner.

The FakeRunner mirrors the shell test suite's recording stubs at the Python
layer: every argv is recorded, and tests script results by prefix match. The
e2e suite (tests/run-tests.sh) still exercises the REAL Runner against the
PATH stubs in tests/stubs/."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import pytest

from carlos_ctl.config import Settings
from carlos_ctl.runner import Runner


class FakeRunner(Runner):
    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.calls: List[List[str]] = []
        self.stdins: List[str] = []  # input_text per call (off-argv payloads)
        # (prefix tuple) -> (returncode, stdout)
        self.results: Dict[Tuple[str, ...], Tuple[int, str]] = {}
        self.default = (0, "")
        self.tools = {"systemctl", "podman", "ss", "nft", "curl", "openssl", "swapon"}

    def script(self, *prefix: str, rc: int = 0, out: str = "") -> None:
        self.results[tuple(prefix)] = (rc, out)

    def have(self, tool: str) -> bool:
        return tool in self.tools

    def podman_user_argv(self, args: Sequence[str]) -> List[str]:
        # The real implementation resolves the service user's uid (runuser
        # boundary); the fake skips that so tests need no local 'carlos' user.
        return ["podman", *args]

    def run(self, argv: Sequence[str], **kw: object) -> subprocess.CompletedProcess:
        argv = list(argv)
        # Off-argv payloads (curl -K - config carrying the URL, kube-play
        # manifests, SQL) ride input_text — matchable for SCRIPTING below
        # (mirrors the shell curl stub, which parses the -K config), but kept
        # OUT of self.calls: the off-argv assertions ("the secret never
        # appears as an argv token") must keep meaning argv.
        stdin_text = str(kw.get("input_text") or "")
        self.calls.append(argv)
        self.stdins.append(stdin_text)
        for prefix, (rc, out) in self.results.items():
            if tuple(argv[: len(prefix)]) == prefix or tuple(prefix) == tuple(
                a for a in argv if not a.startswith("-")
            )[: len(prefix)]:
                return subprocess.CompletedProcess(argv, rc, out, "")
        # Substring convenience: match a prefix anywhere in the argv chain
        # (runuser wrappers prepend boundary-crossing argv) or in the
        # off-argv stdin payload.
        joined = " ".join(argv) + (" " + stdin_text if stdin_text else "")
        for prefix, (rc, out) in self.results.items():
            if " ".join(prefix) in joined:
                return subprocess.CompletedProcess(argv, rc, out, "")
        return subprocess.CompletedProcess(argv, self.default[0], self.default[1], "")

    def called_with(self, *parts: str) -> bool:
        return any(" ".join(parts) in " ".join(c) for c in self.calls)


# Every HOST path Settings resolves, with the env knob that redirects it.
# The knobs already exist in config.py ("overridable ONLY so the hermetic test
# suite can run without touching the host") — they simply were not all being
# used, so a ROOT pytest run acted on the real host. Keyed by knob so a new
# host path added to Settings without a knob shows up as an unredirected
# attribute in the drift pin below.
_HERMETIC_DIR_KNOBS = {
    # secrets.py's decrypted-material staging (the pass-8 leak)
    "CARLOS_RUN_DIR": "run",
    # Settings.run_secrets_dir — uninstall rmtree's it, secrets render writes it
    "CARLOS_RUN_SECRETS_DIR": "run-secrets",
    # Settings.systemd_dir — seal WRITES units here, uninstall UNLINKS them
    "CARLOS_SYSTEMD_DIR": "systemd",
    # Settings.tmpfiles_dir — uninstall unlinks <instance>-emr.conf
    "CARLOS_TMPFILES_DIR": "tmpfiles",
    # Settings.instance_registry_dir — uninstall unlinks the registry claim
    # AND the alert-channel mirror; Settings also READS the mirror, so a real
    # /etc entry changes ALERT_* resolution and makes results host-dependent
    "CARLOS_INSTANCE_REGISTRY_DIR": "registry",
    # Settings.credstore_dir — seal writes the TPM cred blob here
    "CARLOS_CREDSTORE_DIR": "credstore",
    # Settings.journal_dir — read-only today, redirected for symmetry
    "CARLOS_JOURNAL_DIR": "journal",
    # Settings.systemd_runtime_dir — sd_booted(3)'s /run/systemd/system probe
    # behind Runner.systemd_running(). Redirected to an EXISTING scratch dir
    # so the unit suite keeps modelling "systemd works" (its FakeRunner.have
    # already reports systemctl present) regardless of whether the machine
    # running pytest booted with systemd. Read-only; nothing writes here.
    "CARLOS_SYSTEMD_RUNTIME_DIR": "systemd-runtime",
}


@pytest.fixture(autouse=True)
def _hermetic_host_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Redirect EVERY host path the CLI resolves into the test's tmp_path.

    CI runs the suites under sudo, and `cmd_uninstall` acts on real paths for
    whatever INSTANCE the Settings under test carries — which is `carlos`,
    the default name a real deployment also uses. Measured live before this
    fixture existed: one `pytest tests/unit` run as root on a host with a
    deployed `carlos` instance DELETED /etc/systemd/system/carlos-backup.timer
    and carlos-monitor.service, the carlos-secrets.service.d drop-in,
    /etc/tmpfiles.d/carlos-emr.conf, /run/carlos-emr/* (the live rendered
    sealed credentials) and both /etc/carlos-podman/instances/carlos.{conf,
    alert.env} — silently decommissioning a PHI instance's backup schedule,
    monitoring, /run secrets and alert-channel fallback while reporting
    "528 passed". Data was untouched; everything else was not.

    The READ direction matters too: Settings falls back to the registry's
    <instance>.alert.env for ALERT_WEBHOOK/ALERT_EMAIL/HEARTBEAT_URL, so a
    host with a real mirror made the alert tests fail — results depended on
    the machine.

    Only the previous `/run` knob was wired up (pass 8); this extends the
    same treatment to the rest."""
    dirs = {}
    for knob, name in _HERMETIC_DIR_KNOBS.items():
        d = tmp_path / "host" / name
        d.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv(knob, str(d))
        dirs[knob] = d
    return dirs


@pytest.fixture
def live_host_probe():
    """Opt a test OUT of the harness marker for the ROOT-only live-host nft
    probes (`monitor._check_nft_hostfw`, the NAT leg of
    `monitor._check_front_door`, `validate.check_foreign_nft_claim`).

    Those three skip themselves when `CARLOS_SYSTEMD_DIR` is set — the knob
    doubles as an "I am the hermetic harness, do not touch the kernel
    ruleset" signal. Now that this conftest redirects that knob for EVERY
    unit test (it must: seal WRITES units there and uninstall UNLINKS them),
    a test that means to exercise the probe has to clear it explicitly.
    Returns a callable applied to the Settings under test."""

    def _apply(runner) -> None:
        runner.settings._env.pop("CARLOS_SYSTEMD_DIR", None)  # noqa: SLF001

    return _apply


@pytest.fixture
def mk_settings(tmp_path: Path, _hermetic_host_paths):
    def _mk(env_lines: str = "", extra_env: Optional[Dict[str, str]] = None) -> Settings:
        home = tmp_path / "emr"
        (home / "container").mkdir(parents=True, exist_ok=True)
        (home / "container" / "carlos-app.env").write_text(env_lines)
        # The redirects ride in the Settings env too: Settings reads these
        # from the mapping it is handed, NOT from os.environ, so monkeypatch
        # alone would leave every mk_settings() Settings pointed at /etc.
        env = {"EMR_HOME": str(home)}
        env.update({knob: str(d) for knob, d in _hermetic_host_paths.items()})
        env.update(extra_env or {})
        return Settings(env)

    return _mk


@pytest.fixture
def mk_runner(mk_settings):
    def _mk(env_lines: str = "", extra_env: Optional[Dict[str, str]] = None) -> FakeRunner:
        return FakeRunner(mk_settings(env_lines, extra_env))

    return _mk
