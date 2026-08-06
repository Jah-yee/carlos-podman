# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Host-status verbs: status and instances. Their siblings live next door —
build/rebuild/rollback in build.py, play/down/enable/check in lifecycle2.py
(split only to keep file sizes reviewable)."""

from __future__ import annotations

import sys

from .config import read_registry
from .runner import Runner
from .util import CtlError, log, warn


def cmd_status(runner: Runner) -> int:
    s = runner.settings
    runner.run(runner.podman_user_argv([
        "pod", "ps",
        "--filter", f"name={s.obs_pod}",
        "--filter", f"name={s.app_pod}",
        "--filter", f"name={s.waf_pod}",
    ]))
    runner.run(runner.podman_user_argv([
        "ps", "--pod",
        "--filter", f"pod={s.app_pod}",
        "--filter", f"pod={s.obs_pod}",
        "--filter", f"pod={s.waf_pod}",
    ]))
    if runner.systemd_running():
        states = []
        for unit in (s.instance, s.obs_pod, s.waf_pod):
            # is-active prints its answer ('failed'/'inactive') with rc 3 —
            # the rc-gated output() would blank every non-active state.
            state = runner.output_any_rc(
                runner.systemctl_user_argv(["is-active", f"{unit}.service"])
            )
            states.append(f"{unit}.service: {state.strip()}")
        print("   ".join(states))
        runner.run(["systemctl", "list-timers", f"{s.instance}-*", "--no-pager"])
    return 0


def cmd_logs(runner: Runner, args: list) -> int:
    """Tail one container's logs without the operator hand-assembling the
    runuser/XDG_RUNTIME_DIR podman incantation. Read-only convenience;
    accepts the short role names (carlos/db/drugref/waf) or a full container
    name. PHI note: app and db streams can carry PHI-correlating identifiers
    — this only shows them on the local terminal, same as `podman logs`."""
    from .util import CtlError

    s = runner.settings
    follow = False
    name = ""
    for a in args:
        if a in ("-f", "--follow"):
            follow = True
        elif not a.startswith("-") and not name:
            name = a
        else:
            raise CtlError("usage: carlos-ctl logs [carlos|db|drugref|waf|<container>] [-f]")
    short = {
        "carlos": f"{s.app_pod}-carlos",
        "db": f"{s.app_pod}-db",
        "drugref": f"{s.app_pod}-drugref",
        "waf": f"{s.waf_pod}-waf",
    }
    ctr = short.get(name or "carlos", name)
    argv = ["logs", "--tail", "200"] + (["--follow"] if follow else []) + [ctr]
    return runner.podman_user(argv).returncode


def cmd_instances(runner: Runner, args: list | None = None) -> int:
    """List every instance registered on this host, reading the cross-instance
    registry (written by the Ansible role). `--prune` removes entries whose
    EMR_HOME no longer exists (an instance removed without `uninstall`).

    `--prune` MUTATES the shared registry, so it is confirmation-gated: it
    deletes another operator's registry pointer, and a mistaken prune hides an
    instance from `instances`/collision asserts. It requires `--yes` (or an
    interactive 'yes') and echoes exactly which stale entries it will drop
    before touching anything."""
    from pathlib import Path

    args = args or []
    prune = "--prune" in args
    assume_yes = "--yes" in args
    for a in args:
        if a not in ("--prune", "--yes"):
            raise CtlError(f"usage: carlos-ctl instances [--prune] [--yes] (got '{a}')")
    s = runner.settings
    reg_dir = s.instance_registry_dir
    entries = sorted(reg_dir.glob("*.conf")) if reg_dir.is_dir() else []
    if not entries:
        log(f"no instances registered (registry: {reg_dir})")
        return 0

    # Prune is a two-phase mutation: identify stale entries, confirm, THEN
    # delete — never delete mid-listing where a scroll-off hides what went.
    stale = [
        f for f in entries
        if not Path(read_registry(f).get("EMR_HOME", "")).is_dir()
    ]
    if prune and stale:
        print(f"==> registry: {reg_dir}")
        print("WILL PRUNE these stale registry entries (EMR_HOME gone):")
        for f in stale:
            reg = read_registry(f)
            print(f"  - {reg.get('INSTANCE', f.stem)}  (EMR_HOME {reg.get('EMR_HOME', '')})")
        if not assume_yes:
            if sys.stdin.isatty():
                if input("Type 'yes' to prune these registry entries: ") != "yes":
                    raise CtlError("prune aborted")
            else:
                raise CtlError(
                    "refusing to --prune non-interactively without confirmation: "
                    "re-run with 'instances --prune --yes'"
                )
        for f in stale:
            name = read_registry(f).get("INSTANCE", f.stem)
            f.unlink(missing_ok=True)
            log(f"pruned stale entry '{name}'")
        entries = [f for f in entries if f not in stale]
        if not entries:
            return 0
    elif prune and not stale:
        warn("no stale registry entries to prune (every EMR_HOME still exists)")

    fmt = "{:<12} {:<24} {:<16} {:<13} {:<8} {:<6} {:<6} {:<6} {:<8}"
    print(fmt.format(
        "INSTANCE", "EMR_HOME", "BIND_IP", "HTTPS→PUB", "LOGVIEW", "VLOGS", "VMETR", "PMA",
        "STATUS",
    ))
    for f in entries:
        reg = read_registry(f)
        name = reg.get("INSTANCE", "")
        home = reg.get("EMR_HOME", "")
        suser = reg.get("SERVICE_USER", "") or s.service_user
        if not Path(home).is_dir():
            status = "stale"
        elif runner.systemd_running():
            out = runner.output_any_rc(
                ["systemctl", "--user", "-M", f"{suser}@", "is-active", f"{name}.service"]
            ).strip()
            status = out or "unknown"
        else:
            status = "?"
        print(fmt.format(
            name, home, reg.get("BIND_IP", ""),
            f"{reg.get('HTTPS_PORT', '')}→{reg.get('HTTPS_PUBLISH_PORT', '')}",
            reg.get("LOG_VIEW_PORT", ""), reg.get("VICTORIALOGS_PORT", ""),
            reg.get("VICTORIAMETRICS_PORT", ""), reg.get("PMA_PORT", ""), status,
        ))
    return 0
