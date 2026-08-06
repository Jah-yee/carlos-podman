<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 CARLOS Contributors -->
# carlos-podman — ninth-pass review + live end-to-end test report (2026-08-01)

Scope: a fresh adversarial re-review of `carlos_ctl/` (four parallel readers
over the secrets/rotation, backup/PITR, lifecycle/monitor/cli, and Ansible
role/Containerfile surfaces), **plus a full live end-to-end exercise** in a
rootful-podman sandbox (podman 4.9.3, Ubuntu 24.04, cgroup v1, no systemd
PID 1, TLS-intercepting egress proxy, `nofile` hard cap 4096): real image
builds from source, `podman kube play` of the dev spec against
`carlos-emr/carlos@af909f50` + `drugref2026@101063bb`, the Ontario Flyway
schema (427 tables), the app repo's Playwright login suite, and a systematic
drive of the **complete** `carlos-ctl` verb matrix (every verb in `cli.py`'s
dispatch). Everything reported fixed in `REVIEW-2026-08-01-pass8.md` was
treated as baseline and re-verified present; only NEW findings are reported
here.

## What was executed, and results

- **Repo test suites (baseline, before any fix)**: `pytest tests/unit`
  **465/465**; hermetic e2e `tests/run-tests.sh` **279/279**; ruff clean;
  mypy clean; `tests/ansible-checks.sh` fully green (after installing
  `ansible.utils`/`community.general` and pinning the control node's
  `bcrypt<4.1` — the role's own G1 gate caught the passlib/bcrypt-5 combo and
  its error message prescribed the exact fix, re-verified live).
- **Image builds from source, three times**: (1) full `carlos-ctl build`
  (~4 min Maven compile: CA staging via `CARLOS_EXTRA_CA_BUNDLE` through the
  TLS-intercepting proxy, forked-javac build, post-build smoke,
  build-then-promote, three-way tagging); (2) `build --use-cache` (`:previous`
  rotation verified in `podman images`: app `:previous` == the prior build id,
  drugref lockstep); (3) `rebuild` (fresh no-cache build of BOTH images,
  promote, then the loud `play` abort at the provisioning gate — the
  documented build-ok/deploy-blocked contract).
- **Deploy**: `scripts/dev-setup.sh` with a hostile password (`p@ss&"\{#Q9`)
  → `podman kube play` → ON migrations V1…V1.0.6 (427 tables) → **app served
  200 in 24 s** (the pass-7 wait-for-db backslash fix, re-proven live).
- **Playwright**: `scripts/login-playwright-checks.js` against
  `https://127.0.0.1:8443/carlos` — **14/14 checks pass** (login, forced
  reset persistence + retry, CSRF rejection, weak-password rejection,
  legacy-route reset guard, old/new password behavior); security row restored.
- **carlos-ctl verb matrix, live** (every dispatch verb): `version`, `help`,
  `status`, `check` (rc=1 with dev-topology FAILs), `logs`
  (carlos/db/nonexistent→125), `instances`, `instances --prune`, `--instance
  <unregistered>` (fail-closed), `--instance carlos` (ok), `guard` (undeployed
  + post-`down`), `build`, `build --use-cache`, `rebuild`, `play`
  (provisioning-gate refusal), `rollback` (lockstep retag of BOTH images to
  `:previous` + loud play abort), `down` (pod removed, rc=0; `--bogus` usage),
  `enable` (rc=1, loud failed-timer list), `cert-renew` (selfsigned-mode
  refusal), `db` (live SQL, incl. across rotations), `db-dump` (427-table dump
  + PHI plaintext warning), `db-backup` (mariadb-backup snapshot with binlog
  coordinates), `pma` (real phpMyAdmin on :9444, **TTL auto-stop honored**;
  a deliberately-orphaned panel was **caught and paged by `monitor`**),
  `db-users` (refusal without `drugref2.properties`, then a real run: all four
  least-priv accounts verified in `mysql.user`, app healthy on the rotated
  credentials after re-play), `backup full` (local-repo refusal → non-InnoDB
  refusal (`oscar.formRourke2009` [Aria]) → acknowledged run → **sealed-mode
  run decrypting restic creds from the bundle**), `binlogs`, `docs`, `status`
  (all freshness stamps), `verify` (restore drill: dump load + binlog replay +
  doc byte-verify), `restore` (`--dry-run` plan, non-interactive confirmation
  refusal, then a **real destructive PITR restore** — a marker row committed
  after the last dump, existing only in binlogs, survived the replay), `monitor`
  (8-fault relay to a live local webhook, incl. the orphaned-PHI-panel page),
  `alert-test` (journal-only ack + real webhook delivery), `alert <unit> <msg>`
  (delivery + **OnFailure throttle verified**: repeat suppressed, stamp
  persisted under `monitor/state`), `seal` (escrow refusal → no-TPM ack → real
  seal: bundle written, creds ingested to `__SEALED__` placeholders), `secrets
  render` (real sealed render), `rotate db`, `rotate db-root` (hostile new
  password, `db` verified on the rotated credential), `rotate restic` (next
  `backup full` green under the rotated key), `rotate age-key` (real re-key
  with persist-before-swap + re-escrow warning), `rotate log-view`/`obs`
  (provisioning refusals), `rotate bogus` (usage), `setup` (non-interactive
  empty-password refusal), `uninstall` (non-interactive refusal without both
  confirmations, wrong-instance-name refusal, then a real decommission —
  **2.3 GB data tree preserved**, registry entry dropped), and the
  **per-instance mutating lock verified live** (a `db-backup` refused while a
  helper held the instance lock).

Two live observations worth recording, neither a code defect:

- **The `rotate db-root` / restore interaction is a documented re-play
  requirement, not a bug.** `podman restart <container>` does NOT re-run the
  pod's `carlos-init` init container, so the merged
  `/run/carlos-config/carlos.properties` stays frozen at deploy time
  (`db_username=root`, pre-`db-users`). After rotations, only a full
  `carlos-ctl play` / `kube play --replace` re-runs init and picks up the
  current base + sealed fragment — which recovered the app cleanly (200 in
  51 s). In production `carlos-ctl play` is the restart path, so this is the
  correct flow; it is worth a QUICKSTART note for the raw-`kube play` dev path.
- **The restore drill lost a container-startup race under heavy sandbox
  load** (3 of 5 runs): the scratch MariaDB passed its readiness ping, then
  exited before the dump load under concurrent build/IO pressure, and the
  failure message misdirected at `VERIFY_TMPFS_SIZE`. This is the load-leg
  sibling of pass-8 L1 and is fixed below (L1).

## New findings (all fixed on this branch, each with a test pin)

**M1 (MEDIUM, backup/PITR). `--dry-run` falsely refuses a reachable
`--stop-datetime` on the will-ship path, and coaches a data-loss override.**
`backup.py:_restore_pitr`/`fetch_chain`. A dry-run whose local binlogs
continue the dump's chain (`will_ship`) routes through `fetch_chain` without
the final ship, so the past-chain-end guard compares the stop instant against
the *stale* repo chain and refuses — steering the operator to export
`CARLOS_STOP_PAST_CHAIN_END_OK=1` (a data-loss ack) for a refusal the real run
(which ships the active binlog after the app-stop) would never make.
**Live-confirmed**: `backup restore --dry-run --stop-datetime <now-5s>` refused
with the POSTDATES message. Fix: skip the refusal when `dry and will_ship`,
emitting an informational plan line instead. Pin:
`TestDryRunWillShipDoesNotFalselyRefuse`.

**M2 (MEDIUM, backup/PITR + dbops/secrets). Credential-provisioning and
db-root-rotation SQL is binlogged, so PITR replay re-applies account DDL.**
`dbops._PROVISION_SQL`, `secrets._rotate_db_root`. Neither batch set
`SET SESSION sql_log_bin=0`, so every `CREATE/ALTER USER`/`GRANT` (root and
the four least-priv accounts) rode the binary log while the restore machinery's
own contract is that accounts are *never* restored. A `rotate db-root` between
the nightly dump and the Sunday drill overwrites the drill's scratch-root
password and yields a misleading "sanity query returned no row count" failure;
a windowed restore across two rotations rewinds `mysql.user` to a stale
generation while the credential stores hold the current one — app-down at
reboot, worst case a root lockout requiring skip-grant-tables. The load/replay
legs already run `sql_log_bin=0`; this closes the provisioning half. Fix:
prepend `SET SESSION sql_log_bin=0` to both SQL batches. Pins:
`TestProvisioningSqlNotBinlogged`, `TestRotateDbRoot::test_root_alter_is_not_binlogged`.

**M3 (MEDIUM, config/guards). A persisted word-boolean
(`CARLOS_ACCEPT_EMPTY_DATADIR=true`) disarms the blank-datadir guard on every
boot with no warning.** `config.warn_if_persisted_oneshot` compared `== "1"`
while the guards read the value via `flag()` (which accepts `1/true/yes/on`),
so the fail-open half of the persisted-override warning never fired for the
word spellings. Fix: share one `_TRUTHY_FLAGS` set between `flag()` and the
persisted-oneshot warning. Pin:
`TestFlagTruthinessSharedWithPersistedWarning`.

**M4 (MEDIUM, config/alerting). The alert-channel sidecar is read for the
DEFAULT instance under `--instance` pinning — the exact unmounted-volume
incident it exists for.** `config.Settings.__init__` built the sidecar path
from `self.get('INSTANCE')` (which falls back to `carlos` when the pinned
instance's env file is missing) instead of the pinned `self.instance`. So
`carlos-ctl --instance clinicb guard|monitor|alert` with clinicb's volume
unmounted delivered clinicb's page to the *carlos* instance's channel (or
nowhere). Fix: build the sidecar path from `self.instance` (the pass-7
identity-pin value). Pin:
`TestAlertChannelSidecar::test_pinned_instance_reads_its_own_sidecar_not_the_default`.

**M5 (MEDIUM, secrets/rotation). `rotate restic` never validated
`RESTIC_NEW_PASSWORD`, so a newline/CR corrupts the line-oriented
`RESTIC_PASSWORD=` store.** `secrets._rotate_restic`. The sibling rotations
(`rotate db-root`, `rotate obs`) validate their operator values; this one
wrote the raw value into `restic.env`, where a newline splits the line and a
CR is trimmed by restic but kept in the file — the stored password then stops
opening the repo. Fix: `validate_db_password(new_pw, "RESTIC_NEW_PASSWORD")`
before any mutation. Pin: `TestRotateResticValidation`.

**M6 (MEDIUM, ansible). The same-engine image-identity assert (pass-7 fix)
omits `carlos_drugref_ref`.** `tasks/asserts.yml`. Two siblings sharing a
service user (one image store) that disagree on `carlos_drugref_ref` passed
the assert, yet `carlos-ctl build` builds BOTH images from the per-instance
refs — one instance's build silently retags the drugref image the other runs
and destroys its rollback target. Fix: add `carlos_drugref_ref` to the
compared set and the fail_msg. Pin: ansible-checks presence case.

**L1 (LOW, backup). A SIGKILLed restore drill's `.verify.*` scratch dir
(plaintext PHI) escapes the 15-minute reaper for up to a week, and a scratch
DB that dies before the load is misdiagnosed as a tmpfs-sizing problem.**
`backup._reap_orphaned_stagings` swept `.restore.*` (24h age-gate on every
backup verb) but not the drill's identically-shaped `.verify.*`, which was
only cleaned at the start of the next weekly drill. Separately, a scratch
MariaDB that passes the readiness ping then exits before the dump load
(observed live 3/5 under sandbox load) produced a raw socket error and the
`VERIFY_TMPFS_SIZE` guidance. Fixes: add `.verify.*` to the age-gated reaper;
add a container-liveness check before the load with an accurate
startup/OOM message. (No standalone pin beyond the existing drill tests; both
are contained diagnostic/hygiene changes.)

**L2 (LOW, ansible). `carlos_emr_home` permits whitespace and `%`, which
corrupt every systemd unit that embeds the path.** `tasks/asserts.yml`. A
space makes systemd word-split `Environment=EMR_HOME=...`; a `%` is
specifier-expanded — both silently point every timer/guard/alert unit at the
wrong tree while provisioning reads green. Fix: reject whitespace and `%`. Pin:
ansible-checks whitespace case.

**L3 (LOW, ansible). The obs HTTP username assert misses `:`.**
`tasks/asserts.yml`. RFC 7617 basic auth splits on the first colon, so a
colon in `carlos_obs_http_user` moves part of it into the password and every
store client (vmagent, vector, Caddy, vmalert) 401s on a fully-green
provisioning run. Fix: add `:` to the denylist. Pin: ansible-checks colon
case.

**L4 (LOW, uninstall). A persisted `CARLOS_UNINSTALL_CONFIRMED`/`_INSTANCE`
pair pre-confirms every future `uninstall` — even interactively — with no
warning.** `uninstall.cmd_uninstall`. `backup restore` got a persisted-value
warning in pass-7; uninstall had no equivalent, so two stale env-file lines
could decommission the instance from a fat-fingered verb months later. Fix:
warn value-agnostically when the pair is persisted. Pin:
`TestPersistedConfirmationWarning`.

**L5 (LOW, docs). QUICKSTART step 2's manual `sed` render drifted from
`carlos.properties.j2`.** Three template tokens changed in pass-7
(`HL7_A04_GENERATION` gained `| bool`; the two TOMCAT keystore passwords gained
`| replace('\\','\\\\')`) but the QUICKSTART sed expressions did not — running
the documented pipeline left three unrendered `{{ … }}` tokens and the
mandated `! grep '{{'` safety check then failed the walkthrough.
**Live-confirmed** by running the verbatim pipeline. Fix: update the three sed
expressions (verified to render clean). `scripts/dev-setup.sh` was unaffected
(name-based substitution).

**N1 (nit, secrets). `_rotate_age_key`'s unconditional key-file `_shred`
emits a false "plaintext may be recoverable" warning on a TPM host**, where
`seal` already shredded the on-disk key. Fix: guard the shred with
`is_file()`, matching the adjacent recovery-wrap shred.

## Findings reviewed and NOT fixed (documented, lower stakes)

These were surfaced by the review sweep, confirmed real, and left as tracked
consistency debt — each is fail-*closed* or requires manual image/FS surgery
to reach, so none is an open exposure:

- **`--instance` pins EMR_HOME + INSTANCE but not SERVICE_USER** (cli/config).
  Under per-instance service users with a missing env file, verbs could target
  the wrong user's engine. Real, but the recommended isolation posture
  (per-instance users) is not the default, and the fix touches the
  registry-pin path broadly; tracked for a focused follow-up.
- **`preflight_reseal` treats a tty as a satisfied escrow gate** (secrets), so
  an interactive `rotate db` begun before re-escrowing can refuse *after* the
  DB was re-passworded. Real but narrow (requires an un-re-escrowed interactive
  rotation between an age-key rotation and a seal); the safe fix is to resolve
  the escrow answer up front and add a `bundle_decrypts()` probe.
- **Several `== "1"` override sites** (`CARLOS_ALLOW_DB_ROOT`,
  `CARLOS_ACCEPT_NEW_BINLOG_IDENTITY`, the backup override family) accept only
  the `=1` spelling. All fail-closed (a `true` spelling leaves the refusal in
  place), so consistency debt, not a hole; unify on `flag()` next pass.
- **`rotate db-root`'s `secret rm` failure branch misdiagnoses "in use" vs
  "no such secret"** and skips recreating a genuinely-missing db-root secret
  on a rebuilt host. Narrow (DR path with a fresh podman store).
- **`0.0.0.0` bind + default-on host firewall = front-door blackout**
  (nat.nft.j2): the `ip daddr 0.0.0.0` allow rules match no real packet under
  `policy drop`. Requires the documented `carlos_allow_any_bind` opt-out on a
  hostfw-enabled host; worth an assert next pass.
- **`cmd_db_backup` name regex admits `.`/`..`** — safe today only by the
  role pre-creating `backup/mariadb-hot`; tighten to reject dot-only names.

## Suite status after fixes

- `pytest tests/unit`: **465 → 473** (8 new pins).
- hermetic e2e `tests/run-tests.sh`: **279** (unchanged; the new behaviors are
  pinned at the unit + ansible-checks layers).
- `tests/ansible-checks.sh`: green, with **3 new negative-assert cases**
  (obs-username colon, emr_home whitespace, drugref_ref same-engine).
- ruff clean; mypy clean.
