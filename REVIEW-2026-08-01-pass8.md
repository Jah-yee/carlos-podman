<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 CARLOS Contributors -->
# carlos-podman — eighth-pass review + live end-to-end test report (2026-08-01)

Scope: re-review of `carlos_ctl/` (static pass + a fresh adversarial read of
the secrets/rotation, backup/PITR, monitor, and lifecycle paths), the Ansible
role, both Containerfiles, `scripts/dev-setup.sh`, and the test suites —
**plus a fresh live end-to-end exercise** in a rootful-podman sandbox
(podman 4.9.3, Ubuntu 24.04, cgroup v1, no systemd PID 1, TLS-intercepting
egress proxy, nofile hard cap 65536): real image builds from source,
`podman kube play` of the dev spec against `carlos-emr/carlos@af909f50` +
`drugref2026@101063bb`, the Ontario Flyway schema (427 tables), the app
repo's Playwright login suite, and a systematic drive of the **complete**
`carlos-ctl` verb matrix (every verb in `cli.py`'s dispatch, including
`rebuild` and a real `seal`/`secrets render`/`rotate age-key` leg with
sops+age installed — both firsts for a live pass). Everything reported fixed
in `REVIEW-2026-08-01-pass7.md` was treated as baseline; only NEW findings
are reported here.

## What was executed, and results

- **Repo test suites**: `pytest tests/unit` **464/464**; hermetic e2e
  `tests/run-tests.sh` **270/270**; ruff clean; mypy clean;
  `tests/ansible-checks.sh` fully green (after installing `ansible.utils`/
  `community.general` collections and pinning the control node's
  `bcrypt<4.1` — the role's own G1 gate caught the bad passlib/bcrypt-5
  combo and its error message prescribed the exact fix, verified live).
- **Image builds from source, three times**: (1) full `carlos-ctl build`
  (~10 min: CA staging via `CARLOS_EXTRA_CA_BUNDLE` through the
  TLS-intercepting proxy, forked-javac Maven build, post-build smoke,
  build-then-promote, three-way tagging); (2) `build --use-cache`
  (`:previous` rotation verified in `podman images`); (3) `rebuild`
  (fresh no-cache build, promote, then the loud `play` abort at the
  provisioning gate, rc=1 — the documented build-ok/deploy-blocked contract).
- **Deploy**: `scripts/dev-setup.sh` with a hostile password containing
  `@ & " \ {#` → `podman kube play` → ON migrations V1…V1.0.6 (427 tables)
  → **app served 200 in 37 s** (the pass-7 wait-for-db backslash fix,
  re-proven live; pre-fix behavior was a 600 s stall).
- **Playwright**: `scripts/login-playwright-checks.js` against
  `https://127.0.0.1:8443/carlos` — **14/14 checks pass** (login, forced
  reset persistence, CSRF rejection, weak-password rejection, legacy-route
  reset guard, old/new password behavior); security row restored.
- **carlos-ctl verb matrix, live** (every dispatch verb): `version`, `help`,
  `status`, `check` (rc=1 with dev-topology FAILs; 8 ok with the pod up),
  `logs` (carlos/db/nonexistent→125), `instances`, `instances --prune`
  (non-interactive refusal), `--instance <unregistered>` (fail-closed),
  `guard` (undeployed + non-play-deployed), `build`, `rebuild`, `play`
  (provisioning-gate refusal), `rollback` (lockstep retag of both images +
  loud play abort), `down` (pods stopped and removed, rc=0; `--bogus` usage
  error), `enable` (rc=1, loud failed-timer list), `cert-renew` (selfsigned
  mode refusal), `db` (live SQL incl. after both rotations), `db-dump`
  (427-table dump + PHI plaintext warning), `db-backup` (mariadb-backup
  snapshot with binlog coordinates), `pma` (real phpMyAdmin on :9444, TTL
  honored; a deliberately-orphaned panel was **caught and paged by
  `monitor`**), `db-users` (refusal without `drugref2.properties`, then a
  real run: all four least-priv accounts verified in `mysql.user`, app
  healthy on the rotated credentials after replay), `backup full`
  (local-repo refusal → non-InnoDB refusal (`oscar.formRourke2009` [Aria])
  → acknowledged run → **sealed-mode run decrypting restic creds from the
  bundle**), `binlogs`, `docs`, `status` (all four freshness stamps OK),
  `verify` (restore drill: dump load + 4-binlog replay + doc byte-verify),
  `restore` (`--dry-run` plan, non-interactive confirmation refusal, then a
  **real destructive PITR restore** — a marker row committed after the last
  dump, existing only in binlogs, survived the replay; app back on the
  restored DB in 53 s), `monitor` (fault relay to a live local webhook),
  `alert-test` (journal-only ack + real webhook delivery), `alert <unit>
  <msg>` (delivery + **OnFailure throttle verified**: repeat suppressed,
  stamp persisted under `monitor/state`), `seal` (escrow refusal → no-TPM
  ack → real seal: bundle written, creds ingested to `__SEALED__`
  placeholders, `restic.env` shredded; loud rc=1 only at the sandbox's
  missing systemd), `secrets render` (bundle refusal, then a real sealed
  render), `rotate db`, `rotate db-root` (hostile new password, `db`
  verified on the rotated credential), `rotate restic` (next `backup full`
  green under the rotated key), `rotate age-key` (real re-key with
  persist-before-swap and re-escrow warning), `rotate log-view`/`obs`
  (provisioning refusals), `rotate bogus` (usage), `setup` (non-interactive
  empty-password refusal), `uninstall` (non-interactive refusal without
  both confirmations, then a real decommission — **2.3 GB data tree
  preserved**), and the **per-instance mutating lock verified live twice**
  (`down` and `seal` each refused while a `build` held the lock).

## New findings

**M1 (minor, secrets). `_rotate_age_key`'s staged bundle copy is not in the
`finally` cleanup set.** `carlos_ctl/secrets.py` (rekey flow): `plain` and
`new_key` are unlinked in the `finally`, but `staged`
(`/run/rekey-staged.*.yaml`) is cleaned only on the success path and on the
two explicitly-handled sops failure branches. Any other exception between
its creation and the bundle swap — an `OSError` staging the `.new` key
siblings (disk error, `O_EXCL` collision), or the SIGTERM→SystemExit
conversion firing mid-`sops -e` — leaks the file. Worst-case window
(between `staged.write_text(plain)` and `sops -e -i` completing) the leak
is the **full decrypted bundle in plaintext** at `/run/rekey-staged.*.yaml`
(root-only 0600 on tmpfs, so bounded — but the module's own standard
everywhere else is shred-on-every-path). Reproduced live: the unit suite's
`TestRotateAgeKey::test_keygen_failure_leaves_bundle_untouched` drives
exactly this path (OSError at key staging, after `staged` exists). Fix: add
`staged` (and the transient `new_bundle`) to the `finally` unlink set.

**M2 (minor, tests). The unit suite is not hermetic when run as root — it
leaks fixture files into the host's real `/run`.** `_run_tmpfile()` honors
no test override and falls back to default-tmp only for non-root callers,
so a root `pytest tests/unit/test_secrets.py` (CI runs the suites under
sudo) writes to the real `/run` and, via M1's path, leaves
`rekey-staged.*.yaml` droppings behind (2 per run, measured; content is
fixture data, not real secrets). This contradicts the suites' "nothing
outside the throwaway workdir is touched" contract. Fix: M1's `finally`
closes the leak; consider also a `CARLOS_RUN_DIR`-style override in
`_run_tmpfile` so root test runs stay out of the real `/run` entirely.

**M3 (minor, provisioning — from the static review). The obs-HTTP-password
provisioning assert is narrower than the runtime validator it stands in
for.** `ansible/roles/carlos_podman/tasks/asserts.yml` rejects only `"` and
`\` in `carlos_obs_http_password`, but the value renders into a TOML basic
string (`journald-collector.toml.j2`) and the Caddyfile. A control
character (e.g. a pasted newline/tab) passes the assert and crash-loops the
log-collector at config load on a provisioned PHI instance. The rotate path
(`carlos-ctl rotate obs`) validates control chars; the provisioning path
does not. Fix: extend the assert to reject C0 controls, matching the CLI's
`validate_db_password` posture (same class as pass-7 M12).

**L1 (low, backup). The restore drill's ping-loop exhaustion is not a
terminal condition, producing a misleading failure message.** In
`_verify_restore`, if the throwaway MariaDB never answers
`mariadb-admin ping` within 120 s the loop just falls through; the drill
then fails at the dump load with "could not load carlos-databases.sql …
raise VERIFY_TMPFS_SIZE" — pointing the operator at a tmpfs-sizing fix for
what was actually a scratch-DB startup failure. Observed live: a drill run
concurrent with an image pull lost the startup race and failed with the
wrong message; the re-run passed in 22 s. Fix: on loop exhaustion, warn
"scratch DB never became ready" and return False before the load.

**N1 (nit, config — from the static review).
`CARLOS_RECOVERY_PASSPHRASE_FILE` is read via `Settings.get()` but absent
from `_EXTRA_KNOWN_KEYS`,** so persisting it in `carlos-app.env` (as the
README suggests) triggers the spurious unknown-key warning on every verb.

**N2 (nit, monitor — from the static review). The crash-loop detector's
`RestartCount` baseline silently resets on a whole-pod restart** (containers
recreated at 0), so a crash-loop manifesting as pod-level churn never trips
`container-restarting-*`; partial cover exists via pod-unit-failed and
container-down checks.

## Findings fixed in this pass

All six findings above were fixed on this branch after the report landed,
each with a test pin; suites after fixes: pytest **464 → 465**, hermetic
e2e **270 → 279**, ansible-checks green including the new assert case.

- **M1** *fixed*: `_rotate_age_key` now creates every transient staging
  path inside the `try` and sweeps `staged`/`new_bundle` in the `finally`
  alongside `plain`/`new_key` (the `.new` key/pub crash-recovery siblings
  remain deliberately excluded). Pinned by extending the exact test that
  reproduced the live leak
  (`TestRotateAgeKey::test_keygen_failure_leaves_bundle_untouched`).
- **M2** *fixed*: `_run_tmpfile` honors a `CARLOS_RUN_DIR` override
  (os.environ-only, fail-closed on an unusable dir — never a silent
  fallback to `/run`); `tests/unit/conftest.py` sets it autouse into
  `tmp_path` and `tests/run-tests.sh` exports it into the workdir. Root
  suite runs now leave the real `/run` untouched (measured 0 residue,
  previously 2 files per `test_secrets.py` run).
- **M3** *fixed*: new provisioning assert rejects C0 controls in
  `carlos_obs_http_password` (regex parity with the db-root assert and the
  CLI's rotate-time validation); ansible-checks gained a tab-bearing
  refusal case with the no-value-leak grep.
- **L1** *fixed*: the restore drill's ping-loop exhaustion is now terminal
  — it warns that the scratch MariaDB never became ready (naming container
  startup/image contention, explicitly not VERIFY_TMPFS_SIZE) and returns
  False before the load; unit-pinned with a scripted always-failing ping.
  Live `backup verify` re-run green after the change.
- **N1** *fixed*: `CARLOS_RECOVERY_PASSPHRASE_FILE` registered in
  `_EXTRA_KNOWN_KEYS` (comment makes the DR-copy keep-the-line side effect
  deliberate; NOT a secret key); pinned in `test_known_keys_do_not_warn`.
- **N2** *fixed*: crash-loop detection now inspects `{{.Id}}
  {{.RestartCount}}` and keeps `id count streak` state — same id keeps the
  rising-count page (legacy single-field state upgraded in place, e2e-pinned
  unchanged), one recreation (a normal `play`/rebuild) is silent, and
  recreations on consecutive sweeps page `container-recreated-<name>`.
  Five new e2e cases pin the state transitions; the podman stub grew a
  combined-format inspect branch ordered before the bare `*RestartCount*`
  match.

## Verified and as-designed (no change requested)

- The role's G1 control-node bcrypt gate: fired on bcrypt 5.0 with a
  precise, actionable message (this pass hit it for real).
- `pma` TTL loss when the CLI parent is SIGKILLed: pass-7 documented
  artifact; this pass additionally proved the designed backstop — `monitor`
  detected the lingering panel and paged the exact break-glass alert.
- `check` rc=1 with dev-topology FAILs; `monitor`'s silent non-tty output;
  `play`/`rollback` provisioning-gate aborts; `rotate db` rc=0 with loud
  restart warnings in the dev topology — all consistent with the documented
  contracts.
- Off-argv credential discipline held everywhere observed live: schema
  load, wait-for-db, `db`/`db-dump`/`db-backup`, backup/restore, rotations
  (verified by inspection of `ps` and the stub-suite's argv recording).

## Sandbox deltas (not repo defects)

Rootful podman (`SERVICE_USER=root`), no systemd PID 1 (unit-driven paths
degrade loudly as designed), cgroup v1, no TPM (`CARLOS_SEAL_NO_TPM=1`
path exercised for real), egress via a TLS-intercepting proxy
(`.extra-ca-bundle.crt` hook exercised in all three builds). The sandbox's
default `python3` (3.11) does not match Ubuntu 24.04's packaged 3.12, so
distro `python3-bcrypt`/`python3-cffi-backend` were unusable against it —
pip-installed equivalents used instead (environment artifact, not a repo
issue; the EL9 floor in `pyproject.toml` is unaffected).
