<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 CARLOS Contributors -->
# carlos-podman — seventh-pass review + live end-to-end test report (2026-08-01)

Scope: full adversarial re-review of `carlos_ctl/`, the Ansible role + all
templates, both Containerfiles, `conf/`, `scripts/dev-setup.sh`, `examples/`,
and the test suites — **plus a fresh live end-to-end exercise** in a
rootful-podman sandbox (podman 4.9.3, Ubuntu 24.04, cgroup v1, no systemd
PID 1, TLS-intercepting egress proxy): real image builds from source,
`podman kube play` of the dev spec against `carlos-emr/carlos@af909f50` +
`drugref2026@101063bb`, the Ontario Flyway schema (427 tables), the app
repo's Playwright login suite, and a systematic drive of the `carlos-ctl`
verb matrix. Everything reported fixed in `REVIEW-2026-08-01.md` (sixth
pass) was treated as baseline; only NEW findings (or verifiably-unfixed
leftovers) are reported here.

## What was executed, and results

- **Repo test suites** (before fixes / after fixes): ruff **1 committed
  I001 error → clean**; mypy clean; `pytest tests/unit` **460 → 464**;
  hermetic e2e `tests/run-tests.sh` **265 → 270**; `tests/ansible-checks.sh`
  fully green (now including a wait-loop unescape pin).
- **Image builds from source, twice each**: (1) direct `podman build` of
  both Containerfiles at a hard `nofile=4096` cap (forked-javac default —
  Maven WAR build succeeded in ~4 min through the sandbox's
  TLS-intercepting proxy via the `.extra-ca-bundle.crt` hook); (2) the full
  **`carlos-ctl build`** path from a role-contract `$EMR_HOME/build` context
  (CA staging via `CARLOS_EXTRA_CA_BUNDLE`, build-then-promote, three-way
  tagging, `:previous` rotation — all verified in `podman images`).
- **Deploy**: `scripts/dev-setup.sh` with a deliberately hostile password
  containing `@ & " \` → `podman kube play` → ON migrations V1…V1.0.6
  (427 tables) → login page 200.
- **Playwright**: the app repo's `scripts/login-playwright-checks.js`
  against `https://127.0.0.1:8443/carlos` — **14/14 checks pass** (browser
  login to provider schedule, forced reset persistence, CSRF rejection,
  weak-password rejection, legacy-route reset guard, old/new password
  behavior).
- **carlos-ctl verb matrix, live**: `status`, `check` (dev-topology FAILs
  as designed), `logs` (all forms), `db` / `db-dump` (427 tables dumped),
  `db-users` (least-priv accounts verified by logging in as `carlos`),
  `db-backup` (refused under the build's mutation lock — lock verified
  live), `backup full` (non-InnoDB refusal rc=1, then allowed run),
  `binlogs`, `docs`, `status`, `verify` (full restore drill), a **real
  destructive `backup restore`** (marker row inserted post-dump survived
  the 4-binlog PITR replay), `rotate db`, `rotate db-root` (hostile new
  password; `db` verified on the rotated credential), `rotate restic`
  (next `backup full` green under the rotated key), `alert-test` +
  `monitor` + `alert <unit>` against a live local webhook (payload receipt
  verified; monitor's local-repo condition fired and relayed), `pma`
  (served phpMyAdmin on :9444 over the DB socket), `build`, `rollback`
  (retag + loud abort at the provisioning gate), `down` (pods stopped and
  removed, rc=0), `enable`, `guard`, `instances`.
- **Refusal matrix**: `--instance <unregistered>`, `uninstall` without
  confirmations, `seal` without sops, `secrets render` without a bundle,
  `cert-renew` in manual mode, `backup restore` without confirmation,
  `db-users` without `drugref2.properties` (rc=1), the per-instance
  mutation lock, `instances --prune` on an empty registry.

## Findings fixed in this pass

**H1. The OnFailure alert throttle was a no-op on every default install.**
`carlos-alert@.service` sets `ProtectSystem=full` (remounts `/usr`
read-only) while the throttle stamps live under the default
`EMR_HOME=/usr/local/emr`; `cmd_alert` suppressed the resulting EROFS, so
the stamp never persisted and every failing 15-minute timer re-paged — the
exact flood the throttle (and the 07-31 H2 fix) exists to prevent. *Fixed*:
`ReadWritePaths={{ carlos_emr_home }}/monitor/state` in the unit, the role
pre-creates the directory, and a stamp-write failure now warns loudly
instead of silently re-flooding.

**M1. The in-pod wait-for-db loop read the java-properties-ESCAPED
db_password raw** (`\` → `\\`), so a backslash-bearing password auth-failed
the loop and **every pod start stalled the full 600 s** before Tomcat
(found live: `logs db` showed the loop's access-denied every 5 s; the app
then started via the fallback and worked, since Java unescapes correctly).
*Fixed* in `carlos-app.yaml.j2` + `examples/carlos-app-dev.yaml` (backslash
halving before `MYSQL_PWD`), pinned by a new ansible-check; *verified
live*: the redeployed pod with the same hostile password served 200 in
**47 s** with zero WARN lines.

**M2. `carlos-ctl setup` emitted YAML-1.1-boolean `ON`** —
`carlos_billing_province: ON` parses as `True`, so the wizard's default
Ontario output failed the role's own province assert with a misleading
message. *Fixed*: every string scalar is now `json.dumps`-quoted; a new
test YAML-loads the emitted file. (The old unit test pinned the broken
emission and never YAML-loaded it.)

**M3. Monitor ack-spelling mismatch caused perpetual false paging.**
`ALERT_JOURNAL_ONLY` / `CARLOS_ACCEPT_LOCAL_REPO` were compared `== "1"`
in the monitor while `play`'s gates accept `true/yes/on` via `flag()` — an
operator using a documented spelling passed go-live, then every 15-minute
sweep failed and pinged `HEARTBEAT_URL/fail` forever. *Fixed*: both sites
use `flag()`.

**M4. Crash-recovery credential convergence never restarted the app.**
The `.db-provision-incomplete` marker path re-provisioned (minting fresh
passwords) but skipped `restart_app_and_waf`, leaving the running app on a
password the DB no longer accepts — a green deploy that degrades as the
pool recycles. *Fixed*: the convergence path now bounces app+WAF like every
other provisioning path.

**M5. The PITR engine audit covered only `oscar`/`drugref2`** while the
dump is `--all-databases` and the restore replays every non-system schema —
a MyISAM/Aria table in any other schema (e.g. a populated legacy `test`
schema, which provisioning deliberately preserves) broke the consistency
contract while the audit read green. *Fixed*: audit inverted to
`NOT IN (<system schemas>)`.

**M6. The restic lost-mount sentinel lived on the volume it guards.**
`backup/.restic-repo-initialized` sits inside `$EMR_HOME/backup` — the tree
operators are told to put on its own LUKS volume; an unmounted backup
volume took the sentinel with it and `ensure_repo` silently `restic init`ed
a fresh empty repo over the bare mountpoint (freshness monitor stays
green). *Fixed*: sentinel moved to `conf/restic/` (root volume) with the
legacy location still honored; 2 new e2e tests pin the lost-mount refusal.

**M7. `--instance` pinned EMR_HOME but not the instance identity.** With
the selected home's env file missing (the unmounted-volume incident
`--instance` exists for), `INSTANCE` silently defaulted to `carlos` and
verbs targeted the wrong instance's pods/units/nft tables. *Fixed*: the
selector now pins `INSTANCE` from the registry entry (authoritative; warns
on a stale env-file mismatch); 3 new unit tests.

**M8. `CARLOS_ACCEPT_EMPTY_DATADIR`'s guard marker was a standing,
unbounded acceptance** — it survived after the datadir initialized, until
the *next* no-flag play (possibly months later), re-opening the
silent-blank-database hole at any reboot in between. *Fixed*: a successful
accepting `play` consumes the marker once the datadir is verifiably
initialized; e2e-pinned.

**M9. Shared-engine image contamination had no guard.** Two instances
sharing a service user share one image store; divergent
`carlos_image`/`carlos_ref` between them meant one instance's `build`
silently retagged what the other deploys, and destroyed its rollback
target. *Fixed*: a cross-instance assert requires same-engine siblings to
agree on the image identity (or isolate via per-instance service users).

**M10. Boolean truthiness was inconsistent across the role.** An
INI-inventory `carlos_obs_enabled=false` (string, truthy in raw Jinja)
produced a split-brain render: task-level `| bool` gates OFF while the pod
templates/env render treated it ON — the next `play` fails on a
non-existent secret, with `OBS_ENABLED=1` in the env. Worse,
`carlos_allow_nft_failure=false` / `carlos_allow_any_bind=false` on a host
line silently GRANTED those fail-open opt-outs. *Fixed*: `| bool` at every
raw site (pod-spec/quadlet loops, `carlos-app.env.j2`, `carlos-app.yaml.j2`
obs gates, both opt-out asserts, `HL7_A04_GENERATION`).

**M11. `cli.yml` copied `__pycache__` then deleted it** — every run
re-uploaded and re-deleted it, so the play never converged and the
documented `--check --diff` drift review was permanently dirty on any
control node that had run pytest. *Fixed*: per-file `*.py` fileglob copy
(the package is flat); the cache-delete task retained for upgrades.

**M12. The db-root-password assert rejected only newline** while the CLI
validator also rejects CR/C0 — a Windows-pasted `pw\r` passed the role and
then corrupted three credential stores three different ways (Java
Properties truncates at CR; the bootstrap secret hashes the full value;
`parse_env_file` splits the rendered line). *Fixed*: assert now rejects all
control characters, matching the CLI.

**Lower-severity fixes** (all verified before fixing):

- The local-repo DR gates keyed on `startswith("/")` — `local:/path` (the
  spelling restic's docs use) and relative paths bypassed the go-live
  refusal, the monitor nag, and the mount plumbing. A shared
  `restic_local_path()` helper now feeds all ten sites (gates, posture
  marker, mount/exists/mountpoint checks, rotate-restic).
- `parse_env_file` corrupted an ANSI-C `$'...'` value carrying an inline
  comment — the exact form the role renders for non-shell-safe root
  passwords — returning the whole line backslash-stripped with no warning.
  Now decodes the quoted token and warns on non-comment trailers.
- A persisted `CARLOS_RESTORE_CONFIRMED=<instance>` line pre-confirmed
  every future restore silently; now warned value-agnostically.
- Binlog ship: a server-side rotation between the index read and restic's
  walk could capture a torn copy of the new active binlog; the exclusion
  now covers everything at/after the active sequence (numeric compare —
  lexical breaks at the 6→7 digit rollover).
- `_check_liveness` conflated "podman ps failed" with "every container
  down" (a 12-alert storm with the real stderr discarded); now a single
  rc-aware `tool-failed-podman-ps` fault alert, and the pod-unit bridge
  (split into `_pod_unit_bridge`) still runs.
- `cmd_enable` swallowed every systemctl failure and printed success —
  after `down --disable`, a broken user manager meant the EMR silently did
  not return at the next boot. Now rc-checked, loud, nonzero (verified
  live: rc=1 with the failed timer list in this sandbox).
- `cert-renew` installed the pair via two non-atomic writes keyed by a
  fullchain-only "not due" hash — a crash between them left a permanently
  mismatched chain/key that no later run repaired. Now staged +
  `os.replace()`, key first (a partial install re-reads as "due").
- `tlsops` carried an unreachable half-pair branch encoding a WEAKER
  contract (warn-and-continue) than the live hard refusal; removed.
- `dev-setup.sh`: a password containing `{#` flipped the Jinja
  comment-strip state and silently swallowed the `db_password` line; the
  strip now runs before substitution and every remaining token is
  validated against the known-value map pre-substitution (verified with a
  `{#`/`{{`-bearing password).
- `setup` interactive vaulting prompts twice for a NEW vault password (two
  `encrypt_string` runs); a note now warns the same password must be
  entered both times.
- Subuid grant: the flock protected the write but the decide happened on a
  pre-grant slurp, so a fresh machine with two same-host instances
  double-allocated ranges; the grant now re-checks inside the lock (and
  `changed_when` is output-keyed).
- Role TLS staging: "fullchain present, privkey missing" produced no
  generation and no warning; a half-pair warning task added.
- Tomcat keystore/truststore passwords rendered into carlos.properties
  unescaped (backslash forms crash `Properties.load`); now escaped like
  `db_password`.
- `scrape.yml.j2` rendered the obs username as an unquoted YAML scalar
  (a `: `-bearing value the charset assert permits would crash-loop
  vmagent); now `to_json`-quoted.
- `restic.env.j2`'s sample `BACKUP_KEEP_BINLOG=--keep-within 7d`
  contradicted the code's 9d anchor-margin default; aligned.
- **07-31 L8 leftover (still present, now fixed)**: the restore drill's
  `.verify-doc.<pid>` plaintext patient document matched no orphan-reap
  glob, and a SIGKILLed drill's `<instance>-verify-<pid>` throwaway
  MariaDB (full PHI copy) had no sweep; both are now PID-precise reaped in
  `_reap_orphaned_stagings`.
- **07-31 L6 leftover (still present, now fixed)**: the secrets unit's
  `ExecStopPost` swept `/run/age.*` instance-agnostically, deleting a
  sibling instance's in-flight decrypted key; tempfile prefixes and the
  sweep are now instance-scoped.
- `tests/unit/test_backup.py` carried a committed ruff I001 error.

## Findings verified and REJECTED / as-designed

- `pma`'s container surviving my killed CLI parent — artifact of signaling
  only the Python process from outside; a real Ctrl-C signals the process
  group (and the monitor alerts on a lingering panel). TTL behavior was
  verified in the sixth pass.
- `rollback`'s retag-before-gate ordering, `monitor`'s silent non-tty
  output, `check`'s dev-topology FAILs, `db-dump`'s dump-to-stdout
  contract — all documented as designed.
- `rotate db`'s rc=0 with restart warnings in the dev topology (no
  rendered production specs) — degradation is loud and the rotation itself
  completed; consistent with the documented contract.

## Sandbox deltas (not repo defects)

Rootful podman (`SERVICE_USER=root`), no systemd PID 1 (quadlet/timer
paths degrade loudly as designed; `enable`'s new failure path exercised
for real), cgroup v1, no TPM, egress via a TLS-intercepting proxy
(`.extra-ca-bundle.crt` hook exercised in both build paths), nofile hard
cap 4096 (the forked-javac default fit comfortably).
