<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 CARLOS Contributors -->
# Quick start — a CARLOS pod for development and testing

> **Status: early access.** carlos-podman is under active development and is
> currently intended for **testing and development use**. This walk-through
> deploys the CARLOS EMR with **synthetic/development data only** — do not
> point it at real patient data (PHI). For the full provisioning path
> (WAF, backups, monitoring, secrets sealing) that production rollouts will
> use once the project leaves early access, see the
> [README Quick start](README.md#quick-start).

This is the shortest **verified** path from a clean Linux host to a running,
browser-accessible CARLOS pod under **rootless podman**: one pod containing
MariaDB and the CARLOS Tomcat, built from the app's `develop` branch with
this repo's `Containerfile`, deployed with `podman kube play` from
[`examples/carlos-app-dev.yaml`](examples/carlos-app-dev.yaml).

**Verification record.** This exact sequence was last exercised end-to-end on
2026-07-31 against `carlos-emr/carlos` `develop@2cf46689` with rootless
podman 4.9.3 (native overlay, kernel 6.18), MariaDB 11.4.12, and the app
repo's Playwright login suite (`scripts/login-playwright-checks.js`):
14/14 checks passed, including browser login to the provider schedule,
forced password reset, and CSRF rejection. Re-verify after any podman major
bump or when tracking a newer `develop`. The `scripts/dev-setup.sh` scripted
path (steps 2-3) was verified the same day against the same commit: fresh
instance dir → script → `kube play` → schema load → login page serving 200
(rootful-podman sandbox). Re-verified 2026-08-01 against `develop@af909f50`
(rootful podman 4.9.3, forked-javac Containerfile at a 4096 nofile cap,
`dev-setup.sh` → `kube play` → ON migrations → Playwright 14/14 — twice,
the second pass after a full PITR restore and credential rotations); see
`REVIEW-2026-08-01.md`. Re-verified again the same day in a seventh pass
(fresh sandbox, cgroup v1: builds via both the raw Containerfile path and
`carlos-ctl build`, deploy with a `@ & " \`-bearing password, ON
migrations, Playwright 14/14, destructive PITR restore, rotations, and the
wait-for-db backslash fix proven live — app up in 47 s where it previously
stalled 600 s); see `REVIEW-2026-08-01-pass7.md`.

## 0. Host prerequisites

A Linux host with podman ≥ 4.9 configured for rootless operation, running as
a dedicated non-root user:

```bash
# Debian/Ubuntu package set (Fedora/RHEL ship these with podman):
sudo apt install podman uidmap slirp4netns passt fuse-overlayfs

# The service user needs subuid/subgid ranges (usually created by useradd):
grep "$USER" /etc/subuid /etc/subgid
```

Check these before building — each one below bit during verification:

- **A subuid/subgid range at least 65536 wide.** The third field of each
  grant is the count, and it must be at least `65534`: the mysqld-exporter runs as
  container uid 65534, and `apt-get` drops to it *inside the image builds*.
  A narrower range makes `chown(2)` fail with `EINVAL` on an unmapped id —
  surfacing as `setgroups 65534 failed - setgroups (22: Invalid argument)`
  tens of minutes into the runtime stage of `podman build` (verified live),
  and as silently-missing MariaDB metrics on a deployed instance. Rootless
  podman builds its map from the **first** grant only, so *appending* a
  second range does not widen it — widen the existing one and re-run
  `podman system migrate` as the service user:

  ```bash
  sudo usermod --del-subuids <old-range> --add-subuids <base>-$((base+65535)) "$USER"
  sudo usermod --del-subgids <old-range> --add-subgids <base>-$((base+65535)) "$USER"
  podman system migrate
  ```

  `carlos-ctl build` and `carlos-ctl play` warn about a too-narrow grant, and
  the Ansible role asserts it.

- **Native overlay storage.** `podman info | grep -A3 graphDriverName` must
  show `overlay` (with `Native Overlay Diff: true` on kernel ≥ 5.13). A
  `vfs` fallback makes builds and container I/O painfully slow.
- **File-descriptor limit.** The Maven build and the runtime both exceed the
  common soft default of 1024. Raise the user's hard limit (e.g.
  `nofile 65536` in `/etc/security/limits.d/carlos.conf`, or systemd user
  `LimitNOFILE`); the build command below passes `--ulimit` explicitly, and
  `carlos-ctl build` does the same (capped at the service user's hard
  limit). **4096 is the verified floor** for the current Containerfile,
  whose forked javac (`-Dmaven.compiler.fork=true`, the default since
  2026-08-01) splits the compile's FD load across two processes — the older
  in-process compile died at exactly 4096 mid-build. `65536` remains the
  recommended headroom; `carlos-ctl build` warns below 4096.
- **/dev/net/tun** must be usable by the rootless user (mode `0666` is the
  usual distro default) or slirp4netns/pasta cannot start.
- **cgroup v2 + systemd delegation** if you want pod resource limits to
  actually apply; without them podman silently runs unlimited (the dev spec
  omits limits for exactly that reason). Ubuntu 24.04+ boots cgroup v2 by
  default — verify with `podman info --format '{{.Host.CgroupsVersion}}'`.
  Ubuntu's systemd delegates only `memory` and `pids` to user sessions out
  of the box; for cpu/io limits under rootless podman add a drop-in and
  re-login:

  ```
  # /etc/systemd/system/user@.service.d/delegate.conf
  [Service]
  Delegate=cpu cpuset io memory pids
  ```
- **Lingering** (`sudo loginctl enable-linger <user>`) if the pod should
  survive logout.

## 1. Build the CARLOS image

Pin the build to a commit SHA of
[`carlos-emr/carlos`](https://github.com/carlos-emr/carlos) — `develop`
moves, and the `ADD <url>` layer caches on the URL string (see the
reproducibility note in the `Containerfile`):

```bash
git clone https://github.com/yingbull/carlos-podman && cd carlos-podman
CARLOS_SHA=$(git ls-remote https://github.com/carlos-emr/carlos develop | cut -f1)
podman build --no-cache --ulimit nofile=65536:65536 \
  --build-arg CARLOS_REF=$CARLOS_SHA \
  -t localhost/carlos-app:latest -f Containerfile .
```

The first build downloads the full Maven dependency tree (~15–30 min);
rebuilds reuse the `/root/.m2` cache mount.

## 2. Lay out the instance directory and config

> **Helper script.** [`scripts/dev-setup.sh`](scripts/dev-setup.sh)
> automates all of step 2 and step 3 — directory layout, verbatim conf
> copies, the `carlos.properties` render (with the render-safety greps), and
> the pod-spec render with the password hash — while keeping the password
> off argv (terminal prompt, or `CARLOS_DEV_DB_PASSWORD` for unattended
> runs):
>
> ```bash
> scripts/dev-setup.sh                  # defaults: $HOME/emr, Ontario
> scripts/dev-setup.sh --emr-home /srv/emr --province BC
> ```
>
> Then continue at step 3's `podman kube play` line (the script prints the
> exact next commands). The manual commands below remain the documented
> reference for what the script does — read them at least once so you know
> what is on disk.

```bash
export EMR_HOME=$HOME/emr
mkdir -p $EMR_HOME/container/conf/{tomcat,carlos,mariadb} \
         $EMR_HOME/container/guard \
         $EMR_HOME/data/{mariadb-mnt,mariadb-binlog,OscarDocument/oscar/document} \
         $EMR_HOME/logs/carlos $EMR_HOME/backup/mariadb-hot \
         $EMR_HOME/run/{db-socket,app-secrets}

cp conf/tomcat/server.xml conf/tomcat/context.xml conf/tomcat/logging.properties \
   $EMR_HOME/container/conf/tomcat/
cp conf/mariadb/zz-carlos.cnf $EMR_HOME/container/conf/mariadb/
```

Render `carlos.properties` from the role template. Outside Ansible the
handful of Jinja placeholders can be filled with `sed` — pick a MariaDB root
password and generate the **required** app encryption key first:

> `scripts/dev-setup.sh` (the helper above) does this whole render in-process
> with `python3` — no charset restriction, and the password never touches
> argv. The manual `sed` path below is the documented reference; it has the
> escaping limits called out in the comments. Prefer the helper for real use.

```bash
DB_PW='choose-a-dev-password'          # dev instance only — no PHI; avoid '@',
                                       # '\' and '&' (the sed below uses @ as
                                       # its delimiter and expands '&' in the
                                       # replacement; Ansible — and the
                                       # dev-setup.sh helper — handle escaping
                                       # for you). The password is also visible
                                       # in `ps` for the duration of the sed
                                       # command (argv); the helper avoids that.
                                       # NOTE: assignments land in shell
                                       # history — fine for a throwaway dev
                                       # password, never do this with a real
                                       # credential (the production path
                                       # vaults it via carlos-ctl setup).
ENC_KEY=$(openssl rand -base64 32)     # REQUIRED: develop refuses first boot without it

umask 077   # the rendered file carries the db password + key from first write
sed -e "s@{{ carlos_jdbc_zero_date | default('round', true) }}@round@" \
    -e "s@{{ carlos_db_root_password | replace('\\\\\\\\', '\\\\\\\\\\\\\\\\') }}@$DB_PW@" \
    -e "s@{{ carlos_encryption_secret_key }}@$ENC_KEY@" \
    -e "s@{{ carlos_rx_allergy_checking | default('no', true) }}@no@" \
    -e "s@{{ carlos_billing_province | default('ON', true) }}@ON@" \
    -e "s@{{ carlos_server_name }}@localhost@" \
    -e "s@{{ carlos_pin_encrypted_effective | default('no', true) }}@no@" \
    -e "s@{{ carlos_tomcat_keystore_password | replace('\\\\\\\\', '\\\\\\\\\\\\\\\\') }}@changeit@" \
    -e "s@{{ carlos_tomcat_truststore_password | replace('\\\\\\\\', '\\\\\\\\\\\\\\\\') }}@changeit@" \
    -e "s@{{ carlos_hl7_a04_dir | default('/var/lib/adt/', true) }}@/var/lib/adt/@" \
    -e "s@{{ 'true' if carlos_hl7_a04_generation | default(false) | bool else 'false' }}@false@" \
    -e "s@{{ carlos_eform_pdf_browser_startup_check | default('off', true) }}@off@" \
    -e "s@{{ carlos_eform_pdf_browser_chromium_path | default('', true) }}@@" \
    -e "s@{{ carlos_eform_pdf_browser_chromedriver_path | default('', true) }}@@" \
    -e "s@{{ carlos_buildtag | default('carlos-podman', true) }}@carlos-podman@" \
    -e '/{#/,/#}/d' -e '/^##/d' \
    ansible/roles/carlos_podman/templates/carlos.properties.j2 \
    > $EMR_HOME/container/conf/carlos/carlos.properties
chmod 600 $EMR_HOME/container/conf/carlos/carlos.properties

# No unrendered Jinja may remain, and the required key must be non-blank
# (an empty $ENC_KEY would render `encryption.util.secret.key=` — boot-fatal,
# and the playbook's additive migration won't fix a present blank line):
! grep -E '\{\{|\{%' $EMR_HOME/container/conf/carlos/carlos.properties
grep -Eq '^encryption\.util\.secret\.key=.+' $EMR_HOME/container/conf/carlos/carlos.properties
```

(BC instead of Ontario: use `|BC|` for the billing province, and load the
`bc/` migrations in step 4.)

## 3. Deploy the pod

The pod spec consumes the MariaDB root password as a
`mysql_native_password` **hash** in a kube Secret (never a plaintext env
var):

```bash
# stdin, not argv: command arguments are visible to every local user in `ps`
DB_HASH=$(printf '%s' "$DB_PW" | python3 -c "import hashlib,sys; \
  print('*'+hashlib.sha1(hashlib.sha1(sys.stdin.buffer.read()).digest()).hexdigest().upper())")
DB_HASH_B64=$(printf '%s' "$DB_HASH" | base64 -w0)

sed -e "s|__EMR_HOME__|$EMR_HOME|g" \
    -e "s|__DB_ROOT_HASH_B64__|$DB_HASH_B64|" \
    examples/carlos-app-dev.yaml > $EMR_HOME/carlos-app-dev.yaml
chmod 600 $EMR_HOME/carlos-app-dev.yaml   # carries the crackable root-pw hash

podman kube play $EMR_HOME/carlos-app-dev.yaml
podman ps --pod   # db + carlos containers, 8443 published on 127.0.0.1
```

First boot initializes the MariaDB datadir, then Tomcat deploys the
pre-exploded WAR (a few minutes; the startup probe allows up to 20). The
carlos container **waits for the `oscar` database to be queryable** before
starting Tomcat (up to 600 s), so on a fresh install it sits waiting until you
load the schema in step 4 — that is expected, not a hang. If the schema is
loaded *later* than that 600 s window, the webapp comes up on an empty
database and serves 404; `podman restart carlos-app-carlos` (or a fresh `kube
play`) re-runs the wait and it recovers.

## 4. Load the schema (fresh install, once)

MariaDB binds pod-loopback only — reach it with `podman exec` (or the unix
socket at `$EMR_HOME/run/db-socket/mysqld.sock`). From a
`carlos-emr/carlos` checkout, apply the Flyway migration files in version
order, common and province interleaved (Ontario shown):

The password rides `MYSQL_PWD`, set inside the container from the first line
of stdin — never `-p"$DB_PW"` on the argv (which host-side `ps` shows for the
whole minutes-long load, and never in the container's argv either — the same
off-argv rule step 3's hashing follows):

```bash
# stdin line 1 = password (consumed by `read`), the rest = SQL for mariadb
podman exec -i carlos-app-db bash -c \
  'read -r p; export MYSQL_PWD="$p"; mariadb -uroot \
   -e "CREATE DATABASE IF NOT EXISTS oscar DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci"' \
  <<<"$DB_PW"

cd /path/to/carlos/database/mysql/migration
for f in common/V1__baseline_schema.sql on/V1.0.1__on_schema.sql \
         on/V1.0.2__on_data.sql common/V1.0.3__performance_indexes.sql \
         on/V1.0.4__on_performance_indexes.sql \
         common/V1.0.5__restore_live_legacy_common_tables.sql \
         on/V1.0.6__restore_reporting_privilege.sql; do
  { printf '%s\n' "$DB_PW"; cat "$f"; } \
    | podman exec -i carlos-app-db bash -c 'read -r p; export MYSQL_PWD="$p"; mariadb -uroot oscar'
done
```

Newer upstream migrations continue the `V1.0.N` sequence — check
`database/mysql/migration/README.md` in the app repo for the current list.

## 5. Log in

Browse to `https://127.0.0.1:8443/` (the in-pod TLS cert is self-signed —
accept the browser warning; production fronts this with the WAF pod and real
certificates). The `/` root redirects to `/carlos/`, the login page. Two
fresh-install cosmetics are expected: the clinic-logo box above the login
fields is empty until a logo is configured (Administration, or the
logo-file properties), and hitting the legacy `/carlos/index.jsp` URL
directly lands on the plainer `/carlos/logoutPage` variant rather than the
styled login — use `/carlos/`. The Ontario dev dataset seeds one
**development-only** account: username `carlosdoc`, password `carlos2026`,
PIN `2026`. First login forces a password change — **do that login yourself,
immediately after the schema load**, and treat re-crediting the seed account
as part of this step, not an afterthought: the 8443 publish is pinned to
127.0.0.1, but loopback is shared by **every local user** on the host, and
whoever logs in first completes the forced reset and owns the instance. Run
this quick start on a single-user workstation only — on a shared host, skip
the hostPort and reach the app via `podman exec` instead. Note also that in
this WAF-less dev topology the app cannot attribute client IPs: rootless
port forwarding rewrites the source address, and when the rewritten source
lands in 10/8 it matches `server.xml`'s RemoteIpValve trust, so a
client-supplied `X-Forwarded-For` header is recorded as the client IP — the
access log can contain deliberately forged addresses, not just
unattributable ones.

Headless check:

```bash
curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:8443/carlos/   # → 200
```

For a browser-level regression pass, the app repo ships a Playwright suite
that exercises login, failed login, forced reset, and CSRF handling —
`scripts/login-playwright-checks.js` (see its header for the required
environment; point `BASE_URL` at `https://127.0.0.1:8443/carlos`). Two
caveats against this WAF-less, self-signed dev endpoint: (1) current
`develop` already passes `ignoreHTTPSErrors: true` in every
`request.newContext()` call (verified 2026-08-01), so the in-pod self-signed
cert needs no suite changes — only older checkouts needed patching; and
(2) the `mariadb`/`mysql` client ignores `MYSQL_UNIX_PORT`, so its DB calls
must reach the pod socket another way — no TCP port is published. Symlink
the pod socket to the client's default path (needs root; skip if a host
MariaDB already owns that path, and use `podman exec` instead):

```bash
sudo mkdir -p /var/run/mysqld
sudo ln -sf $EMR_HOME/run/db-socket/mysqld.sock /var/run/mysqld/mysqld.sock
```

Then run the suite with `MYSQL_HOST=localhost` (the client picks the unix
socket for `localhost`), `BASE_URL=https://127.0.0.1:8443/carlos`,
`CHROME_PATH` pointing at a system Chromium if Playwright's own download is
unavailable, and the seeded-account env from the script header.

Two things bite when the db password contains a backslash — which
`dev-setup.sh` accepts, and which the hermetic suite deliberately tests:

- **`MYSQL_PASSWORD` must be option-file-escaped for the suite.** The app
  repo's `login-playwright-checks.js` writes `password=$MYSQL_PASSWORD`
  verbatim into a MariaDB `--defaults-extra-file`, where a backslash is an
  escape — an unescaped `a\rd` is read back as `a<CR>d` and every DB call in
  the suite fails with `Access denied`. Double the backslashes in the value
  you export (`'dev@P4ss & "w\\rd'` for the password `dev@P4ss & "w\rd`)
  until the suite escapes it itself. `carlos-ctl` renders its own copies of
  this password correctly (`properties_escape_value`); this is only about the
  suite's env input.
- **The same rule applies to hand-written SQL.** `ALTER USER … IDENTIFIED BY
  '…'` treats a backslash as an escape too, so a copy-pasted password with
  `\r` in it silently sets a CR-bearing credential. Use
  `carlos_ctl.util.sql_escape` (or double the backslashes) when scripting
  password changes by hand.

Do **not** put `${` or `#{` in the db password: Spring re-interpolates the
value it reads from `carlos.properties`, so those sequences are evaluated as
a placeholder/SpEL expression and the webapp context fails to start (with a
fragment of the password echoed into the app log). `dev-setup.sh` and
`carlos-ctl` now refuse such passwords up front.

## Teardown / persistence

```bash
podman kube down $EMR_HOME/carlos-app-dev.yaml   # stops and removes the pod
```

The database datadir, binlogs, documents, and logs persist under
`$EMR_HOME/data` and `$EMR_HOME/logs` across `kube down`/`play` cycles.
Delete `$EMR_HOME` to start over.

Two lifecycle gotchas on a persistent instance: the root-password hash in
the Secret is consulted **only when the datadir is empty** — re-rendering
the YAML with a new password and replaying does *not* rotate the live DB
credential (rotate interactively — `podman exec -it carlos-app-db mariadb
-uroot -p`, then type `SET PASSWORD = PASSWORD('...');` at the SQL prompt,
which keeps both old and new passwords off argv and out of shell history —
then re-render so the next fresh install matches). And depending on podman version the `carlos-db-secret` podman
secret may outlive `kube down` — `podman secret rm carlos-db-secret` after
teardown clears the stale hash from the secret store.

## Troubleshooting (all hit during verification)

| Symptom | Cause / fix |
| --- | --- |
| Maven build dies with `Too many open files` | Rootless build inherited a 1024 nofile soft limit — pass `--ulimit nofile=...` (≤ the user's hard limit) and raise the host limit. |
| Build dies in the runtime stage: `apt` prints `setgroups 65534 failed - setgroups (22: Invalid argument)` | The service user's subuid/subgid range is narrower than 65535, so container id 65534 (apt's `_apt`/`nogroup`) is not in the userns map. Widen the **first** grant to 65536 and `podman system migrate` — see step 0. |
| Build fails: `cannot access <package>` across the whole tree | Same nofile problem surfacing inside javac — see above. |
| `slirp4netns failed: open("/dev/net/tun"): Permission denied` | Device not usable by the rootless user — `sudo chmod 0666 /dev/net/tun` (or udev rule). |
| db crash-loops: `Can't create/write to file '/tmp/ib...' (Errcode: 13)` | podman 4.9 kube play's read-only-root auto-tmpfs shadowed the `/tmp` emptyDir. The dev spec already routes MariaDB at `--tmpdir=/db-tmp`; keep that pattern for any container that must write a volume mounted exactly at `/tmp`. |
| App 404s forever; log shows `Unable to generate and persist a new encryption key at startup` | `encryption.util.secret.key` missing/blank in `carlos.properties` — the app tries to generate and persist one, and the config mount is read-only. Set the key (step 2). |
| Build fails in `buildnumber-maven-plugin`: `not a git repository` | You are building from a source tarball with an older `Containerfile` — this repo's current one synthesizes the git metadata the plugin needs. |
| Build fails: `Invalid project.build.outputTimestamp value ''` | Empty-but-set `SOURCE_DATE_EPOCH` reaching Maven — fixed in the current `Containerfile` (unset when no real epoch is passed). |
| Pod resource `limits` seem ignored | Rootless limits require cgroup v2 with systemd delegation; without them podman runs the containers unlimited. |
| `kube play` fails on its first volume: `Error: statfs …/carlos.properties: permission denied` | A shared parent under `$EMR_HOME` (`container/conf/`, `data/`, `logs/`, `metrics/`) is root-owned and not traversable by the service user. The role now declares those parents explicitly — re-run the playbook, or check with `namei -l`. |
| `carlos-obs-logcollect` restarts forever: `Missing environment variable in config. name = "…"` | vector env-interpolates its config text — **comments included** — before parsing. Double any literal `$` in `conf/vector/journald-collector.toml` (`$$`). |
| No metrics at all; `carlos-app-vmagent` keeps exiting with no `podman logs` output | vmagent hard-fails on an invalid `conf/vmagent/scrape.yml` (and the app pod's journald log driver hides it). Parse the file: `python3 -c 'import yaml,sys;yaml.safe_load(open(sys.argv[1]))' $EMR_HOME/container/conf/vmagent/scrape.yml`. |
| `carlos-ctl play` never greens; drugref probe fails, `/drugref2/` is 404 | DrugRef's Hibernate dialect auto-detect fails on MariaDB (mysql-connector-j 9.x reads `INFORMATION_SCHEMA.KEYWORDS.RESERVED`, absent in MariaDB). The pod spec and image pass `-Dhibernate.dialect=org.hibernate.dialect.MariaDBDialect` and `-Dhibernate.boot.allow_jdbc_metadata_access=false`; re-run the playbook / rebuild. |
