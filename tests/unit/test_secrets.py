# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Unit tests for the secrets subsystem and alert dispatcher."""

import builtins
import errno
import os
import subprocess
from pathlib import Path

import pytest

from carlos_ctl import alert
from carlos_ctl.config import parse_env_file
from carlos_ctl.secrets import (
    _SECRETS_UNIT_TEMPLATE,
    _bundle_recipients,
    _rotate_age_key,
    _rotate_caddy_password,
    _rotate_db_root,
    _rotate_obs_http,
    cmd_rotate,
    percent_q,
    preflight_reseal,
    reap_credential_dropfiles,
    validate_db_password,
)
from carlos_ctl.util import CtlError


class TestPreflightReseal:
    def _sealed(self, r) -> None:
        b = r.settings.secrets_bundle
        b.parent.mkdir(parents=True, exist_ok=True)
        b.write_text("sops: {}\n")

    def test_unsealed_install_passes(self, mk_runner) -> None:
        preflight_reseal(mk_runner())  # no bundle -> nothing to re-seal

    def test_sealed_no_tpm_refuses_before_mutation(self, mk_runner) -> None:
        # Discovering the no-TPM seal refusal AFTER the DB was re-passworded
        # strands a stale bundle that re-materializes OLD creds at boot.
        r = mk_runner()
        self._sealed(r)
        # seal toolchain present, but no systemd-creds -> no TPM
        r.tools = {"systemctl", "podman", "sops", "age", "age-keygen"}
        with pytest.raises(CtlError, match="CARLOS_SEAL_NO_TPM"):
            preflight_reseal(r)

    def test_sealed_missing_seal_tool_refuses(self, mk_runner) -> None:
        # cmd_seal hard-fails on a missing sops/age — that refusal must also
        # fire before the mutation, not after.
        r = mk_runner("", {"CARLOS_SEAL_NO_TPM": "1"})
        self._sealed(r)
        r.tools = {"systemctl", "podman", "age", "age-keygen"}  # no sops
        with pytest.raises(CtlError, match="sops"):
            preflight_reseal(r)

    def test_sealed_no_tpm_with_ack_passes(self, mk_runner) -> None:
        r = mk_runner("", {"CARLOS_SEAL_NO_TPM": "1"})
        self._sealed(r)
        r.tools = {"systemctl", "podman", "sops", "age", "age-keygen"}
        preflight_reseal(r)

    def test_sealed_with_tpm_passes(self, mk_runner) -> None:
        r = mk_runner()
        self._sealed(r)
        r.tools = {"systemd-creds", "sops", "age", "age-keygen"}
        r.script("systemd-creds", "has-tpm2", rc=0)
        preflight_reseal(r)


class TestRotateDbRoot:
    def test_failed_secret_recreate_does_not_strand_the_new_password(
        self, mk_runner
    ) -> None:
        # ALTER USER has already run and the OLD podman secret was already
        # removed when `kube play -` fails — aborting there would leave a
        # root password that exists NOWHERE (not persisted, not emitted).
        # The rotation must warn and continue to the persistence steps.
        r = mk_runner(
            "CARLOS_DB_ROOT_PASSWORD=oldpw\n",
            {"CARLOS_DB_NEW_ROOT_PASSWORD": "newpw-1234"},
        )
        s = r.settings
        r.script("podman", "ps", rc=0, out=f"{s.app_pod}-db\n")
        r.script("podman", "kube", "play", rc=1)  # secret re-create fails
        assert _rotate_db_root(r) == 0  # no CtlError escapes
        # The env file (which HELD a stored root password) was updated.
        assert "CARLOS_DB_ROOT_PASSWORD=newpw-1234" in s.env_file.read_text()

    def test_unready_db_refuses_before_the_alter(self, mk_runner) -> None:
        # `rotate db` restarts the app pod, so the documented back-to-back
        # rotation reached a db that was Up (podman ps) but not yet accepting.
        # The ALTER's generic failure used to be reported as "is the current
        # CARLOS_DB_ROOT_PASSWORD correct?" — a wrong diagnosis. Refuse with
        # the real cause, and mutate nothing.
        r = mk_runner("CARLOS_DB_ROOT_PASSWORD=oldpw\n",
                      {"CARLOS_DB_READY_SECONDS": "0"})
        s = r.settings
        r.script("podman", "ps", rc=0, out=f"{s.app_pod}-db\n")
        r.script("podman", "exec", rc=1, out="")
        with pytest.raises(CtlError) as e:
            _rotate_db_root(r)
        assert "not accepting root connections" in str(e.value)
        assert "nothing was changed" in str(e.value)
        assert not any("ALTER USER" in t for t in r.stdins)
        assert "CARLOS_DB_ROOT_PASSWORD=oldpw" in s.env_file.read_text()

    def test_root_alter_is_not_binlogged(self, mk_runner) -> None:
        # The root ALTER USER must run under sql_log_bin=0, or a windowed PITR
        # restore replays it and rewinds root to a stale generation — a root
        # lockout (ninth-pass finding). The SQL rides input_text (off-argv).
        r = mk_runner(
            "CARLOS_DB_ROOT_PASSWORD=oldpw\n",
            {"CARLOS_DB_NEW_ROOT_PASSWORD": "newpw-1234"},
        )
        s = r.settings
        r.script("podman", "ps", rc=0, out=f"{s.app_pod}-db\n")
        _rotate_db_root(r)
        alter = next((t for t in r.stdins if "ALTER USER" in t and "root" in t), "")
        assert alter, "no root ALTER USER statement was sent"
        pre = alter.split("ALTER USER", 1)[0]
        assert "sql_log_bin" in pre.lower() and "= 0" in pre.replace("=0", "= 0")


class TestRotateArgumentContract:
    """Only `rotate db` takes a flag. Every other sub-verb used to accept and
    DROP whatever followed it, so `rotate age-key --dry-run` re-keyed the
    sealed-secrets master for real and `rotate restic --help` re-passworded
    the backup repository — the same silently-dropped-argument class the CLI's
    no_arg_verbs guard and the `backup <tier>` guard already close."""

    @pytest.mark.parametrize("sub", ["db-root", "log-view", "obs", "age-key", "restic"])
    def test_trailing_arguments_are_refused_before_any_mutation(
        self, mk_runner, sub
    ) -> None:
        r = mk_runner("CARLOS_DB_ROOT_PASSWORD=oldpw\n")
        with pytest.raises(CtlError) as e:
            cmd_rotate(r, [sub, "--dry-run"])
        assert "takes no arguments" in str(e.value)
        # Refused BEFORE anything ran: no external command was issued.
        assert r.calls == []

    def test_rotate_db_still_accepts_its_documented_flag(self, mk_runner) -> None:
        # The guard must not break `rotate db --no-restart`; it gets past the
        # argument check and fails later on the real prerequisites instead.
        r = mk_runner("CARLOS_DB_ROOT_PASSWORD=oldpw\n")
        with pytest.raises(CtlError) as e:
            cmd_rotate(r, ["db", "--no-restart"])
        assert "takes no arguments" not in str(e.value)

    def test_unknown_sub_verb_still_prints_usage(self, mk_runner) -> None:
        r = mk_runner("CARLOS_DB_ROOT_PASSWORD=oldpw\n")
        with pytest.raises(CtlError) as e:
            cmd_rotate(r, ["bogus", "--dry-run"])
        assert "usage: carlos-ctl rotate" in str(e.value)


class TestRotateResticValidation:
    """An operator-supplied RESTIC_NEW_PASSWORD renders into the line-oriented
    RESTIC_PASSWORD= store; a newline/CR corrupts it so the stored value stops
    opening the repo. It must be validated BEFORE any mutation (ninth-pass
    finding: the sibling rotations validate, this one did not)."""

    def _restic_env(self, r) -> None:
        env = r.settings.conf_dir / "restic" / "restic.env"
        env.parent.mkdir(parents=True, exist_ok=True)
        env.write_text("RESTIC_REPOSITORY=/repo\nRESTIC_PASSWORD=oldpw\n")

    def test_newline_new_password_refused_before_key_add(self, mk_runner) -> None:
        from carlos_ctl.secrets import _rotate_restic

        r = mk_runner("", {"RESTIC_NEW_PASSWORD": "a\nb"})
        self._restic_env(r)
        with pytest.raises(CtlError):
            _rotate_restic(r)
        # No `restic key add` was issued — the refusal is pre-mutation.
        assert not any("key" in c and "add" in c for c in r.calls)


class TestRotateAgeKey:
    """H1: the re-keyed bundle must never be committed before the NEW private
    key is durable on disk. These drive the real _rotate_age_key with a run()
    that materializes the files age-keygen/sops would produce."""

    PLAIN = "db_password: s3cret\n"
    NEWPUB = "age1newpubabcdefghijklmnopqrstuvwxyz0123456789abcd"

    def _wire(self, mk_runner, *, keygen_writes: bool = True):
        r = mk_runner("", {"CARLOS_SEAL_NO_TPM": "1"})
        s = r.settings
        s.secrets_bundle.parent.mkdir(parents=True, exist_ok=True)
        s.secrets_bundle.write_text("ORIGINAL-BUNDLE-CIPHERTEXT\n")
        s.secrets_private_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        s.age_key_file.write_text("AGE-SECRET-KEY-OLD\n")
        s.age_pub_file.write_text("age1oldpub\n")
        r.tools = {"sops", "age", "age-keygen"}  # NO systemd-creds -> have_tpm False

        orig = r.run

        def emulate(argv, **kw):
            a = list(argv)
            if a[:2] == ["age-keygen", "-o"]:
                if keygen_writes:
                    Path(a[2]).write_text("AGE-SECRET-KEY-NEW\n")
                r.calls.append(a)
                return subprocess.CompletedProcess(a, 0, "", "")
            if a[:2] == ["age-keygen", "-y"]:
                r.calls.append(a)
                return subprocess.CompletedProcess(a, 0, self.NEWPUB + "\n", "")
            if a[:2] == ["sops", "-d"]:
                r.calls.append(a)
                return subprocess.CompletedProcess(a, 0, self.PLAIN, "")
            return orig(a, **kw)

        r.run = emulate  # instance attr shadows the method; output()/ok() use it
        return r, s

    def test_new_key_and_pub_installed_no_stray_siblings(self, mk_runner) -> None:
        r, s = self._wire(mk_runner)
        assert _rotate_age_key(r) == 0
        assert s.age_key_file.read_text() == "AGE-SECRET-KEY-NEW\n"
        assert s.age_pub_file.read_text() == self.NEWPUB + "\n"
        # No half-installed staging siblings survive a successful rotation.
        assert not Path(str(s.age_key_file) + ".new").exists()
        assert not Path(str(s.age_pub_file) + ".new").exists()
        # The bundle was swapped (content changed from the original).
        assert s.secrets_bundle.read_text() != "ORIGINAL-BUNDLE-CIPHERTEXT\n"

    def test_key_sibling_exists_before_bundle_swap(self, mk_runner, monkeypatch) -> None:
        # The ordering guard: at the instant the bundle is swapped in, the new
        # private key must ALREADY be staged durably on disk.
        r, s = self._wire(mk_runner)
        import carlos_ctl.secrets as secmod

        real_replace = os.replace
        seen = {}

        def spy(src, dst, *a, **k):
            if str(dst) == str(s.secrets_bundle):
                seen["key_new_present_at_swap"] = Path(
                    str(s.age_key_file) + ".new"
                ).is_file()
            return real_replace(src, dst, *a, **k)

        monkeypatch.setattr(secmod.os, "replace", spy)
        assert _rotate_age_key(r) == 0
        assert seen.get("key_new_present_at_swap") is True

    def test_keygen_failure_leaves_bundle_untouched(self, mk_runner,
                                                    _hermetic_host_paths) -> None:
        # If the new key never materializes, the persist-before-swap staging
        # fails BEFORE the bundle swap -> the original bundle is intact.
        r, s = self._wire(mk_runner, keygen_writes=False)
        with pytest.raises(OSError):  # new key file never materialized
            _rotate_age_key(r)
        assert s.secrets_bundle.read_text() == "ORIGINAL-BUNDLE-CIPHERTEXT\n"
        # M1: this is exactly the path that leaked /run/rekey-staged.*.yaml
        # live (OSError at key staging, AFTER `staged` exists) — the finally
        # must now have swept every transient rekey file.
        assert not list(_hermetic_host_paths["CARLOS_RUN_DIR"].glob("rekey-*"))


class TestSecretsUnitReap:
    """M4: the boot-time secrets render must actually be able to reap leftover
    .new-* cleartext credential drop-files under EMR_HOME."""

    def test_unit_grants_readwrite_to_secrets_private(self) -> None:
        # ReadOnlyPaths={emr_home} would make the reap a silent EROFS no-op;
        # a nested ReadWritePaths for secrets-private must punch through it.
        rendered = _SECRETS_UNIT_TEMPLATE.format(
            instance="carlos", service_uid=1000, emr_home="/usr/local/emr",
            run_dir="/run/carlos-emr", age_key_file="/usr/local/emr/x",
        )
        assert "ReadWritePaths=-/usr/local/emr/secrets-private" in rendered
        # and it must appear AFTER the ReadOnlyPaths line it overrides.
        assert rendered.index("ReadOnlyPaths=") < rendered.index(
            "ReadWritePaths=-/usr/local/emr/secrets-private")

    def test_reap_warns_and_keeps_file_on_erofs(self, mk_runner, capsys, monkeypatch) -> None:
        r = mk_runner()
        s = r.settings
        s.secrets_private_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        dropf = s.secrets_private_dir / ".new-db-root"
        dropf.write_text("live-cleartext-password\n")

        real_open = builtins.open

        def erofs_open(path, *a, **k):
            if ".new-" in str(path):
                raise OSError(errno.EROFS, "read-only file system")
            return real_open(path, *a, **k)

        monkeypatch.setattr(builtins, "open", erofs_open)
        reap_credential_dropfiles(s)
        monkeypatch.undo()
        assert dropf.is_file()  # NOT silently dropped — still present
        assert "READ-ONLY" in capsys.readouterr().err


class TestPercentQ:
    @pytest.mark.parametrize(
        "raw",
        ["plainvalue", "with space", "pa$s'word", 'dq"uote', "back\\slash",
         "new\nline", "tab\there", "ctrl\x07bell", "utf-éà"],
    )
    def test_roundtrips_through_parse_env_file(self, raw: str) -> None:
        encoded = percent_q(raw)
        parsed = parse_env_file(f"KEY={encoded}\n")
        assert parsed["KEY"] == raw

    def test_plain_values_stay_plain(self) -> None:
        assert percent_q("simple-value_1.0") == "simple-value_1.0"


class TestValidateDbPassword:
    def test_rejects_empty(self) -> None:
        with pytest.raises(CtlError, match="must not be empty"):
            validate_db_password("", "the test password")

    def test_rejects_newline(self) -> None:
        # Line-oriented credential stores would be corrupted.
        with pytest.raises(CtlError, match="newline"):
            validate_db_password("a\nb", "the test password")

    def test_rejects_carriage_return(self) -> None:
        # Java Properties.load and option-file readers treat CR as a line
        # terminator, so a CR-bearing password passes the env-channel re-auth
        # probe but SILENTLY truncates in carlos.properties / exporter.my.cnf.
        with pytest.raises(CtlError, match="control character"):
            validate_db_password("a\rb", "the test password")

    def test_rejects_other_c0_controls(self) -> None:
        with pytest.raises(CtlError, match="control character"):
            validate_db_password("a\x00b", "the test password")

    def test_accepts_special_chars(self) -> None:
        validate_db_password("p@$s'w\\ord", "the test password")

    def test_rejects_spel_expression_token(self) -> None:
        # spring_jpa.xml reads the password as `value="${db_password}"`, so
        # the resolved VALUE is still run through Spring's SpEL resolver: a
        # '#{' password made the whole webapp context fail to start (verified
        # live: EL1008E, /carlos served 404) and echoed a fragment of the
        # password into the app log.
        with pytest.raises(CtlError, match=r"#\{"):
            validate_db_password("pa#{ok}ss", "the test password")

    def test_rejects_nested_placeholder_token(self) -> None:
        # '${' is the same class one layer earlier: re-resolved as a nested
        # placeholder, so the app authenticates with a DIFFERENT string than
        # the one provisioned.
        with pytest.raises(CtlError, match=r"\$\{"):
            validate_db_password("pa${db_username}ss", "the test password")

    def test_accepts_a_bare_dollar_or_hash(self) -> None:
        # Only the two-character opening sequences are interpolation — a
        # lone '$' or '#' must stay usable.
        validate_db_password("pa$s#word", "the test password")


class TestScrubRepoCreds:
    def test_redacts_userinfo_in_rest_url(self) -> None:
        from carlos_ctl.secrets import scrub_repo_creds

        out = scrub_repo_creds("unable to open rest:https://bob:s3cr3t@backup.host/carlos")
        assert "s3cr3t" not in out
        assert "bob" not in out
        assert "<redacted>@backup.host" in out

    def test_leaves_creds_free_text_untouched(self) -> None:
        from carlos_ctl.secrets import scrub_repo_creds

        msg = "repository /var/backup/restic-repo does not exist"
        assert scrub_repo_creds(msg) == msg

    def test_rejects_surrogate_bearing_values(self) -> None:
        # A non-UTF-8 bash-era env value decodes to lone surrogates
        # (surrogateescape); strict text sinks (bundle write, SQL over stdin)
        # would raise a bare UnicodeEncodeError mid-verb — refuse up front.
        with pytest.raises(CtlError, match="not valid UTF-8"):
            validate_db_password("pw\udcc3\udca9", "the test password")


class TestBundleRecipients:
    def test_reads_all_recorded_recipients(self, mk_runner) -> None:
        # An operator-added escrow recipient must survive re-encryption —
        # silently dropping it would cut the escrow key off.
        r = mk_runner()
        s = r.settings
        s.secrets_bundle.parent.mkdir(parents=True, exist_ok=True)
        s.secrets_bundle.write_text(
            "carlos:\n    db_password: ENC[...]\n"
            "sops:\n"
            "    age:\n"
            "        - recipient: age1instancekey000\n"
            "          enc: xxx\n"
            "        - recipient: age1escrowkey111\n"
            "          enc: yyy\n"
        )
        assert _bundle_recipients(r) == "age1instancekey000,age1escrowkey111"

    def test_falls_back_to_instance_recipient(self, mk_runner) -> None:
        r = mk_runner()
        s = r.settings
        s.secrets_bundle.parent.mkdir(parents=True, exist_ok=True)
        s.secrets_bundle.write_text("not yaml: [")
        s.age_pub_file.write_text("age1fallback\n")
        assert _bundle_recipients(r) == "age1fallback"


class TestRotateCaddyPassword:
    def _caddyfile(self, runner, user: str = "logview") -> Path:
        p = runner.settings.conf_dir / "caddy" / "Caddyfile"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            ":9443 {\n"
            "    basic_auth {\n"
            f"        {user} $2b$14$oldhash\n"
            "    }\n"
            "    reverse_proxy /select/* 127.0.0.1:9428\n"
            "}\n"
        )
        return p

    def test_rewrites_only_the_credential_line(self, mk_runner) -> None:
        r = mk_runner()
        f = self._caddyfile(r)
        _rotate_caddy_password(r, "logview", "log view", "newpw123")
        text = f.read_text()
        assert "$2b$14$oldhash" not in text
        assert "reverse_proxy /select/* 127.0.0.1:9428" in text  # local edits survive
        hash_line = [ln for ln in text.splitlines() if ln.strip().startswith("logview ")][0]
        assert hash_line.split()[1].startswith("$2b$")

    def test_replacement_preserves_owner_metadata(self, mk_runner) -> None:
        # The Caddyfile is service-user-owned (rootless Caddy reads it via
        # the subuid map); a root-owned 0600 replacement would crash-loop the
        # log view — the rotate must stat the original and fchown the staged
        # file. Non-root tests can't change uids, so pin the mechanism: the
        # rewritten file keeps the ORIGINAL file's uid/gid.
        import os

        r = mk_runner()
        f = self._caddyfile(r)
        before = f.stat()
        _rotate_caddy_password(r, "logview", "log view", "newpw123")
        after = f.stat()
        assert (after.st_uid, after.st_gid) == (before.st_uid, before.st_gid)
        assert (after.st_mode & 0o777) == 0o600
        assert not os.path.exists(str(f) + ".new")  # staging cleaned up

    def test_failed_logview_restart_warns_loudly(self, mk_runner, capsys) -> None:
        # The file already holds the NEW hash; a failed restart means the
        # running Caddy still serves the OLD credential — "rotated" must not
        # read as success silently.
        r = mk_runner()
        self._caddyfile(r)
        r.script("podman", "ps", rc=0, out=f"{r.settings.obs_pod}-logview\n")
        r.script("podman", "restart", rc=1)
        _rotate_caddy_password(r, "logview", "log view", "newpw123")
        err = capsys.readouterr().err
        assert "could not restart" in err
        assert "OLD credential" in err

    def test_missing_user_refused(self, mk_runner) -> None:
        r = mk_runner()
        self._caddyfile(r, user="otheruser")
        with pytest.raises(CtlError, match="no basic_auth entry"):
            _rotate_caddy_password(r, "logview", "log view", "x")

    def test_obs_disabled_refused_with_guidance(self, mk_runner) -> None:
        r = mk_runner("OBS_ENABLED=0\n")
        with pytest.raises(CtlError, match="observability pod"):
            _rotate_caddy_password(r, "logview", "log view", "x")


class TestAlertDispatch:
    def test_journal_only_is_healthy(self, mk_runner) -> None:
        r = mk_runner()
        r.tools = {"logger"}
        assert alert.dispatch(r, "test", "detail") is True

    def test_configured_webhook_failure_is_unhealthy(self, mk_runner) -> None:
        # A webhook 404 must not look like a delivered page.
        r = mk_runner("ALERT_WEBHOOK=https://hooks/x\n")
        r.tools = {"logger", "curl"}
        r.script("curl", rc=22)
        assert alert.dispatch(r, "test") is False

    def test_webhook_delivery_is_healthy_and_url_off_argv(self, mk_runner) -> None:
        r = mk_runner("ALERT_WEBHOOK=https://hooks/secret-token\n")
        r.tools = {"logger", "curl"}
        r.script("curl", rc=0)
        assert alert.dispatch(r, "test") is True
        curl_calls = [c for c in r.calls if c and c[0] == "curl"]
        assert curl_calls, "curl was not invoked"
        # The capability URL must never be an argv token (process-list leak).
        assert not any("secret-token" in arg for c in curl_calls for arg in c)

    def test_email_fallback_covers_webhook_failure(self, mk_runner) -> None:
        r = mk_runner("ALERT_WEBHOOK=https://hooks/x\nALERT_EMAIL=ops@example.ca\n")
        r.tools = {"logger", "curl", "sendmail"}
        r.script("curl", rc=22)
        r.script("sendmail", rc=0)
        assert alert.dispatch(r, "test") is True

    def test_email_without_mta_is_unhealthy(self, mk_runner) -> None:
        # ALERT_EMAIL set but no MTA — misconfiguration must not read healthy.
        r = mk_runner("ALERT_EMAIL=ops@example.ca\n")
        r.tools = {"logger"}
        assert alert.dispatch(r, "test") is False

    def test_webhook_with_injection_char_is_not_sent(self, mk_runner) -> None:
        # M8: a webhook URL carrying a curl-config-hostile char must not ride
        # the config (it would truncate/hijack it) — no curl call, unhealthy.
        r = mk_runner('ALERT_WEBHOOK=https://hooks/x"evil\n')
        r.tools = {"logger", "curl"}
        r.script("curl", rc=0)
        assert alert.dispatch(r, "test") is False
        assert not any(c and c[0] == "curl" for c in r.calls)


class TestRotateObsHttpValidation:
    """M8: an operator-supplied OBS_HTTP_NEW_PASSWORD rides the TOML/curl/file
    holders — reject a hostile value BEFORE any mutation."""

    def test_injection_password_refused_before_write(self, mk_runner) -> None:
        r = mk_runner("", {"OBS_HTTP_NEW_PASSWORD": 'a"b'})
        s = r.settings
        s.secrets_private_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        s.obs_http_password_file.write_text("old-obs-pw\n")
        with pytest.raises(CtlError, match="curl config line"):
            _rotate_obs_http(r)
        # The canonical password file is untouched (no half-rotation).
        assert s.obs_http_password_file.read_text() == "old-obs-pw\n"


class TestRenderOwnershipVerify:
    # Finding C22: the render's chowns are suppress(OSError)-wrapped — a
    # failed chown must be caught by the post-chown verification, not read
    # as a green render while the rootless pod cannot open its fragments.

    def test_matching_owner_passes(self, tmp_path: Path) -> None:
        import os

        from carlos_ctl.secrets import _assert_owned_by

        f = tmp_path / "fragment"
        f.write_text("db_password=x\n")
        _assert_owned_by(f, os.stat(f).st_uid)  # must not raise

    def test_foreign_owner_raises_loudly(self, tmp_path: Path) -> None:
        import os

        from carlos_ctl.secrets import _assert_owned_by

        f = tmp_path / "fragment"
        f.write_text("db_password=x\n")
        with pytest.raises(CtlError, match="__SEALED__"):
            _assert_owned_by(f, os.stat(f).st_uid + 1)


class TestAttendedRecovery:
    """The attended TPM-failure fallback: age_key() unwraps the passphrase-
    wrapped recovery copy when the sealed-blob decrypt fails; unattended runs
    without an answer keep the fail-loud contract."""

    AGE_KEY = "AGE-SECRET-KEY-1TESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTEST\n"

    def _wire(self, r, monkeypatch, tmp_path, creds_decrypt_rc=1,
              recovery=True, openssl_rc=0, ask_out="pass-phrase-123\n", ask_rc=0):
        """Wire a runner whose subprocess fakes WRITE the -out files (the
        stock FakeRunner only records argv)."""
        import os as _os

        s = r.settings
        monkeypatch.setenv("CARLOS_CREDSTORE_DIR", str(tmp_path / "credstore"))
        s.credstore_dir = tmp_path / "credstore"
        s.credstore_dir.mkdir(parents=True, exist_ok=True)
        (s.credstore_dir / f"{s.cred_age}.cred").write_text("sealed-blob")
        r.tools.add("systemd-creds")
        if recovery:
            s.secrets_private_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            s.age_key_recovery_file.write_text("wrapped")
        monkeypatch.setattr("sys.stdin", type("T", (), {"isatty": lambda self: False})())
        # The secrets unit's opt-in (read from os.environ ONLY, so the
        # env file cannot widen/narrow it).
        monkeypatch.setenv("CARLOS_ATTENDED_RECOVERY", "1")
        real_run = r.run

        def run(argv, **kw):
            argv = list(argv)
            if argv[:2] == ["systemd-creds", "decrypt"]:
                out = argv[-1]
                if creds_decrypt_rc == 0 and out != "-":
                    Path(out).write_text(self.AGE_KEY)
                r.calls.append(argv)
                import subprocess as sp
                return sp.CompletedProcess(argv, creds_decrypt_rc, "", "")
            if argv[:1] == ["systemd-ask-password"]:
                r.calls.append(argv)
                import subprocess as sp
                return sp.CompletedProcess(argv, ask_rc, ask_out, "")
            if argv[:2] == ["openssl", "enc"] and "-out" in argv:
                out = argv[argv.index("-out") + 1]
                if openssl_rc == 0:
                    Path(out).write_text(self.AGE_KEY)
                r.calls.append(argv)
                r.stdins.append(str(kw.get("input_text") or ""))
                import subprocess as sp
                return sp.CompletedProcess(argv, openssl_rc, "", "")
            return real_run(argv, **kw)

        r.run = run  # type: ignore[method-assign]
        _os.environ.pop("CREDENTIALS_DIRECTORY", None)
        return r

    def test_tpm_failure_unwraps_recovery_copy_via_ask_password(
        self, monkeypatch, mk_runner, tmp_path
    ) -> None:
        from carlos_ctl.secrets import age_key

        r = self._wire(mk_runner(), monkeypatch, tmp_path)
        r.tools.add("systemd-ask-password")
        with age_key(r) as kp:
            assert Path(kp).read_text() == self.AGE_KEY
        # The passphrase rode stdin to openssl, never argv.
        openssl_calls = [c for c in r.calls if c[:2] == ["openssl", "enc"]]
        assert openssl_calls and all("pass-phrase-123" not in " ".join(c) for c in openssl_calls)
        # transient key removed after the context exits
        assert not Path(kp).exists()

    def test_tpm_failure_without_recovery_file_fails_loud(
        self, monkeypatch, mk_runner, tmp_path
    ) -> None:
        from carlos_ctl.secrets import age_key

        r = self._wire(mk_runner(), monkeypatch, tmp_path, recovery=False)
        r.tools.add("systemd-ask-password")
        with pytest.raises(CtlError, match="ESCROWED"):
            with age_key(r):
                pass

    def test_ask_password_timeout_keeps_fail_loud_contract(
        self, monkeypatch, mk_runner, tmp_path
    ) -> None:
        from carlos_ctl.secrets import age_key

        r = self._wire(mk_runner(), monkeypatch, tmp_path, ask_rc=1, ask_out="")
        r.tools.add("systemd-ask-password")
        with pytest.raises(CtlError, match="ESCROWED"):
            with age_key(r):
                pass
        # exactly one prompt: a timed-out unattended boot must not burn 3 timeouts
        assert len([c for c in r.calls if c[:1] == ["systemd-ask-password"]]) == 1

    def test_wrong_passphrase_three_attempts_then_fail(
        self, monkeypatch, mk_runner, tmp_path
    ) -> None:
        from carlos_ctl.secrets import age_key

        r = self._wire(mk_runner(), monkeypatch, tmp_path, openssl_rc=1)
        r.tools.add("systemd-ask-password")
        with pytest.raises(CtlError, match="ESCROWED"):
            with age_key(r):
                pass
        assert len([c for c in r.calls if c[:1] == ["systemd-ask-password"]]) == 3

    def test_no_ask_password_tool_fails_loud_without_prompt(
        self, monkeypatch, mk_runner, tmp_path
    ) -> None:
        from carlos_ctl.secrets import age_key

        r = self._wire(mk_runner(), monkeypatch, tmp_path)
        r.tools.discard("systemd-ask-password")
        with pytest.raises(CtlError, match="ESCROWED"):
            with age_key(r):
                pass

    def test_headless_without_optin_never_prompts(
        self, monkeypatch, mk_runner, tmp_path
    ) -> None:
        """A backup timer (or any scripted verb) whose key sources are broken
        must fail immediately — console prompting is scoped to the secrets
        unit's CARLOS_ATTENDED_RECOVERY=1 opt-in."""
        from carlos_ctl.secrets import age_key

        r = self._wire(mk_runner(), monkeypatch, tmp_path)
        monkeypatch.delenv("CARLOS_ATTENDED_RECOVERY", raising=False)
        r.tools.add("systemd-ask-password")
        with pytest.raises(CtlError, match="ESCROWED"):
            with age_key(r):
                pass
        assert not [c for c in r.calls if c[:1] == ["systemd-ask-password"]]

    def test_healthy_tpm_never_touches_recovery(
        self, monkeypatch, mk_runner, tmp_path
    ) -> None:
        from carlos_ctl.secrets import age_key

        r = self._wire(mk_runner(), monkeypatch, tmp_path, creds_decrypt_rc=0)
        r.tools.add("systemd-ask-password")
        with age_key(r) as kp:
            assert Path(kp).read_text() == self.AGE_KEY
        assert not [c for c in r.calls if c[:1] == ["systemd-ask-password"]]

    def test_sealed_decrypt_passes_the_cred_name(
        self, monkeypatch, mk_runner, tmp_path
    ) -> None:
        """systemd-creds refuses a decrypt whose embedded name does not match
        the filename, so the sealed-blob decrypt MUST pass --name=<cred_age>
        (the name _seal_one sealed it with). Without it every TPM-host boot
        render fails the decrypt. The stub can't reproduce systemd-creds'
        refusal, so pin the argument shape instead (verified against real
        systemd-creds 255 separately)."""
        from carlos_ctl.secrets import age_key

        r = self._wire(mk_runner(), monkeypatch, tmp_path, creds_decrypt_rc=0)
        with age_key(r):
            pass
        decrypt = next(c for c in r.calls if c[:2] == ["systemd-creds", "decrypt"])
        assert f"--name={r.settings.cred_age}" in decrypt


    def test_stale_wrap_of_rotated_key_is_rejected(
        self, monkeypatch, mk_runner, tmp_path
    ) -> None:
        """A recovery wrap holding a ROTATED-OUT key unwraps cleanly with its
        passphrase but no longer matches the current recipient — the render
        must reject it (a slot that lies) rather than yield a dead key."""
        from carlos_ctl.secrets import age_key

        r = self._wire(mk_runner(), monkeypatch, tmp_path)
        r.tools.add("systemd-ask-password")
        r.tools.add("age-keygen")
        s = r.settings
        s.age_pub_file.parent.mkdir(parents=True, exist_ok=True)
        s.age_pub_file.write_text("age1CURRENTrecipient\n")
        # age-keygen -y on the unwrapped (old) key derives a DIFFERENT pub.
        r.script("age-keygen", "-y", rc=0, out="age1OLDrecipient\n")
        with pytest.raises(CtlError, match="ESCROWED"):
            with age_key(r):
                pass


class TestRecoveryWrapWriter:
    def test_headless_passphrase_file_writes_verified_wrap(
        self, monkeypatch, mk_runner, tmp_path
    ) -> None:
        from carlos_ctl.secrets import _maybe_write_recovery_wrap

        r = mk_runner()
        s = r.settings
        s.secrets_private_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        s.age_key_file.write_text(TestAttendedRecovery.AGE_KEY)
        pf = tmp_path / "recovery-pass"
        pf.write_text("a-long-enough-passphrase\n")
        monkeypatch.setenv("CARLOS_RECOVERY_PASSPHRASE_FILE", str(pf))
        r.settings._env["CARLOS_RECOVERY_PASSPHRASE_FILE"] = str(pf)  # noqa: SLF001
        monkeypatch.setattr("sys.stdin", type("T", (), {"isatty": lambda self: False})())
        real_run = r.run

        def run(argv, **kw):
            argv = list(argv)
            if argv[:2] == ["openssl", "enc"] and "-out" in argv:
                out = argv[argv.index("-out") + 1]
                if "-d" in argv:
                    Path(out).write_text(TestAttendedRecovery.AGE_KEY)
                else:
                    Path(out).write_text("wrapped-bytes")
                r.calls.append(argv)
                import subprocess as sp
                return sp.CompletedProcess(argv, 0, "", "")
            return real_run(argv, **kw)

        r.run = run  # type: ignore[method-assign]
        _maybe_write_recovery_wrap(r)
        assert s.age_key_recovery_file.is_file()
        assert (s.age_key_recovery_file.stat().st_mode & 0o777) == 0o600

    def test_short_passphrase_refused(self, monkeypatch, mk_runner, tmp_path) -> None:
        from carlos_ctl.secrets import _maybe_write_recovery_wrap

        r = mk_runner()
        pf = tmp_path / "recovery-pass"
        pf.write_text("short\n")
        r.settings._env["CARLOS_RECOVERY_PASSPHRASE_FILE"] = str(pf)  # noqa: SLF001
        with pytest.raises(CtlError, match="12 characters"):
            _maybe_write_recovery_wrap(r)

    def test_no_passphrase_headless_skips_quietly(self, monkeypatch, mk_runner) -> None:
        from carlos_ctl.secrets import _maybe_write_recovery_wrap

        r = mk_runner()
        monkeypatch.setattr("sys.stdin", type("T", (), {"isatty": lambda self: False})())
        _maybe_write_recovery_wrap(r)
        assert not r.settings.age_key_recovery_file.exists()
