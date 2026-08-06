# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Unit tests for the `carlos-ctl setup` wizard's input validation (finding 45).

The wizard reads answers line-by-line from stdin when it is not a tty, so each
test feeds a full answer script and asserts the wizard either writes a 0600
host_vars file or fails closed on a bad answer BEFORE writing anything."""

from __future__ import annotations

import io
import stat
from typing import List

import pytest

from carlos_ctl.setup import cmd_setup
from carlos_ctl.util import CtlError

# The prompt order in cmd_setup. A valid baseline script; individual tests
# override single answers to exercise one validation gate at a time.
_VALID: List[str] = [
    "clinic-a",          # instance name
    "/usr/local/emr",    # EMR_HOME
    "192.168.20.250",    # BIND_IP
    "emr.example.ca",    # server name
    "selfsigned",        # TLS mode
    "root-pw",           # DB root password (_ask_secret)
    "ON",                # province
    "America/Toronto",   # tz
    "",                  # alert email
    "",                  # heartbeat
    "no",                # obs
    "443",               # https
    "8443",              # publish
    "9443",              # logview
    "9428",              # vlogs
    "8428",              # vmetr
    "8880",              # vmalert
    "9444",              # pma
]


def _run(monkeypatch, mk_runner, tmp_path, answers: List[str], extra=None):
    monkeypatch.setattr("sys.stdin", io.StringIO("\n".join(answers) + "\n"))
    env = {
        "CARLOS_HOST_VARS_DIR": str(tmp_path / "host_vars"),
        # These tests exercise the ANSWER validation gates; the S19
        # plaintext-refusal gate has its own tests below.
        "CARLOS_SETUP_ALLOW_PLAINTEXT": "1",
    }
    env.update(extra or {})
    r = mk_runner("", env)
    r.tools.discard("ansible-vault")  # force the plaintext (non-interactive) path
    return r, cmd_setup(r)


class TestSetupValidation:
    def test_valid_answers_write_host_vars(self, monkeypatch, mk_runner, tmp_path) -> None:
        r, rc = _run(monkeypatch, mk_runner, tmp_path, _VALID)
        assert rc == 0
        out = tmp_path / "host_vars" / "clinic-a.yml"
        assert out.is_file()
        assert stat.S_IMODE(out.stat().st_mode) == 0o600
        body = out.read_text()
        assert 'carlos_instance: "clinic-a"' in body
        assert 'carlos_billing_province: "ON"' in body

    def test_host_vars_yaml_loads_with_string_province(
        self, monkeypatch, mk_runner, tmp_path
    ) -> None:
        # Seventh-pass F: unquoted `ON` is YAML-1.1 boolean True — the wizard's
        # default Ontario output then failed the role's province assert. The
        # emitted file must LOAD as YAML with the province as the string "ON".
        yaml = pytest.importorskip("yaml")
        _run(monkeypatch, mk_runner, tmp_path, _VALID)
        data = yaml.safe_load((tmp_path / "host_vars" / "clinic-a.yml").read_text())
        assert data["carlos_billing_province"] == "ON"
        assert data["carlos_instance"] == "clinic-a"

    def test_next_steps_use_flyway_not_retired_oscarinit(
        self, monkeypatch, mk_runner, tmp_path, capsys
    ) -> None:
        # M6: the schema-load instructions must point at the Flyway migrations,
        # not the retired oscarinit*.sql / oscardata.sql build.
        _run(monkeypatch, mk_runner, tmp_path, _VALID)
        out = capsys.readouterr().out
        assert "V1__baseline_schema.sql" in out
        assert "utf8mb4" in out
        assert "oscarinit" not in out
        assert "oscardata" not in out

    def test_bad_instance_name_refused(self, monkeypatch, mk_runner, tmp_path) -> None:
        answers = ["Clinic_A", *_VALID[1:]]
        with pytest.raises(CtlError, match="INSTANCE"):
            _run(monkeypatch, mk_runner, tmp_path, answers)

    def test_unknown_province_refused(self, monkeypatch, mk_runner, tmp_path) -> None:
        answers = list(_VALID)
        answers[6] = "Ontario"
        with pytest.raises(CtlError, match="province"):
            _run(monkeypatch, mk_runner, tmp_path, answers)

    def test_province_case_normalized(self, monkeypatch, mk_runner, tmp_path) -> None:
        answers = list(_VALID)
        answers[6] = "bc"
        _run(monkeypatch, mk_runner, tmp_path, answers)
        body = (tmp_path / "host_vars" / "clinic-a.yml").read_text()
        assert 'carlos_billing_province: "BC"' in body

    def test_bad_bind_ip_refused(self, monkeypatch, mk_runner, tmp_path) -> None:
        answers = list(_VALID)
        answers[2] = "999.1.1.1"
        with pytest.raises(CtlError, match="IPv4"):
            _run(monkeypatch, mk_runner, tmp_path, answers)

    def test_duplicate_ports_refused(self, monkeypatch, mk_runner, tmp_path) -> None:
        answers = list(_VALID)
        answers[12] = "443"  # publish == https
        with pytest.raises(CtlError, match="duplicate|no-op|redirect"):
            _run(monkeypatch, mk_runner, tmp_path, answers)

    def test_empty_db_password_refused(self, monkeypatch, mk_runner, tmp_path) -> None:
        answers = list(_VALID)
        answers[5] = ""
        with pytest.raises(CtlError, match="empty"):
            _run(monkeypatch, mk_runner, tmp_path, answers)


class TestNonInteractiveVaulting:
    """Finding S19: scripted setup must not silently persist the
    full-PHI-access root credential in plaintext."""

    def _env(self, tmp_path, extra=None):
        env = {"CARLOS_HOST_VARS_DIR": str(tmp_path / "host_vars")}
        env.update(extra or {})
        return env

    def test_non_tty_without_ack_or_vault_source_refuses(
        self, monkeypatch, mk_runner, tmp_path
    ) -> None:
        monkeypatch.setattr("sys.stdin", io.StringIO("\n".join(_VALID) + "\n"))
        monkeypatch.delenv("ANSIBLE_VAULT_PASSWORD_FILE", raising=False)
        r = mk_runner("", self._env(tmp_path))
        r.tools.discard("ansible-vault")
        with pytest.raises(CtlError, match="PLAINTEXT"):
            cmd_setup(r)
        assert not (tmp_path / "host_vars" / "clinic-a.yml").is_file()

    def test_vault_password_file_enables_headless_vaulting(
        self, monkeypatch, mk_runner, tmp_path
    ) -> None:
        monkeypatch.setattr("sys.stdin", io.StringIO("\n".join(_VALID) + "\n"))
        pwfile = tmp_path / "vault-pw"
        pwfile.write_text("vaultpw\n")
        r = mk_runner("", self._env(
            tmp_path, {"CARLOS_VAULT_PASSWORD_FILE": str(pwfile)}
        ))
        r.tools.add("ansible-vault")
        r.script("ansible-vault", "encrypt_string", rc=0,
                 out="carlos_db_root_password: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  61\n")
        assert cmd_setup(r) == 0
        body = (tmp_path / "host_vars" / "clinic-a.yml").read_text()
        assert "!vault" in body
        assert "root-pw" not in body
        vault_call = next(c for c in r.calls if c[:2] == ["ansible-vault", "encrypt_string"])
        assert "--vault-password-file" in vault_call
        # The password itself rides stdin, never argv.
        assert "root-pw" not in " ".join(vault_call)

    def test_explicit_plaintext_ack_writes_with_warning_comment(
        self, monkeypatch, mk_runner, tmp_path
    ) -> None:
        monkeypatch.setattr("sys.stdin", io.StringIO("\n".join(_VALID) + "\n"))
        monkeypatch.delenv("ANSIBLE_VAULT_PASSWORD_FILE", raising=False)
        r = mk_runner("", self._env(tmp_path, {"CARLOS_SETUP_ALLOW_PLAINTEXT": "1"}))
        r.tools.discard("ansible-vault")
        assert cmd_setup(r) == 0
        body = (tmp_path / "host_vars" / "clinic-a.yml").read_text()
        assert 'carlos_db_root_password: "root-pw"' in body

    def test_headless_key_vault_failure_after_db_vaulted_fails_closed(
        self, monkeypatch, mk_runner, tmp_path
    ) -> None:
        """db password vaults fine, the app-encryption-key vaulting FAILS:
        a headless run must refuse (CtlError) and persist NOTHING — the old
        behavior (plaintext key + exit 0 in CI) is the regression under
        test."""
        monkeypatch.setattr("sys.stdin", io.StringIO("\n".join(_VALID) + "\n"))
        monkeypatch.delenv("ANSIBLE_VAULT_PASSWORD_FILE", raising=False)
        pwfile = tmp_path / "vault-pw"
        pwfile.write_text("vaultpw\n")
        r = mk_runner("", self._env(
            tmp_path, {"CARLOS_VAULT_PASSWORD_FILE": str(pwfile)}
        ))
        r.tools.add("ansible-vault")
        r.script("ansible-vault", "encrypt_string", "--stdin-name",
                 "carlos_db_root_password", rc=0,
                 out="carlos_db_root_password: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  61\n")
        r.script("ansible-vault", "encrypt_string", "--stdin-name",
                 "carlos_encryption_secret_key", rc=1, out="")
        with pytest.raises(CtlError, match="PLAINTEXT"):
            cmd_setup(r)
        assert not (tmp_path / "host_vars" / "clinic-a.yml").is_file()

    def test_headless_key_vault_failure_with_plaintext_ack_writes_plaintext_key(
        self, monkeypatch, mk_runner, tmp_path
    ) -> None:
        """Same partial-failure shape, but the operator explicitly accepted
        plaintext: the file is written with the vaulted db password and the
        quoted plaintext key (plus the vault-it note)."""
        monkeypatch.setattr("sys.stdin", io.StringIO("\n".join(_VALID) + "\n"))
        monkeypatch.delenv("ANSIBLE_VAULT_PASSWORD_FILE", raising=False)
        pwfile = tmp_path / "vault-pw"
        pwfile.write_text("vaultpw\n")
        r = mk_runner("", self._env(
            tmp_path,
            {"CARLOS_VAULT_PASSWORD_FILE": str(pwfile),
             "CARLOS_SETUP_ALLOW_PLAINTEXT": "1"},
        ))
        r.tools.add("ansible-vault")
        r.script("ansible-vault", "encrypt_string", "--stdin-name",
                 "carlos_db_root_password", rc=0,
                 out="carlos_db_root_password: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  61\n")
        r.script("ansible-vault", "encrypt_string", "--stdin-name",
                 "carlos_encryption_secret_key", rc=1, out="")
        assert cmd_setup(r) == 0
        body = (tmp_path / "host_vars" / "clinic-a.yml").read_text()
        assert "carlos_db_root_password: !vault" in body
        assert 'carlos_encryption_secret_key: "' in body
        assert "Vault this value like the db password" in body


class TestWizardBindIpDefault:
    def test_enter_through_default_matches_the_role_default(
        self, monkeypatch, mk_runner, tmp_path
    ) -> None:
        # The old wizard default was a made-up LAN IP (192.168.20.250) that
        # disagreed with defaults/main.yml — Enter-through installs got a
        # listener address wrong everywhere.
        answers = list(_VALID)
        answers[2] = ""  # accept the BIND_IP default
        r, rc = _run(monkeypatch, mk_runner, tmp_path, answers)
        assert rc == 0
        body = (tmp_path / "host_vars" / "clinic-a.yml").read_text()
        assert 'carlos_bind_ip: "127.0.0.1"' in body
