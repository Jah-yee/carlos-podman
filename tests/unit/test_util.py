# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Unit tests for carlos_ctl.util — behavioral parity with the bash helpers."""

from pathlib import Path

import pytest

from carlos_ctl.util import (
    CtlError,
    curl_config_quote,
    first_match,
    native_password_hash,
    properties_escape_value,
    properties_unescape_value,
    set_kv,
    shell_unquote_value,
    size_to_mib,
    sql_escape,
    stray_tokens,
)


class TestSizeToMib:
    @pytest.mark.parametrize(
        ("value", "expect"),
        [
            ("12Gi", 12 * 1024),
            ("8g", 8 * 1024),
            ("2G", 2 * 1024),
            ("512Mi", 512),
            ("256m", 256),
            ("1024Ki", 1),
            ("1048576", 1),  # bare bytes
            ("1.5Gi", 1536),
            ("0.5G", 512),
            ("2.25Gi", 2304),
        ],
    )
    def test_valid(self, value: str, expect: int) -> None:
        assert size_to_mib(value) == expect

    @pytest.mark.parametrize("value", ["", "abc", "1.5", "1.5X", "12Ti", "1..5Gi", "-1Gi"])
    def test_invalid(self, value: str) -> None:
        assert size_to_mib(value) is None


class TestEscaping:
    def test_sql_escape_doubles_quotes_not_backslash_escapes(self) -> None:
        # '' doubling is correct under EVERY sql_mode incl. NO_BACKSLASH_ESCAPES.
        assert sql_escape("pa'ss") == "pa''ss"
        assert sql_escape("a\\b'c") == "a\\\\b''c"

    def test_properties_escape_roundtrip(self) -> None:
        for raw in ["plain", "pa\\ss", "ends\\", "\\u0041", "a\\\\b"]:
            assert properties_unescape_value(properties_escape_value(raw)) == raw

    def test_properties_escape_doubles_backslash(self) -> None:
        assert properties_escape_value("pa\\ss") == "pa\\\\ss"


class TestCurlConfigQuote:
    """M8: values interpolated into a `curl -K -` config must reject the
    characters that could truncate the value or inject a directive."""

    @pytest.mark.parametrize(
        "ok",
        ["https://hooks.example/abc?x=1&y=2",
         "user:p@ss-word_1",
         "https://h/path;q=r,s",  # ; , : are fine
         "plainhost:9428"],
    )
    def test_accepts_urls_and_userinfo(self, ok: str) -> None:
        assert curl_config_quote(ok, "x") == f'"{ok}"'

    @pytest.mark.parametrize(
        "bad",
        ['has"quote', "back\\slash", "new\nline", "carriage\rreturn", "bell\x07"],
    )
    def test_rejects_quotes_backslashes_and_controls(self, bad: str) -> None:
        with pytest.raises(CtlError, match="curl config line"):
            curl_config_quote(bad, "x")


class TestShellUnquote:
    @pytest.mark.parametrize(
        ("encoded", "expect"),
        [
            ("plain", "plain"),
            ("'single quoted'", "single quoted"),
            ("a\\ b", "a b"),  # %q backslash-escaped printables
            ("\\!bang", "!bang"),
            ("a\\\\b", "a\\b"),
            ("$'line1\\nline2'", "line1\nline2"),
            ("$'tab\\there'", "tab\there"),
            ("$'a\\x41b'", "aAb"),
            ("$'\\''", "'"),  # escaped quote inside ANSI-C
            # bash printf %q octal-escapes multibyte values BYTE-wise under
            # the C locale ($'caf\303\251' is café) — the escapes are UTF-8
            # byte fragments, not codepoints. A codepoint decode yields the
            # mojibake 'cafÃ©' and breaks every bash-era non-ASCII password.
            ("$'caf\\303\\251'", "café"),
            ("$'\\xc3\\xa9'", "é"),
            ("$'\\342\\202\\254'", "€"),
        ],
    )
    def test_decode(self, encoded: str, expect: str) -> None:
        assert shell_unquote_value(encoded) == expect


class TestSetKv:
    def test_replaces_existing_key(self, tmp_path: Path) -> None:
        f = tmp_path / "app.env"
        f.write_text("A=1\nKEY=old\nB=2\n")
        set_kv(f, "KEY", "new")
        assert f.read_text() == "A=1\nKEY=new\nB=2\n"

    def test_appends_missing_key(self, tmp_path: Path) -> None:
        f = tmp_path / "app.env"
        f.write_text("A=1\n")
        set_kv(f, "KEY", "v")
        assert f.read_text() == "A=1\nKEY=v\n"

    def test_value_with_sed_metachars_is_literal(self, tmp_path: Path) -> None:
        # The reason set_kv exists: operator values may contain & \ / |.
        f = tmp_path / "app.env"
        f.write_text("KEY=old\n")
        set_kv(f, "KEY", "p&\\/|ss")
        assert f.read_text() == "KEY=p&\\/|ss\n"

    def test_result_is_0600(self, tmp_path: Path) -> None:
        f = tmp_path / "app.env"
        f.write_text("KEY=old\n")
        set_kv(f, "KEY", "secret")
        assert (f.stat().st_mode & 0o777) == 0o600

    def test_handles_file_without_trailing_newline(self, tmp_path: Path) -> None:
        f = tmp_path / "app.env"
        f.write_text("A=1\nKEY=old")  # hand-edited file, no final newline
        set_kv(f, "KEY", "new")
        assert "KEY=new" in f.read_text().splitlines()
        assert "A=1" in f.read_text().splitlines()

    def test_preserves_original_ownership(self, tmp_path: Path, monkeypatch) -> None:
        # The bash used `cp -p`: carlos.properties is SERVICE-USER-owned so
        # the rootless pod can read it — a root-run rotate must not replace
        # it with a root:root 0600 file. Ownership changes need root, so
        # assert the fchown CALL (to the original uid/gid) instead.
        import os as os_mod

        f = tmp_path / "carlos.properties"
        f.write_text("db_password=old\n")
        orig = f.stat()
        calls = []
        real_fchown = os_mod.fchown
        monkeypatch.setattr(
            "carlos_ctl.util.os.fchown",
            lambda fd, uid, gid: (calls.append((uid, gid)), real_fchown(fd, uid, gid)),
        )
        set_kv(f, "db_password", "new")
        assert (orig.st_uid, orig.st_gid) in calls


class TestMisc:
    def test_native_password_hash_known_vector(self) -> None:
        # MySQL documents PASSWORD('password'):
        assert (
            native_password_hash("password")
            == "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
        )

    def test_stray_tokens_lists_unrendered(self, tmp_path: Path) -> None:
        f = tmp_path / "r.yaml"
        f.write_text("image: @CARLOS_IMAGE@\nname: ok\nport: @HTTPS_PORT@\n")
        assert stray_tokens(f) == "@CARLOS_IMAGE@ @HTTPS_PORT@ "

    def test_stray_tokens_empty_when_rendered(self, tmp_path: Path) -> None:
        f = tmp_path / "r.yaml"
        f.write_text("image: localhost/x\n")
        assert stray_tokens(f) == ""

    def test_first_match_returns_raw_value(self) -> None:
        lines = ["# c", "db_password=s=cr=t", "db_password=second"]
        assert first_match(lines, "db_password") == "s=cr=t"
        assert first_match(lines, "missing") is None
