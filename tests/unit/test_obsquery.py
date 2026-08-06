# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Unit tests for carlos_ctl.obsquery — the store_curl chokepoint every
store/vmalert probe funnels through (finding 33: authed stores, credential
off-argv), plus the JSON parsing contracts."""

from __future__ import annotations

from carlos_ctl import obsquery


def _provision_credential(runner, pw: str = "obs-unit-pw") -> None:
    d = runner.settings.secrets_private_dir
    d.mkdir(parents=True, exist_ok=True)
    runner.settings.obs_http_password_file.write_text(pw + "\n")


class TestStoreCurl:
    def test_url_and_credential_ride_stdin_never_argv(self, mk_runner) -> None:
        r = mk_runner()
        _provision_credential(r)
        obsquery.store_curl(r, "http://127.0.0.1:8428/health")
        assert r.calls and r.calls[-1][0] == "curl"
        # Off-argv contract: neither the URL nor the credential is a token.
        assert not any("8428" in a for a in r.calls[-1])
        assert not any("obs-unit-pw" in a for a in r.calls[-1])
        assert 'url = "http://127.0.0.1:8428/health"' in r.stdins[-1]
        assert 'user = "obs:obs-unit-pw"' in r.stdins[-1]

    def test_missing_credential_file_omits_the_user_line(self, mk_runner) -> None:
        r = mk_runner()
        obsquery.store_curl(r, "http://127.0.0.1:8428/health")
        assert "user =" not in r.stdins[-1]

    def test_injection_bearing_credential_omitted_and_warned(
        self, mk_runner, capsys
    ) -> None:
        # M8: a password carrying a curl-config-hostile char must NOT ride the
        # config (it would corrupt/hijack it) — omit it and warn; the store
        # then 401s the credential-less probe loudly.
        r = mk_runner()
        _provision_credential(r, pw='bad"pw')
        obsquery.store_curl(r, "http://127.0.0.1:8428/health")
        assert "user =" not in r.stdins[-1]
        assert 'bad"pw' not in r.stdins[-1]
        assert "WITHOUT auth" in capsys.readouterr().err

    def test_with_auth_false_is_deliberately_credential_less(self, mk_runner) -> None:
        # check's enforcement probe: MUST be able to send no credential even
        # when one is provisioned (it asserts the store rejects it).
        r = mk_runner()
        _provision_credential(r)
        obsquery.store_curl(r, "http://127.0.0.1:8428/api/v1/query", with_auth=False)
        assert "user =" not in r.stdins[-1]

    def test_query_bodies_stay_on_argv(self, mk_runner) -> None:
        # Queries are not secrets; the shell stub discriminates on them.
        r = mk_runner()
        obsquery.vm_scalar(r, "mysql_up")
        assert any("query=mysql_up" in a for a in r.calls[-1])


class TestParsing:
    def test_vm_scalar_reads_the_first_value(self, mk_runner) -> None:
        r = mk_runner()
        r.script("curl", rc=0,
                 out='{"status":"success","data":{"result":[{"value":[0,"1"]}]}}')
        assert obsquery.vm_scalar(r, "up") == "1"

    def test_vm_scalar_unreachable_is_empty(self, mk_runner) -> None:
        r = mk_runner()
        r.script("curl", rc=7)
        assert obsquery.vm_scalar(r, "up") == ""

    def test_vmalert_malformed_response_is_none_not_empty(self, mk_runner) -> None:
        # A corrupt 200 must NOT read as "no alerts firing".
        r = mk_runner()
        r.script("curl", rc=0, out="not json")
        assert obsquery.vmalert_firing(r) is None

    def test_vl_count_parses_the_stats_line(self, mk_runner) -> None:
        r = mk_runner()
        r.script("curl", rc=0, out='{"n":"7"}')
        assert obsquery.vl_count(r, "_stream:x") == 7
