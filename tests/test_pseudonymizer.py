"""Tests for the pseudonymizer package public API and CLI."""

from __future__ import annotations

import base64
import hashlib
import re
from io import StringIO

import pytest

from pseudonymizer import InMemoryVault, PseudoError, Pseudonymizer

KEY1 = bytes(range(32))
KEY2 = bytes(range(32, 64))


def test_acceptance_token_email_k1_and_determinism() -> None:
    p = Pseudonymizer({"k1": KEY1}, active_key_id="k1")
    expected = "pz_k1_wktl6nutd3rd4p2xsepvga2sid"
    assert p.pseudonymize("ana@example.com", domain="email") == expected
    assert p.pseudonymize("ana@example.com", domain="email") == expected


def test_acceptance_token_phone_domain() -> None:
    p = Pseudonymizer({"k1": KEY1}, active_key_id="k1")
    assert p.pseudonymize("ana@example.com", domain="phone") == "pz_k1_pbngttrszjs5fvlb3mqgbefcty"


def test_acceptance_token_active_k2() -> None:
    p = Pseudonymizer({"k1": KEY1, "k2": KEY2}, active_key_id="k2")
    assert p.pseudonymize("ana@example.com", domain="email") == "pz_k2_xhtogzlikxntb2i2gkx3q3pwuo"


def test_vault_reidentify_and_errors() -> None:
    vault = InMemoryVault()
    p = Pseudonymizer({"k1": KEY1}, active_key_id="k1", vault=vault)
    token = p.pseudonymize("ana@example.com", domain="email")
    assert p.reidentify(token) == "ana@example.com"

    with pytest.raises(PseudoError) as exc:
        p.reidentify("abc")
    assert exc.value.code == "invalid_token"

    well_formed = "pz_k1_abcdefghijklmnopqrstuvwxyz"
    with pytest.raises(PseudoError) as exc:
        p.reidentify(well_formed)
    assert exc.value.code == "not_in_vault"

    p_no_vault = Pseudonymizer({"k1": KEY1}, active_key_id="k1")
    with pytest.raises(PseudoError) as exc:
        p_no_vault.reidentify(token)
    assert exc.value.code == "no_vault"


def test_constructor_errors() -> None:
    with pytest.raises(PseudoError) as exc:
        Pseudonymizer({"k1": b"x" * 31}, active_key_id="k1")
    assert exc.value.code == "weak_key"

    with pytest.raises(PseudoError) as exc:
        Pseudonymizer({"k1": KEY1}, active_key_id="k9")
    assert exc.value.code == "unknown_key"

    with pytest.raises(PseudoError) as exc:
        Pseudonymizer({"K-1": KEY1}, active_key_id="K-1")
    assert exc.value.code == "invalid_key_id"

    with pytest.raises(PseudoError) as exc:
        Pseudonymizer({"k1": KEY1}, active_key_id="K-1")
    assert exc.value.code == "invalid_key_id"


def test_key_id_selection_and_vault() -> None:
    vault = InMemoryVault()
    p = Pseudonymizer({"k1": KEY1, "k2": KEY2}, active_key_id="k2", vault=vault)
    token_old = p.pseudonymize("ana@example.com", domain="email", key_id="k1")
    assert token_old.startswith("pz_k1_")
    assert p.reidentify(token_old) == "ana@example.com"

    with pytest.raises(PseudoError) as exc:
        p.pseudonymize("ana@example.com", domain="email", key_id="k9")
    assert exc.value.code == "unknown_key"

    with pytest.raises(PseudoError) as exc:
        p.pseudonymize("ana@example.com", domain="email", key_id="K-1")
    assert exc.value.code == "invalid_key_id"


def test_value_errors() -> None:
    p = Pseudonymizer({"k1": KEY1}, active_key_id="k1")
    with pytest.raises(PseudoError) as exc:
        p.pseudonymize("", domain="email")
    assert exc.value.code == "invalid_value"
    with pytest.raises(PseudoError) as exc:
        p.pseudonymize("a" * 4097, domain="email")
    assert exc.value.code == "value_too_large"
    with pytest.raises(PseudoError) as exc:
        p.pseudonymize(123, domain="email")  # type: ignore[arg-type]
    assert exc.value.code == "invalid_value"


def test_domain_errors() -> None:
    p = Pseudonymizer({"k1": KEY1}, active_key_id="k1")
    for bad in ["", "A", "a" * 33, "email!"]:
        with pytest.raises(PseudoError) as exc:
            p.pseudonymize("x", domain=bad)
        assert exc.value.code == "invalid_domain"


def test_inmemory_vault_cap_and_noop() -> None:
    vault = InMemoryVault(max_entries=2)
    p = Pseudonymizer({"k1": KEY1}, active_key_id="k1", vault=vault)
    t1 = p.pseudonymize("a", domain="d")
    t2 = p.pseudonymize("b", domain="d")
    assert p.pseudonymize("a", domain="d") == t1
    with pytest.raises(PseudoError) as exc:
        p.pseudonymize("c", domain="d")
    assert exc.value.code == "vault_full"
    vault.put(t2, "b")  # no-op, should not raise
    with pytest.raises(PseudoError) as exc:
        vault.put("pz_k1_newtoken1234567890123456789012", "d")
    assert exc.value.code == "vault_full"


def test_pseudonymize_record() -> None:
    p = Pseudonymizer({"k1": KEY1}, active_key_id="k1")
    result = p.pseudonymize_record({"email": "ana@example.com", "plan": "pro"}, {"email": "email"})
    assert result == {
        "email": "pz_k1_wktl6nutd3rd4p2xsepvga2sid",
        "plan": "pro",
    }

    with pytest.raises(PseudoError) as exc:
        p.pseudonymize_record({"email": 123}, {"email": "email"})
    assert exc.value.code == "invalid_value"

    result2 = p.pseudonymize_record({"plan": "pro"}, {"email": "email"})
    assert "email" not in result2
    assert result2 == {"plan": "pro"}


def test_event_and_repr() -> None:
    events: list[dict[str, str]] = []
    p = Pseudonymizer({"k1": KEY1}, active_key_id="k1", on_event=events.append)
    p.pseudonymize("ana@example.com", domain="email")
    assert events == [{"event": "pseudonymized", "domain": "email", "key_id": "k1"}]

    repr_str = repr(p)
    assert base64.b64encode(KEY1).decode() not in repr_str
    assert KEY1.hex() not in repr_str


def test_token_grammar_and_linkage() -> None:
    pattern = re.compile(r"^pz_([a-z0-9]{1,8})_([a-z2-7]{26})$")
    p = Pseudonymizer({"k1": KEY1}, active_key_id="k1")
    token = p.pseudonymize("unicode-é", domain="domain_1")
    assert pattern.fullmatch(token)

    p2 = Pseudonymizer({"k1": KEY1, "k2": KEY2}, active_key_id="k2")
    t1 = p.pseudonymize("ana@example.com", domain="email")
    t2 = p2.pseudonymize("ana@example.com", domain="email")
    assert t1 != t2


def test_unicode_value_and_determinism() -> None:
    p = Pseudonymizer({"k1": KEY1}, active_key_id="k1")
    value = "Jöhn.Döé@example.com"
    t1 = p.pseudonymize(value, domain="email")
    t2 = p.pseudonymize(value, domain="email")
    assert t1 == t2


def test_token_differs_from_plain_sha256() -> None:
    p = Pseudonymizer({"k1": KEY1}, active_key_id="k1")
    value = "ana@example.com"
    token = p.pseudonymize(value, domain="email")
    assert token != hashlib.sha256(value.encode()).hexdigest()


def test_old_token_without_vault_returns_not_in_vault() -> None:
    p1 = Pseudonymizer({"k1": KEY1}, active_key_id="k1")  # no vault
    token = p1.pseudonymize("ana@example.com", domain="email")
    p2 = Pseudonymizer({"k1": KEY1}, active_key_id="k1", vault=InMemoryVault())
    with pytest.raises(PseudoError) as exc:
        p2.reidentify(token)
    assert exc.value.code == "not_in_vault"


def test_error_messages_do_not_leak_secrets() -> None:
    value = "secret-value"
    with pytest.raises(PseudoError) as exc:
        Pseudonymizer({"k1": KEY1}, active_key_id="k1").pseudonymize(value * 1000, domain="email")
    assert value not in str(exc.value)
    assert str(exc.value).count("a") < 200  # only the repeated 'a' not the actual value


def test_cli_success(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from pseudonymizer import __main__ as cli

    monkeypatch.setenv("PSEUDO_KEY", KEY1.hex())
    monkeypatch.setattr("sys.stdin", StringIO("ana@example.com\n\nplane@example.com\n"))
    exit_code = cli.main(["--key-env", "PSEUDO_KEY", "--key-id", "k1", "--domain", "email"])
    captured = capsys.readouterr()
    assert exit_code == 0
    lines = captured.out.splitlines()
    assert len(lines) == 2
    assert lines[0] == "pz_k1_wktl6nutd3rd4p2xsepvga2sid"
    assert lines[1].startswith("pz_k1_")


def test_cli_missing_key_env(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from pseudonymizer import __main__ as cli

    monkeypatch.delenv("PSEUDO_KEY", raising=False)
    monkeypatch.setattr("sys.stdin", StringIO(""))
    exit_code = cli.main(["--key-env", "PSEUDO_KEY", "--key-id", "k1", "--domain", "email"])
    captured = capsys.readouterr()
    assert exit_code == 2
    assert "missing key" in captured.err


def test_cli_invalid_value(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from pseudonymizer import __main__ as cli

    monkeypatch.setenv("PSEUDO_KEY", KEY1.hex())
    long_value = "a" * 4097 + "\n"
    monkeypatch.setattr("sys.stdin", StringIO(long_value))
    exit_code = cli.main(["--key-env", "PSEUDO_KEY", "--key-id", "k1", "--domain", "email"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert long_value not in captured.err


def test_cli_usage_error() -> None:
    from pseudonymizer import __main__ as cli

    exit_code = cli.main([])
    assert exit_code == 2
