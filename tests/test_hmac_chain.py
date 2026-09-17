import pytest

from zaynor.hmac_chain import compute_entry_hmac, resolve_hmac_key


def test_no_key_configured_resolves_to_none(monkeypatch):
    monkeypatch.delenv("ZAYNOR_HMAC_KEY", raising=False)
    monkeypatch.delenv("ZAYNOR_HMAC_KEY_FILE", raising=False)
    assert resolve_hmac_key() is None


def test_resolves_hex_key_from_env(monkeypatch):
    monkeypatch.setenv("ZAYNOR_HMAC_KEY", "aa" * 32)
    monkeypatch.delenv("ZAYNOR_HMAC_KEY_FILE", raising=False)
    assert resolve_hmac_key() == bytes.fromhex("aa" * 32)


def test_invalid_hex_key_falls_back_to_file(monkeypatch, tmp_path):
    key_file = tmp_path / "key.bin"
    key_file.write_bytes(b"raw-key-bytes")
    key_file.chmod(0o600)
    monkeypatch.setenv("ZAYNOR_HMAC_KEY", "not-valid-hex")
    monkeypatch.setenv("ZAYNOR_HMAC_KEY_FILE", str(key_file))
    assert resolve_hmac_key() == b"raw-key-bytes"


def test_resolves_key_from_file(monkeypatch, tmp_path):
    key_file = tmp_path / "key.bin"
    key_file.write_bytes(b"  raw-key-bytes  \n")
    key_file.chmod(0o600)
    monkeypatch.delenv("ZAYNOR_HMAC_KEY", raising=False)
    monkeypatch.setenv("ZAYNOR_HMAC_KEY_FILE", str(key_file))
    assert resolve_hmac_key() == b"raw-key-bytes"


def test_compute_entry_hmac_is_deterministic_and_key_sensitive():
    a = compute_entry_hmac(b"key-a", "somehash")
    a_again = compute_entry_hmac(b"key-a", "somehash")
    b = compute_entry_hmac(b"key-b", "somehash")
    assert a == a_again
    assert a != b
    assert len(a) == 64
