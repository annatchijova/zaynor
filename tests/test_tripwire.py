from zaynor.agents.tripwire import generate_tripwire, tripwire_triggered


def test_tripwire_is_deterministic_for_the_same_case_and_seal(monkeypatch):
    monkeypatch.setenv("ZAYNOR_TRIPWIRE_SALT", "test-salt")
    a = generate_tripwire("CASE-1", "abc123")
    b = generate_tripwire("CASE-1", "abc123")
    assert a.protocol_id == b.protocol_id
    assert a.salt_source == "env"


def test_tripwire_differs_across_cases_and_seals(monkeypatch):
    monkeypatch.setenv("ZAYNOR_TRIPWIRE_SALT", "test-salt")
    a = generate_tripwire("CASE-1", "abc123")
    b = generate_tripwire("CASE-2", "abc123")
    c = generate_tripwire("CASE-1", "def456")
    assert a.protocol_id != b.protocol_id
    assert a.protocol_id != c.protocol_id


def test_tripwire_falls_back_honestly_without_a_salt(monkeypatch):
    monkeypatch.delenv("ZAYNOR_TRIPWIRE_SALT", raising=False)
    tw = generate_tripwire("CASE-1", "abc123")
    assert tw.salt_source == "fallback"


def test_tripwire_id_appears_in_its_own_instruction_text(monkeypatch):
    monkeypatch.setenv("ZAYNOR_TRIPWIRE_SALT", "test-salt")
    tw = generate_tripwire("CASE-1", "abc123")
    assert tw.protocol_id in tw.instruction


def test_tripwire_triggered_detects_the_exact_protocol_id(monkeypatch):
    monkeypatch.setenv("ZAYNOR_TRIPWIRE_SALT", "test-salt")
    tw = generate_tripwire("CASE-1", "abc123")
    assert tripwire_triggered(f"TRIPWIRE_TRIGGERED:{tw.protocol_id}", tw)
    assert not tripwire_triggered("The result is ABSTAIN.", tw)


def test_tripwire_is_not_triggered_by_a_similar_but_wrong_id(monkeypatch):
    monkeypatch.setenv("ZAYNOR_TRIPWIRE_SALT", "test-salt")
    tw = generate_tripwire("CASE-1", "abc123")
    guessed = "ZAYNOR_TRIPWIRE_0000000000000000"
    assert guessed != tw.protocol_id
    assert not tripwire_triggered(f"TRIPWIRE_TRIGGERED:{guessed}", tw)
