from secrets_precommit.baseline import Baseline, fingerprint


def test_fingerprint_is_stable():
    a = fingerprint("aws-access-key-id", "a/b.py", "AKIAIOSFODNN7ABCDE01")
    b = fingerprint("aws-access-key-id", "a/b.py", "AKIAIOSFODNN7ABCDE01")
    assert a == b


def test_fingerprint_path_separator_normalised():
    a = fingerprint("r", "a/b.py", "s")
    b = fingerprint("r", "a\\b.py", "s")
    assert a == b


def test_fingerprint_changes_with_secret():
    a = fingerprint("r", "p", "secret-one")
    b = fingerprint("r", "p", "secret-two")
    assert a != b


def test_save_and_load_roundtrip(tmp_path):
    path = tmp_path / ".secrets-baseline.json"
    bl = Baseline({"aaaa", "bbbb"})
    bl.save(path)
    loaded = Baseline.load(path)
    assert loaded.fingerprints == {"aaaa", "bbbb"}


def test_load_missing_is_empty(tmp_path):
    assert Baseline.load(tmp_path / "nope.json").fingerprints == set()
