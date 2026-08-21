import json

from secrets_precommit.cli import main


def _write(p, content):
    p.write_text(content)
    return str(p)


def test_scan_returns_nonzero_on_finding(tmp_path, capsys):
    f = _write(tmp_path / "leak.env", 'aws = "AKIAIOSFODNN7ABCDE01"')
    rc = main(["scan", f])
    assert rc == 1
    assert "potential secret" in capsys.readouterr().err


def test_scan_returns_zero_when_clean(tmp_path):
    f = _write(tmp_path / "ok.py", "print('hello world')\n")
    assert main(["scan", f]) == 0


def test_scan_honours_allowlist_file(tmp_path):
    al = _write(tmp_path / "al.yaml", "regexes:\n  - AKIAIOSFODNN7EXAMPLE\n")
    f = _write(tmp_path / "docs.md", 'key = "AKIAIOSFODNN7EXAMPLE"')
    assert main(["scan", "--allowlist", al, f]) == 0


def test_baseline_then_scan_is_clean(tmp_path):
    f = _write(tmp_path / "legacy.env", 'ghp = "ghp_%s"' % ("a" * 36))
    base = str(tmp_path / ".secrets-baseline.json")
    assert main(["baseline", "--baseline", base, f]) == 0
    data = json.loads((tmp_path / ".secrets-baseline.json").read_text())
    assert len(data["fingerprints"]) == 1
    assert main(["scan", "--baseline", base, f]) == 0


def test_baseline_does_not_hide_new_secret(tmp_path):
    f = _write(tmp_path / "legacy.env", 'old = "ghp_%s"' % ("a" * 36))
    base = str(tmp_path / ".secrets-baseline.json")
    main(["baseline", "--baseline", base, f])
    # A brand new secret appears -> must still fail.
    f2 = _write(tmp_path / "new.env", 'new = "AKIAIOSFODNN7ABCDE01"')
    assert main(["scan", "--baseline", base, f, f2]) == 1


def test_scan_directory_recurses(tmp_path):
    (tmp_path / "sub").mkdir()
    _write(tmp_path / "sub" / "leak.env", 'aws = "AKIAIOSFODNN7ABCDE01"')
    assert main(["scan", str(tmp_path)]) == 1


def test_scan_directory_skips_git_internals(tmp_path):
    # A clone's .git/config holds the auth token in the remote URL; walking it
    # would flag the scanner's own machinery. It must be skipped.
    git = tmp_path / ".git"
    git.mkdir()
    _write(git / "config", "url = https://user:ghp_%s@github.com/x" % ("a" * 36))
    assert main(["scan", str(tmp_path)]) == 0
