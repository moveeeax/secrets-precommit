from secrets_precommit.allowlist import Allowlist
from secrets_precommit.baseline import Baseline
from secrets_precommit.scanner import scan_paths, scan_text


def test_detects_aws_access_key():
    text = 'aws_key = "AKIAIOSFODNN7ABCDE01"'
    findings = scan_text(text, "config.py", Allowlist.empty())
    assert any(f.rule_id == "aws-access-key-id" for f in findings)


def test_detects_github_token():
    text = "token: ghp_" + "a" * 36
    findings = scan_text(text, "x.env", Allowlist.empty())
    assert any(f.rule_id == "github-token" for f in findings)


def test_detects_private_key_header():
    findings = scan_text("-----BEGIN RSA PRIVATE KEY-----", "id_rsa", Allowlist.empty())
    assert any(f.rule_id == "private-key" for f in findings)


def test_generic_assigned_secret():
    findings = scan_text('password = "hunter2hunter2"', "app.py", Allowlist.empty())
    assert any(f.rule_id == "generic-assigned-secret" for f in findings)


def test_clean_text_has_no_findings():
    text = "def add(a, b):\n    return a + b\n"
    assert scan_text(text, "math.py", Allowlist.empty()) == []


def test_allowlist_value_suppresses():
    text = 'aws_key = "AKIAIOSFODNN7EXAMPLE"'
    al = Allowlist.from_dict({"regexes": ["AKIAIOSFODNN7EXAMPLE"]})
    assert scan_text(text, "docs.md", al) == []


def test_line_numbers_are_reported():
    text = "clean line\nother line\ntoken = 'ghp_%s'" % ("b" * 36)
    findings = scan_text(text, "f.py", Allowlist.empty())
    assert findings and findings[0].line == 3


def test_scan_paths_skips_allowlisted_path(tmp_path):
    f = tmp_path / "fixture.txt"
    f.write_text("AKIAIOSFODNN7ABCDE01")
    al = Allowlist.from_dict({"paths": ["*.txt"]})
    assert scan_paths([str(f)], al) == []


def test_scan_paths_skips_binary(tmp_path):
    f = tmp_path / "blob.bin"
    f.write_bytes(b"\x00\x01AKIAIOSFODNN7ABCDE01\x00")
    assert scan_paths([str(f)], Allowlist.empty()) == []


def test_scan_paths_respects_baseline(tmp_path):
    f = tmp_path / "leak.env"
    f.write_text('token = "ghp_%s"' % ("c" * 36))
    first = scan_paths([str(f)], Allowlist.empty())
    assert first, "should detect before baselining"
    bl = Baseline({fnd.fingerprint for fnd in first})
    assert scan_paths([str(f)], Allowlist.empty(), bl) == []


def test_redaction_hides_middle():
    findings = scan_text("token: ghp_" + "d" * 36, "x", Allowlist.empty())
    red = findings[0].redacted()
    assert "…" in red and len(red) < 40
