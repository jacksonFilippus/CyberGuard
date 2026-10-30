import io

from scanners.email_scanner import analyse_email
from scanners.url_scanner import analyse_url
from scanners.file_scanner import analyse_file


def test_url_rejects_unsupported_scheme():
    result = analyse_url("javascript:alert(1)")
    assert result["valid"] is False


def test_url_accepts_https_and_returns_result():
    result = analyse_url("https://example.com")
    assert result["valid"] is True
    assert "score" in result
    assert 0 <= result["score"] <= 10


def test_url_flags_plain_http():
    result = analyse_url("http://example.com")
    assert result["valid"] is True
    assert any("HTTP" in finding for finding in result["findings"])


def test_email_detects_urgent_sensitive_request():
    result = analyse_email(
        "unknown@example.net",
        "Urgent account verification",
        "Your account will be suspended. Send your password immediately."
    )
    assert result["score"] > 0
    assert result["findings"]


def test_file_hash_is_sha256():
    class Upload:
        filename = "sample.txt"
        stream = io.BytesIO(b"CyberGuard test")

    result = analyse_file(Upload())
    assert len(result["sha256"]) == 64
    assert result["size"] == len(b"CyberGuard test")


def test_file_rejects_empty_upload():
    class Upload:
        filename = "empty.txt"
        stream = io.BytesIO(b"")

    try:
        analyse_file(Upload())
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "empty" in str(exc).lower()
