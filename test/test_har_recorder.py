import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import ibm_cloud_sdk_core.har_recorder as har


@pytest.fixture(autouse=True)
def reset_har_state(monkeypatch):
    har._reset_har_state_for_test()
    monkeypatch.delenv("HAR_ENABLED", raising=False)
    monkeypatch.delenv("HAR_FILE_PATH", raising=False)
    yield
    har._reset_har_state_for_test()


def test_har_enabled_reads_env(tmp_path, monkeypatch):
    monkeypatch.setenv("HAR_ENABLED", "1")
    monkeypatch.setenv("HAR_FILE_PATH", str(tmp_path / "custom.har"))
    assert har.HAREnabled()


def test_redact_secret_value_markers():
    text = (
        "bearer token: Bearer abc "  # pragma: allowlist secret
        "basic auth: Basic xyz "  # pragma: allowlist secret
        "iam_token: iam_token:foo "  # pragma: allowlist secret
        "access_token: access_token=bar "  # pragma: allowlist secret
        "session token: session-token baz "  # pragma: allowlist secret
        "token: token qux "  # pragma: allowlist secret
        "password: password=secret "  # pragma: allowlist secret
        "apikey: apikey:abc "  # pragma: allowlist secret
        "secret: secret=sauce "  # pragma: allowlist secret
        "cookie=verylongcookievalue"  # pragma: allowlist secret
    )
    redacted = har._redact_secret_value(text)
    for marker in [
        "[REDACTED_BEARER_TOKEN]",
        "[REDACTED_BASIC_AUTH]",
        "[REDACTED_IAM_TOKEN]",
        "[REDACTED_ACCESS_TOKEN]",
        "[REDACTED_SESSION_TOKEN]",
        "[REDACTED_TOKEN]",
        "[REDACTED_PASSWORD]",
        "[REDACTED_API_KEY]",
        "[REDACTED_SECRET]",
        "[REDACTED_COOKIE]",
    ]:
        assert marker in redacted


def test_redact_json_secrets_labels_specific_tokens():
    payload = {
        "token": "longtokenvalue" * 3,  # pragma: allowlist secret
        "access_token": "a" * 60,  # pragma: allowlist secret
        "session_token": "s" * 60,  # pragma: allowlist secret
        "iam_token": "i" * 60,  # pragma: allowlist secret
        "nested": {"password": "hunter2", "api_key": "k" * 60},  # pragma: allowlist secret
    }
    redacted = json.loads(har._redact_json_secrets(json.dumps(payload)))
    assert redacted["token"] == "[REDACTED_TOKEN]"
    assert redacted["access_token"] == "[REDACTED_ACCESS_TOKEN]"
    assert redacted["session_token"] == "[REDACTED_SESSION_TOKEN]"
    assert redacted["iam_token"] == "[REDACTED_IAM_TOKEN]"
    assert redacted["nested"]["password"] == "[REDACTED_PASSWORD]"
    assert redacted["nested"]["api_key"] == "[REDACTED_API_KEY]"


def test_process_body_content_binary_and_text():
    text_body = b'{"user":"john","password":"top-secret"}'  # pragma: allowlist secret
    text, encoding = har._process_body_content(text_body, True, "application/json")
    assert encoding == ""
    assert "[REDACTED_PASSWORD]" in text

    binary_body = bytes([0x89, 0x50, 0x4E, 0x47])
    text, encoding = har._process_body_content(binary_body, False, "")
    assert encoding == "base64"
    assert text

    empty_text, empty_enc = har._process_body_content(b"", False, "")
    assert empty_text == empty_enc == ""


def test_is_binary_content_detection():
    assert har._is_binary_content(b"plain text") is False
    assert har._is_binary_content(bytes([0x89, 0x50, 0x4E, 0x47])) is True


def test_convert_headers_redacts_sensitive():
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer secret",  # pragma: allowlist secret
        "X-API-Key": "shouldstay",
    }
    converted = har._convert_headers(headers, is_request=True)
    values = {nv.name: nv.value for nv in converted}
    assert "[REDACTED_BEARER_TOKEN]" in values["Authorization"]
    assert values["Content-Type"] == "application/json"
    assert values["X-API-Key"] == "shouldstay"


def test_build_har_entry_and_write(tmp_path, monkeypatch):
    monkeypatch.setenv("HAR_ENABLED", "1")
    monkeypatch.setenv("HAR_FILE_PATH", str(tmp_path / "capture.har"))
    har._reset_har_state_for_test()
    har.HAREnabled()

    req = SimpleNamespace(
        method="POST",
        url="https://example.com?token=abc",
        headers={"Content-Type": "application/json"},
        http_version="HTTP/1.1",
    )
    resp = SimpleNamespace(status_code=200, reason="OK", headers={"X-Test": "value"})
    start = datetime.now(timezone.utc)
    end = start + timedelta(milliseconds=100)

    har.HARAppendWithCopies(
        req=req,
        resp=resp,
        start_time=start,
        end_time=end,
        call_err=None,
        req_body=b'{"token":"abc"}',
        resp_body=b"response",
        req_content_type="application/json",
        resp_content_type="text/plain",
    )

    archive = json.loads(Path(tmp_path / "capture.har").read_text())
    assert archive["log"]["entries"]
    entry = archive["log"]["entries"][0]
    assert entry["response"]["status"] == 200
    assert "[REDACTED_TOKEN]" in entry["request"]["postData"]["text"]


def test_rotation_resets_entries(tmp_path, monkeypatch):
    monkeypatch.setenv("HAR_ENABLED", "1")
    monkeypatch.setenv("HAR_FILE_PATH", str(tmp_path / "rotate.har"))
    har._reset_har_state_for_test()
    har.HAREnabled()

    recorder = har.HARRecorder(Path(os.environ["HAR_FILE_PATH"]))
    monkeypatch.setattr(har, "HAR_MAX_ENTRIES", 2)

    entry = har._build_har_entry(
        SimpleNamespace(method="GET", url="http://example.com", headers={}),
        None,
        datetime.now(timezone.utc),
        datetime.now(timezone.utc),
        None,
        b"",
        b"",
        "",
        "",
    )

    with recorder._lock:
        recorder.append(entry)
        recorder.append(entry)
        recorder.append(entry)

    archive = json.loads(Path(os.environ["HAR_FILE_PATH"]).read_text())
    assert len(archive["log"]["entries"]) == 1
