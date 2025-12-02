"""HAR recording helpers aligned with the Go SDK implementation."""
from __future__ import annotations

import base64
import json
import logging
import os
import re
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .version import __version__

logger = logging.getLogger(__name__)

HAR_MAX_ENTRIES = 10_000
HAR_BINARY_THRESHOLD = 0.05

# Regex patterns for redacting secrets in non-JSON content.
_BEARER_TOKEN_PATTERN = re.compile(r"(?i)(bearer\s+)([a-zA-Z0-9\-._~+/]+=*)")
_BASIC_AUTH_PATTERN = re.compile(r"(?i)(basic\s+)([a-zA-Z0-9+/]+=*)")
_API_KEY_PATTERN = re.compile(r"(?i)(apikey[\s:=]+)([a-zA-Z0-9\-._~+/]+)")
_TOKEN_PATTERN = re.compile(r"(?i)(token[\s:=]+)([a-zA-Z0-9\-._~+/]+)")
_IAM_TOKEN_PATTERN = re.compile(r"(?i)(iam[_-]?token[\s:=]+)([a-zA-Z0-9\-._~+/]+)")
_ACCESS_TOKEN_PATTERN = re.compile(r"(?i)(access[_-]?token[\s:=]+)([a-zA-Z0-9\-._~+/]+)")
_SESSION_TOKEN_PATTERN = re.compile(r"(?i)(session[_-]?token[\s:=]+)([a-zA-Z0-9\-._~+/]+)")
_PASSWORD_PATTERN = re.compile(r"(?i)(password[\s:=]+)([^\s&\"'<>]+)")
_SECRET_PATTERN = re.compile(r"(?i)(secret[\s:=]+)([a-zA-Z0-9\-._~+/]+)")
_COOKIE_PATTERN = re.compile(r"(?i)(=[^;,\s]{8,})(;|,|$)")

_REDACTED_TOKENS = "|".join(
    [
        "authorization",
        r"x-auth\S*",
        "apikey",
        "api_key",
        "passcode",
        "password",
        "token",
        "client_id",
        "client_x509_cert_url",
        "key",
        "project_id",
        "secret",
        "subscriptionid",
        "tenantid",
        "thumbprint",
        "token_uri",
        "aadclientid",
        "aadclientsecret",
        "auth",
        "auth_provider_x509_cert_url",
        "auth_uri",
        "client_email",
    ]
)
_AUTH_HEADER_RE = re.compile(r"(?m)^(Authorization|X-Auth\S*): .*")
_PROPERTY_SETTING_RE = re.compile(rf"({_REDACTED_TOKENS})=[^&]*(&|$)", re.IGNORECASE)
_JSON_FIELD_RE = re.compile(rf"\"([^\"]*({_REDACTED_TOKENS})[^\"]*)\":\s*\"[^\\,]*\"", re.IGNORECASE)

_har_enabled: bool | None = None
_har_file_path: Path | None = None
_har_once = threading.Lock()


@dataclass
class HARNameValue:
    name: str
    value: str


@dataclass
class HARPostDataParam:
    name: str
    value: str | None = None


@dataclass
class HARPostData:
    mimeType: str
    text: str | None = None
    params: list[HARPostDataParam] = field(default_factory=list)


@dataclass
class HARRequest:
    method: str
    url: str
    httpVersion: str
    headers: list[HARNameValue]
    queryString: list[HARNameValue]
    postData: HARPostData | None
    headersSize: int
    bodySize: int


@dataclass
class HARContent:
    size: int
    mimeType: str
    text: str | None = None
    encoding: str | None = None


@dataclass
class HARResponse:
    status: int
    statusText: str
    httpVersion: str
    headers: list[HARNameValue]
    content: HARContent
    redirectURL: str
    headersSize: int
    bodySize: int


@dataclass
class HARTimings:
    send: float
    wait: float
    receive: float


@dataclass
class HAREntry:
    pageref: str
    startedDateTime: str
    time: float
    request: HARRequest
    response: HARResponse
    cache: dict
    timings: HARTimings
    serverIPAddress: str | None = None
    connection: str | None = None


@dataclass
class HARCreator:
    name: str
    version: str


@dataclass
class HARLog:
    version: str
    creator: HARCreator
    pages: list[dict]
    entries: list[HAREntry]


@dataclass
class HARArchive:
    log: HARLog


class HARRecorder:
    """Thread-safe HAR recorder compatible with the Go SDK behavior."""

    def __init__(self, file_path: Path | None = None) -> None:
        self.file_path = file_path or _get_har_file_path()
        self._lock = threading.Lock()

    def append(self, entry: HAREntry) -> None:
        archive = self._read_or_create()
        if len(archive.log.entries) >= HAR_MAX_ENTRIES:
            logger.warning("HAR file reached maximum entries (%d), rotating...", HAR_MAX_ENTRIES)
            _rotate_har_file(self.file_path)
            archive = _create_new_archive()
        archive.log.entries.append(entry)
        self._write_archive(archive)

    def _read_or_create(self) -> HARArchive:
        try:
            data = self.file_path.read_bytes()
        except Exception:
            return _create_new_archive()
        if not data:
            return _create_new_archive()
        try:
            payload = json.loads(data.decode("utf-8"))
            return _archive_from_dict(payload)
        except Exception as exc:
            logger.warning("Failed to parse existing HAR file, creating new: %s", exc)
            return _create_new_archive()

    def _write_archive(self, archive: HARArchive) -> None:
        try:
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            data = json.dumps(_archive_to_dict(archive), indent=2)
            fd = os.open(self.file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(data)
        except Exception as exc:
            logger.error("Failed to write HAR file: %s", exc)


class HARBodyCapture:
    def __init__(self, raw: Any, capture: Any) -> None:
        self.raw = raw
        self.capture = capture

    def read(self, amt: int | None = None, decode_content: bool | None = None) -> bytes:  # pragma: no cover - passthrough
        data = self.raw.read(amt, decode_content=decode_content) if decode_content is not None else self.raw.read(amt)
        if data:
            self.capture.write(data)
        return data

    def stream(self, amt: int = 2**16, decode_content: bool | None = None) -> Iterable[bytes]:  # pragma: no cover
        generator = self.raw.stream(amt, decode_content=decode_content) if decode_content is not None else self.raw.stream(amt)
        for chunk in generator:
            if chunk:
                self.capture.write(chunk)
            yield chunk

    def __getattr__(self, item: str) -> Any:  # pragma: no cover - delegation
        return getattr(self.raw, item)


def HAREnabled() -> bool:
    global _har_enabled, _har_file_path
    if _har_enabled is None:
        with _har_once:
            if _har_enabled is None:
                _har_enabled = os.getenv("HAR_ENABLED") == "1"
                if _har_enabled:
                    custom = os.getenv("HAR_FILE_PATH")
                    _har_file_path = Path(custom) if custom else Path(tempfile.gettempdir()) / "ibm-go-sdk-core.har"
                    logger.info("HAR recording enabled, writing to: %s", _har_file_path)
    return bool(_har_enabled)


def HARAppendWithCopies(
    req: Any,
    resp: Any,
    start_time: datetime,
    end_time: datetime,
    call_err: Exception | None,
    req_body: bytes,
    resp_body: bytes,
    req_content_type: str,
    resp_content_type: str,
) -> None:
    if not HAREnabled() or req is None:
        return
    try:
        entry = _build_har_entry(
            req,
            resp,
            start_time,
            end_time,
            call_err,
            req_body or b"",
            resp_body or b"",
            req_content_type or "",
            resp_content_type or "",
        )
        recorder = HARRecorder()
        with recorder._lock:
            recorder.append(entry)
    except Exception:
        logger.debug("HAR recording failed", exc_info=True)


def _build_har_entry(
    req: Any,
    resp: Any,
    start_time: datetime,
    end_time: datetime,
    call_err: Exception | None,
    req_body: bytes,
    resp_body: bytes,
    req_content_type: str,
    resp_content_type: str,
) -> HAREntry:
    duration_ms = float(max(0, int((end_time - start_time).total_seconds() * 1000)))
    request = _build_har_request(req, req_body, req_content_type)
    response = _build_har_response(resp, call_err, resp_body, resp_content_type, req)
    return HAREntry(
        pageref="page_1",
        startedDateTime=start_time.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        time=duration_ms,
        request=request,
        response=response,
        cache={},
        timings=HARTimings(send=-1, wait=duration_ms, receive=-1),
    )


def _build_har_request(req: Any, body: bytes, content_type: str) -> HARRequest:
    headers = _convert_headers(getattr(req, "headers", {}) or {}, is_request=True)
    query = _convert_query(getattr(req, "url", ""))
    http_version = _get_http_version(getattr(req, "http_version", None) or getattr(req, "version", None) or getattr(req, "version", ""))
    if hasattr(req, "path_url") and not getattr(req, "url", ""):
        # requests PreparedRequest stores path_url without scheme; prefer url when available
        pass
    post_data = None
    if body:
        text, encoding = _process_body_content(body, True, content_type)
        if text or encoding:
            post_data = HARPostData(mimeType=content_type, text=text)
    return HARRequest(
        method=getattr(req, "method", ""),
        url=str(getattr(req, "url", "")),
        httpVersion=http_version,
        headers=headers,
        queryString=query,
        postData=post_data,
        headersSize=-1,
        bodySize=len(body),
    )


def _build_har_response(resp: Any, call_err: Exception | None, body: bytes, content_type: str, req: Any) -> HARResponse:
    status = _get_status_code(resp, call_err)
    status_text = _get_status_text(resp, call_err)
    headers = _convert_headers(_get_response_headers(resp), is_request=False)
    if resp is not None and not content_type:
        content_type = (resp.headers.get("Content-Type") if getattr(resp, "headers", None) else "") or ""
    text, encoding = _process_body_content(body, False, content_type)
    redirect_url = ""
    try:
        if resp is not None and 300 <= getattr(resp, "status_code", 0) < 400:
            redirect_url = resp.headers.get("Location", "") if getattr(resp, "headers", None) else ""
    except Exception:
        redirect_url = ""
    return HARResponse(
        status=status,
        statusText=status_text,
        httpVersion=_get_response_http_version(resp, req),
        headers=headers,
        content=HARContent(size=len(body), mimeType=content_type, text=text, encoding=encoding or None),
        redirectURL=redirect_url,
        headersSize=-1,
        bodySize=len(body),
    )


def _convert_headers(headers: Mapping[str, Any], *, is_request: bool) -> list[HARNameValue]:
    if not headers:
        return []
    result: list[HARNameValue] = []
    for name, value in headers.items():
        values: Iterable[str]
        if isinstance(value, (list, tuple)):
            values = [str(v) for v in value]
        else:
            values = [str(value)]
        for val in values:
            if _is_sensitive_header(name):
                val = _redact_secret_value(val)
            result.append(HARNameValue(name=name, value=val))
    return result


def _convert_query(url: str) -> list[HARNameValue]:
    from urllib.parse import parse_qsl, urlparse

    parsed = urlparse(url) if url else None
    if not parsed or not parsed.query:
        return []
    result: list[HARNameValue] = []
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        result.append(HARNameValue(name=name, value=value))
    return result


def _process_body_content(body: bytes, is_request: bool, content_type: str) -> tuple[str, str]:
    if not body:
        return "", ""
    if _is_binary_content(body):
        return base64.b64encode(body).decode("ascii"), "base64"
    text = body.decode("utf-8", errors="replace")
    lowered = (content_type or "").lower()
    if "json" in lowered or text.strip().startswith("{") or text.strip().startswith("["):
        redacted_json = _redact_json_secrets(text)
        if redacted_json:
            return redacted_json, ""
    text = _redact_secret_value(text)
    text = _redact_generic_secrets(text)
    return text, ""


def _redact_json_secrets(json_text: str) -> str:
    try:
        data = json.loads(json_text)
    except Exception:
        return ""
    redacted = _redact_json_value(data)
    try:
        return json.dumps(redacted, indent=2)
    except Exception:
        return ""


def _redact_json_value(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            lower_key = key.lower()
            if _is_sensitive_json_key(lower_key):
                result[key] = _get_redaction_label(lower_key)
            else:
                result[key] = _redact_json_value(item)
        return result
    if isinstance(value, list):
        return [_redact_json_value(v) for v in value]
    if isinstance(value, str):
        if _looks_like_token(value):
            return "[REDACTED_TOKEN]"
        return value
    return value


def _is_sensitive_json_key(key: str) -> bool:
    for sensitive in [
        "token",
        "apikey",
        "api_key",
        "password",
        "secret",
        "authorization",
        "auth",
        "credential",
        "access_token",
        "refresh_token",
        "session_token",
        "bearer",
        "api-key",
        "iam_token",
        "session_id",
        "cookie",
        "sessionid",
    ]:
        if sensitive in key:
            return True
    return False


def _get_redaction_label(key: str) -> str:
    if "bearer" in key:
        return "[REDACTED_BEARER_TOKEN]"
    if "apikey" in key or "api_key" in key or "api-key" in key:
        return "[REDACTED_API_KEY]"
    if "password" in key:
        return "[REDACTED_PASSWORD]"
    if "secret" in key:
        return "[REDACTED_SECRET]"
    if "iam_token" in key or "iam-token" in key:
        return "[REDACTED_IAM_TOKEN]"
    if "access_token" in key or "access-token" in key:
        return "[REDACTED_ACCESS_TOKEN]"
    if "session" in key:
        return "[REDACTED_SESSION_TOKEN]"
    if "cookie" in key:
        return "[REDACTED_COOKIE]"
    return "[REDACTED_TOKEN]"


def _looks_like_token(value: str) -> bool:
    if len(value) > 32 and re.fullmatch(r"[A-Za-z0-9\-._~+/]+=*", value):
        return True
    if value.count(".") == 2 and len(value) > 50:
        return True
    return False


def _redact_secret_value(value: str) -> str:
    value = _BEARER_TOKEN_PATTERN.sub(r"\1[REDACTED_BEARER_TOKEN]", value)
    value = _BASIC_AUTH_PATTERN.sub(r"\1[REDACTED_BASIC_AUTH]", value)
    value = _API_KEY_PATTERN.sub(r"\1[REDACTED_API_KEY]", value)
    value = _IAM_TOKEN_PATTERN.sub(r"\1[REDACTED_IAM_TOKEN]", value)
    value = _ACCESS_TOKEN_PATTERN.sub(r"\1[REDACTED_ACCESS_TOKEN]", value)
    value = _SESSION_TOKEN_PATTERN.sub(r"\1[REDACTED_SESSION_TOKEN]", value)
    value = _TOKEN_PATTERN.sub(r"\1[REDACTED_TOKEN]", value)
    value = _PASSWORD_PATTERN.sub(r"\1[REDACTED_PASSWORD]", value)
    value = _SECRET_PATTERN.sub(r"\1[REDACTED_SECRET]", value)
    value = _COOKIE_PATTERN.sub(r"=[REDACTED_COOKIE]\2", value)
    return value


def _redact_generic_secrets(value: str) -> str:
    redacted = "[redacted]"
    value = _AUTH_HEADER_RE.sub(r"\1: " + redacted, value)
    value = _PROPERTY_SETTING_RE.sub(r"\1=" + redacted + r"\2", value)
    value = _JSON_FIELD_RE.sub(rf'"\1":"{redacted}"', value)
    return value


def _is_binary_content(data: bytes) -> bool:
    if not data:
        return False
    sample = data[: min(len(data), 8192)]
    non_printable = 0
    for b in sample:
        if b in (9, 10, 13):
            continue
        if b < 32 or b > 126:
            non_printable += 1
    ratio = non_printable / len(sample)
    return ratio > HAR_BINARY_THRESHOLD


def _is_sensitive_header(name: str) -> bool:
    lower = name.lower()
    for pattern in [
        "authorization",
        "cookie",
        "set-cookie",
        "token",
        "apikey",
        "api-key",
        "secret",
        "password",
        "credential",
        "session",
        "x-auth",
        "x-api",
    ]:
        if pattern in lower:
            return True
    return False


def _archive_from_dict(data: Mapping[str, Any]) -> HARArchive:
    creator_data = data.get("log", {}).get("creator", {})
    creator = HARCreator(name=creator_data.get("name", ""), version=creator_data.get("version", ""))
    entries: list[HAREntry] = []
    for item in data.get("log", {}).get("entries", []):
        entry = HAREntry(
            pageref=item.get("pageref", ""),
            startedDateTime=item.get("startedDateTime", ""),
            time=float(item.get("time", 0.0)),
            request=_dict_to_request(item.get("request", {})),
            response=_dict_to_response(item.get("response", {})),
            cache=item.get("cache", {}),
            timings=HARTimings(**item.get("timings", {})),
            serverIPAddress=item.get("serverIPAddress"),
            connection=item.get("connection"),
        )
        entries.append(entry)
    log = HARLog(
        version=data.get("log", {}).get("version", "1.2"),
        creator=creator,
        pages=data.get("log", {}).get("pages", []),
        entries=entries,
    )
    return HARArchive(log=log)


def _create_new_archive() -> HARArchive:
    creator = HARCreator(name="ibm-python-sdk-core", version=__version__)
    log = HARLog(version="1.2", creator=creator, pages=[], entries=[])
    return HARArchive(log=log)


def _dict_to_request(data: Mapping[str, Any]) -> HARRequest:
    headers = [HARNameValue(**h) for h in data.get("headers", [])]
    query = [HARNameValue(**q) for q in data.get("queryString", [])]
    post = data.get("postData")
    post_data = None
    if post:
        params = [HARPostDataParam(**p) for p in post.get("params", [])]
        post_data = HARPostData(mimeType=post.get("mimeType", ""), text=post.get("text"), params=params)
    return HARRequest(
        method=data.get("method", ""),
        url=data.get("url", ""),
        httpVersion=data.get("httpVersion", "HTTP/1.1"),
        headers=headers,
        queryString=query,
        postData=post_data,
        headersSize=int(data.get("headersSize", -1)),
        bodySize=int(data.get("bodySize", -1)),
    )


def _dict_to_response(data: Mapping[str, Any]) -> HARResponse:
    headers = [HARNameValue(**h) for h in data.get("headers", [])]
    content_data = data.get("content", {})
    content = HARContent(
        size=int(content_data.get("size", 0)),
        mimeType=content_data.get("mimeType", ""),
        text=content_data.get("text"),
        encoding=content_data.get("encoding"),
    )
    return HARResponse(
        status=int(data.get("status", 0)),
        statusText=data.get("statusText", ""),
        httpVersion=data.get("httpVersion", "HTTP/1.1"),
        headers=headers,
        content=content,
        redirectURL=data.get("redirectURL", ""),
        headersSize=int(data.get("headersSize", -1)),
        bodySize=int(data.get("bodySize", -1)),
    )


def _archive_to_dict(archive: HARArchive) -> dict:
    return {
        "log": {
            "version": archive.log.version,
            "creator": archive.log.creator.__dict__,
            "pages": archive.log.pages,
            "entries": [
                {
                    "pageref": e.pageref,
                    "startedDateTime": e.startedDateTime,
                    "time": e.time,
                    "request": _request_to_dict(e.request),
                    "response": _response_to_dict(e.response),
                    "cache": e.cache,
                    "timings": e.timings.__dict__,
                    **({"serverIPAddress": e.serverIPAddress} if e.serverIPAddress else {}),
                    **({"connection": e.connection} if e.connection else {}),
                }
                for e in archive.log.entries
            ],
        }
    }


def _request_to_dict(req: HARRequest) -> dict:
    data: dict[str, Any] = {
        "method": req.method,
        "url": req.url,
        "httpVersion": req.httpVersion,
        "headers": [h.__dict__ for h in req.headers],
        "queryString": [q.__dict__ for q in req.queryString],
        "headersSize": req.headersSize,
        "bodySize": req.bodySize,
    }
    if req.postData:
        data["postData"] = {
            "mimeType": req.postData.mimeType,
            **({"text": req.postData.text} if req.postData.text is not None else {}),
            **({"params": [p.__dict__ for p in req.postData.params]} if req.postData.params else {}),
        }
    return data


def _response_to_dict(resp: HARResponse) -> dict:
    return {
        "status": resp.status,
        "statusText": resp.statusText,
        "httpVersion": resp.httpVersion,
        "headers": [h.__dict__ for h in resp.headers],
        "content": resp.content.__dict__,
        "redirectURL": resp.redirectURL,
        "headersSize": resp.headersSize,
        "bodySize": resp.bodySize,
    }


def _get_har_file_path() -> Path:
    return _har_file_path or Path(tempfile.gettempdir()) / "ibm-go-sdk-core.har"


def _get_http_version(proto: Any) -> str:
    if isinstance(proto, str) and proto:
        return proto
    if proto:
        return str(proto)
    return "HTTP/1.1"


def _get_response_http_version(resp: Any, req: Any) -> str:
    if resp is not None:
        raw = getattr(resp, "raw", None)
        version_attr = getattr(raw, "version", None)
        if version_attr == 11:
            return "HTTP/1.1"
        if version_attr == 10:
            return "HTTP/1.0"
        if version_attr:
            return str(version_attr)

        original = getattr(raw, "_original_response", None)
        if original is not None:
            orig_version = getattr(original, "version", None)
            if orig_version == 11:
                return "HTTP/1.1"
            if orig_version == 10:
                return "HTTP/1.0"
            if orig_version:
                return str(orig_version)

        fp = getattr(raw, "_fp", None)
        http_vsn_str = getattr(fp, "_http_vsn_str", None)
        if http_vsn_str:
            return str(http_vsn_str)

    req_proto = getattr(req, "http_version", None) or getattr(req, "version", None) or getattr(req, "proto", None)
    if req_proto:
        return _get_http_version(req_proto)
    return "HTTP/1.1"


def _get_status_code(resp: Any, err: Exception | None) -> int:
    if resp is not None and getattr(resp, "status_code", None) is not None:
        try:
            return int(resp.status_code)
        except Exception:
            return 0
    if err is not None:
        return 0
    return -1


def _get_status_text(resp: Any, err: Exception | None) -> str:
    if resp is not None:
        if hasattr(resp, "status"):
            return str(getattr(resp, "status"))
        if getattr(resp, "status_code", None) is not None:
            reason = getattr(resp, "reason", "")
            return f"{resp.status_code} {reason}".strip()
    if err is not None:
        return str(err)
    return ""


def _get_response_headers(resp: Any) -> Mapping[str, Any] | None:
    if resp is None:
        return None
    return getattr(resp, "headers", None)


def _rotate_har_file(file_path: Path) -> None:
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    base = str(file_path)
    if base.endswith(".har"):
        base = base[:-4]
    backup = f"{base}_{timestamp}.har"
    try:
        os.replace(file_path, backup)
        logger.info("Rotated HAR file to: %s", backup)
    except Exception as exc:
        logger.error("Failed to rotate HAR file: %s", exc)


# Testing helper

def _reset_har_state_for_test() -> None:
    global _har_enabled, _har_file_path
    with _har_once:
        _har_enabled = None
        _har_file_path = None
