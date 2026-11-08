"""Shared helpers: input validation, key construction, response building."""
import json
import os
import re
import uuid

MAX_SIZE_BYTES = int(os.environ.get("MAX_SIZE_BYTES", 10 * 1024 * 1024))
URL_TTL_SECONDS = int(os.environ.get("URL_TTL_SECONDS", 300))

# Extension -> the only content type accepted for it (allowlist, not denylist).
ALLOWED_TYPES = {
    "pdf": "application/pdf",
    "txt": "text/plain",
    "csv": "text/csv",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}

_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,99}$")
_UUID_RE = re.compile(r"^[0-9a-f]{32}$")


class ValidationError(Exception):
    pass


def validate_upload(filename, content_type, size):
    """Return the normalised extension, or raise ValidationError."""
    if not isinstance(filename, str) or not _FILENAME_RE.match(filename) or ".." in filename:
        raise ValidationError("invalid filename")
    if "." not in filename:
        raise ValidationError("filename needs an extension")
    ext = filename.rsplit(".", 1)[1].lower()
    expected = ALLOWED_TYPES.get(ext)
    if expected is None:
        raise ValidationError(f"file type .{ext} not allowed")
    if content_type != expected:
        raise ValidationError("content type does not match file extension")
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise ValidationError("size must be a positive integer")
    if size > MAX_SIZE_BYTES:
        raise ValidationError(f"file exceeds {MAX_SIZE_BYTES} bytes")
    return ext


def new_file_id():
    return uuid.uuid4().hex


def valid_file_id(file_id):
    return isinstance(file_id, str) and bool(_UUID_RE.match(file_id))


def user_prefix(sub, file_id=None):
    """Every object lives under users/<cognito sub>/<file id>/ - the isolation boundary."""
    base = f"users/{sub}/"
    return base + f"{file_id}/" if file_id else base


def caller_sub(event):
    """Identity comes only from the verified JWT claims, never from the request body."""
    try:
        return event["requestContext"]["authorizer"]["jwt"]["claims"]["sub"]
    except (KeyError, TypeError):
        return None


def response(status, body):
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json", "Cache-Control": "no-store"},
        "body": json.dumps(body),
    }


def log(event_name, **fields):
    """Structured log line; CloudWatch metric filters key off `event`."""
    print(json.dumps({"event": event_name, **fields}))
