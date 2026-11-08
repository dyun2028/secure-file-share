"""POST /files - validate the request and return a short-lived presigned POST."""
import json
import os

import boto3
from botocore.config import Config

import common

BUCKET = os.environ.get("BUCKET_NAME", "")
KMS_KEY_ARN = os.environ.get("KMS_KEY_ARN", "")

_s3 = None


def _client():
    global _s3
    if _s3 is None:
        _s3 = boto3.client("s3", config=Config(signature_version="s3v4"))
    return _s3


def handler(event, context, s3=None):
    sub = common.caller_sub(event)
    if not sub:
        common.log("auth_failure", reason="missing_claims")
        return common.response(401, {"error": "unauthorized"})

    try:
        body = json.loads(event.get("body") or "{}")
        ext = common.validate_upload(body.get("filename"), body.get("content_type"), body.get("size"))
    except (json.JSONDecodeError, common.ValidationError) as exc:
        common.log("upload_rejected", sub=sub, reason=str(exc))
        return common.response(400, {"error": str(exc)})

    file_id = common.new_file_id()
    key = common.user_prefix(sub, file_id) + body["filename"]
    # Presigned POST (not PUT) so S3 itself enforces the size cap and content type.
    post = (s3 or _client()).generate_presigned_post(
        Bucket=BUCKET,
        Key=key,
        Fields={
            "Content-Type": body["content_type"],
            "x-amz-server-side-encryption": "aws:kms",
            "x-amz-server-side-encryption-aws-kms-key-id": KMS_KEY_ARN,
        },
        Conditions=[
            {"Content-Type": body["content_type"]},
            {"x-amz-server-side-encryption": "aws:kms"},
            {"x-amz-server-side-encryption-aws-kms-key-id": KMS_KEY_ARN},
            ["content-length-range", 1, common.MAX_SIZE_BYTES],
        ],
        ExpiresIn=common.URL_TTL_SECONDS,
    )
    common.log("upload_url_issued", sub=sub, file_id=file_id, ext=ext, size=body["size"])
    return common.response(200, {"file_id": file_id, "upload": post, "expires_in": common.URL_TTL_SECONDS})
