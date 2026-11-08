"""GET /files/{file_id} - return a short-lived presigned GET for the caller's own file."""
import os

import boto3
from botocore.config import Config

import common

BUCKET = os.environ.get("BUCKET_NAME", "")

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

    file_id = (event.get("pathParameters") or {}).get("file_id")
    if not common.valid_file_id(file_id):
        return common.response(400, {"error": "invalid file id"})

    client = s3 or _client()
    # The prefix is built from the caller's own sub, so another user's file id
    # simply resolves to nothing and is indistinguishable from "does not exist".
    listing = client.list_objects_v2(Bucket=BUCKET, Prefix=common.user_prefix(sub, file_id), MaxKeys=1)
    contents = listing.get("Contents") or []
    if not contents:
        common.log("download_denied", sub=sub, file_id=file_id)
        return common.response(404, {"error": "not found"})

    url = client.generate_presigned_url(
        "get_object",
        Params={
            "Bucket": BUCKET,
            "Key": contents[0]["Key"],
            "ResponseContentDisposition": "attachment",
        },
        ExpiresIn=common.URL_TTL_SECONDS,
    )
    common.log("download_url_issued", sub=sub, file_id=file_id)
    return common.response(200, {"url": url, "expires_in": common.URL_TTL_SECONDS})
