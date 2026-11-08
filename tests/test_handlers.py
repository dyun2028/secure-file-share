import json
import os
import sys
import types
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
# Handlers import boto3 at module load; stub it so tests need no AWS SDK.
for name in ("boto3", "botocore", "botocore.config"):
    sys.modules.setdefault(name, types.ModuleType(name))
sys.modules["botocore.config"].Config = lambda **kw: None

import common  # noqa: E402
import download  # noqa: E402
import upload  # noqa: E402


def event(sub="user-a", body=None, file_id=None):
    e = {"requestContext": {"authorizer": {"jwt": {"claims": {"sub": sub}}}} if sub else {}}
    if body is not None:
        e["body"] = json.dumps(body)
    if file_id:
        e["pathParameters"] = {"file_id": file_id}
    return e


GOOD = {"filename": "report.pdf", "content_type": "application/pdf", "size": 1000}


class ValidationTests(unittest.TestCase):
    def test_rejects_disallowed_extension(self):
        with self.assertRaises(common.ValidationError):
            common.validate_upload("run.exe", "application/octet-stream", 10)

    def test_rejects_mismatched_content_type(self):
        with self.assertRaises(common.ValidationError):
            common.validate_upload("a.pdf", "text/html", 10)

    def test_rejects_oversize_and_bad_size(self):
        for size in (common.MAX_SIZE_BYTES + 1, 0, -5, "10", True):
            with self.assertRaises(common.ValidationError):
                common.validate_upload("a.pdf", "application/pdf", size)

    def test_rejects_path_traversal(self):
        for name in ("../a.pdf", "a/b.pdf", "..a.pdf", "a\\b.pdf", ""):
            with self.assertRaises(common.ValidationError):
                common.validate_upload(name, "application/pdf", 10)

    def test_accepts_valid(self):
        self.assertEqual(common.validate_upload("Report v2.PDF", "application/pdf", 10), "pdf")


class UploadTests(unittest.TestCase):
    def test_unauthenticated(self):
        self.assertEqual(upload.handler(event(sub=None, body=GOOD), None, s3=MagicMock())["statusCode"], 401)

    def test_bad_input_never_reaches_s3(self):
        s3 = MagicMock()
        r = upload.handler(event(body={**GOOD, "filename": "x.exe"}), None, s3=s3)
        self.assertEqual(r["statusCode"], 400)
        s3.generate_presigned_post.assert_not_called()

    def test_key_is_scoped_to_caller_and_ttl_is_short(self):
        s3 = MagicMock()
        s3.generate_presigned_post.return_value = {"url": "u", "fields": {}}
        r = upload.handler(event(sub="user-a", body=GOOD), None, s3=s3)
        self.assertEqual(r["statusCode"], 200)
        kw = s3.generate_presigned_post.call_args.kwargs
        self.assertTrue(kw["Key"].startswith("users/user-a/"))
        self.assertLessEqual(kw["ExpiresIn"], 300)
        self.assertIn(["content-length-range", 1, common.MAX_SIZE_BYTES], kw["Conditions"])


class DownloadTests(unittest.TestCase):
    FID = "a" * 32

    def test_other_users_file_is_404(self):
        s3 = MagicMock()
        s3.list_objects_v2.return_value = {}
        r = download.handler(event(sub="user-b", file_id=self.FID), None, s3=s3)
        self.assertEqual(r["statusCode"], 404)
        self.assertEqual(s3.list_objects_v2.call_args.kwargs["Prefix"], f"users/user-b/{self.FID}/")
        s3.generate_presigned_url.assert_not_called()

    def test_owner_gets_short_lived_url(self):
        s3 = MagicMock()
        s3.list_objects_v2.return_value = {"Contents": [{"Key": f"users/user-a/{self.FID}/r.pdf"}]}
        s3.generate_presigned_url.return_value = "https://signed"
        r = download.handler(event(sub="user-a", file_id=self.FID), None, s3=s3)
        self.assertEqual(r["statusCode"], 200)
        self.assertEqual(s3.generate_presigned_url.call_args.kwargs["ExpiresIn"], 300)

    def test_malformed_id_rejected(self):
        self.assertEqual(download.handler(event(file_id="../x"), None, s3=MagicMock())["statusCode"], 400)


if __name__ == "__main__":
    unittest.main()
