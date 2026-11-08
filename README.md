# secure-file-share

A serverless file-sharing API on AWS. Authenticated users request a short-lived (5 minute) pre-signed URL to upload a file or download one of their own files. Everything is defined in Terraform.

```
Client --JWT--> API Gateway (HTTP API, Cognito JWT authorizer)
                    |-- POST /files          -> upload Lambda   -> presigned POST (S3)
                    '-- GET  /files/{id}     -> download Lambda -> presigned GET  (S3)
S3 bucket: private, SSE-KMS, TLS-only, versioned, 30-day lifecycle
CloudTrail (S3 data events) + CloudWatch alarms -> SNS email
```

## Security controls

| Control | Where |
|---|---|
| Private bucket, all four public-access blocks, `BucketOwnerEnforced` | `terraform/main.tf` |
| SSE-KMS with a customer-managed, rotating key; bucket policy denies unencrypted `PutObject` and non-TLS access | `terraform/main.tf` |
| Separate least-privilege IAM role per Lambda: upload = `s3:PutObject` + `kms:GenerateDataKey` on `users/*`; download = `s3:GetObject`, prefix-restricted `s3:ListBucket`, `kms:Decrypt` | `terraform/main.tf` |
| Cognito user pool (admin-created users only, 12+ char passwords, optional TOTP MFA); API Gateway JWT authorizer on every route | `terraform/main.tf` |
| Per-user isolation: object keys are `users/<cognito sub>/<file id>/<name>`; `sub` is read from the verified JWT, never the request body | `src/common.py`, handlers |
| Upload validation: extension allowlist, content type must match extension, filename regex (no traversal), size cap | `src/common.py` |
| Presigned **POST** with `content-length-range` and required KMS headers, so S3 itself enforces the size cap and encryption | `src/upload.py` |
| Downloads served as `attachment`; 5-minute URL expiry; throttling on the API stage | `src/download.py`, `terraform/main.tf` |
| CloudTrail with S3 data events and log-file validation; alarms on bursts of 401/403 and on denied downloads (someone probing other users' file ids) | `terraform/main.tf` |

## Threat model

| Threat | Mitigation | Residual risk |
|---|---|---|
| Unauthenticated access | JWT authorizer on every route | Stolen valid token works until it expires (60 min) |
| User reads another user's file | Prefix derived from JWT `sub`; unknown id returns 404 (no existence oracle); ids are random 128-bit | A leaked presigned URL works for up to 5 minutes |
| Malicious / oversized upload | Allowlist, size and type conditions enforced by S3 | Content is not virus-scanned and magic bytes are not inspected (a mislabelled file passes) |
| Path traversal via filename | Strict filename regex; key built server-side | None known |
| Data at rest / in transit exposure | SSE-KMS, TLS-only bucket policy | |
| Over-privileged function compromise | Per-function roles scoped to `users/*` | A compromised function can reach all users' prefixes; per-user scoping relies on handler code |
| Abuse / enumeration | Stage throttling, denied-download alarm | No WAF; no per-user quota |

## Layout

```
src/         Lambda code (common.py, upload.py, download.py)
terraform/   Entire stack
tests/       Unit tests (stdlib unittest, no AWS access needed)
```

## Usage

```bash
python -m unittest discover -s tests          # run tests
cd terraform
terraform init
terraform apply -var alert_email=you@example.com
```

Create a user (self-sign-up is disabled), then call the API:

```bash
aws cognito-idp admin-create-user --user-pool-id <pool> --username you@example.com
# sign in with SRP (e.g. via the Cognito SDK / Amplify) to get an ID token, then:
curl -X POST "$API_URL/files" -H "Authorization: Bearer $TOKEN" \
  -d '{"filename":"report.pdf","content_type":"application/pdf","size":12345}'
# response contains an S3 presigned POST: send a multipart form with the returned fields + file
curl "$API_URL/files/<file_id>" -H "Authorization: Bearer $TOKEN"   # -> {"url": "..."}
```

## Status

Unit tests for validation and handler logic pass locally. The Terraform has **not yet been applied to a live AWS account** or run through `terraform validate`; treat deployment as unverified until you have run it.
