terraform {
  required_version = ">= 1.5"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.0" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "name" {
  type    = string
  default = "secure-file-share"
}

variable "alert_email" {
  type        = string
  description = "Email subscribed to security alarms (must confirm the SNS subscription)."
}

variable "max_size_bytes" {
  type    = number
  default = 10485760
}

variable "url_ttl_seconds" {
  type    = number
  default = 300
}

data "aws_caller_identity" "me" {}
data "aws_partition" "p" {}

locals {
  account = data.aws_caller_identity.me.account_id
}

# ---------------------------------------------------------------- KMS
resource "aws_kms_key" "files" {
  description             = "${var.name} object encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "files" {
  name          = "alias/${var.name}"
  target_key_id = aws_kms_key.files.key_id
}

# ---------------------------------------------------------------- S3
resource "aws_s3_bucket" "files" {
  bucket        = "${var.name}-${local.account}-${var.region}"
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "files" {
  bucket                  = aws_s3_bucket.files.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "files" {
  bucket = aws_s3_bucket.files.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "files" {
  bucket = aws_s3_bucket.files.id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.files.arn
    }
  }
}

resource "aws_s3_bucket_versioning" "files" {
  bucket = aws_s3_bucket.files.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_lifecycle_configuration" "files" {
  bucket = aws_s3_bucket.files.id
  rule {
    id     = "expire-old"
    status = "Enabled"
    filter {}
    expiration { days = 30 }
    noncurrent_version_expiration { noncurrent_days = 7 }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
}

data "aws_iam_policy_document" "bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.files.arn, "${aws_s3_bucket.files.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
  statement {
    sid       = "DenyUnencryptedUploads"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.files.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }
}

resource "aws_s3_bucket_policy" "files" {
  bucket     = aws_s3_bucket.files.id
  policy     = data.aws_iam_policy_document.bucket.json
  depends_on = [aws_s3_bucket_public_access_block.files]
}

# ---------------------------------------------------------------- Cognito
resource "aws_cognito_user_pool" "this" {
  name                     = var.name
  auto_verified_attributes = ["email"]
  username_attributes      = ["email"]
  mfa_configuration        = "OPTIONAL"

  software_token_mfa_configuration { enabled = true }

  password_policy {
    minimum_length    = 12
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = true
  }

  admin_create_user_config { allow_admin_create_user_only = true }
}

resource "aws_cognito_user_pool_client" "this" {
  name                          = "${var.name}-cli"
  user_pool_id                  = aws_cognito_user_pool.this.id
  generate_secret               = false
  explicit_auth_flows           = ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
  prevent_user_existence_errors = "ENABLED"
  access_token_validity         = 60
  id_token_validity             = 60
  token_validity_units {
    access_token = "minutes"
    id_token     = "minutes"
  }
}

# ---------------------------------------------------------------- Lambda + IAM
data "archive_file" "src" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/build/src.zip"
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_cloudwatch_log_group" "upload" {
  name              = "/aws/lambda/${var.name}-upload"
  retention_in_days = 90
}

resource "aws_cloudwatch_log_group" "download" {
  name              = "/aws/lambda/${var.name}-download"
  retention_in_days = 90
}

# Upload role: may ONLY write objects under users/*, and use the KMS key to encrypt.
resource "aws_iam_role" "upload" {
  name               = "${var.name}-upload"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

data "aws_iam_policy_document" "upload" {
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.files.arn}/users/*"]
  }
  statement {
    actions   = ["kms:GenerateDataKey"]
    resources = [aws_kms_key.files.arn]
  }
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.upload.arn}:*"]
  }
}

resource "aws_iam_role_policy" "upload" {
  role   = aws_iam_role.upload.id
  policy = data.aws_iam_policy_document.upload.json
}

# Download role: may ONLY read objects / list under users/*, and decrypt.
resource "aws_iam_role" "download" {
  name               = "${var.name}-download"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

data "aws_iam_policy_document" "download" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.files.arn}/users/*"]
  }
  statement {
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.files.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["users/*"]
    }
  }
  statement {
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.files.arn]
  }
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.download.arn}:*"]
  }
}

resource "aws_iam_role_policy" "download" {
  role   = aws_iam_role.download.id
  policy = data.aws_iam_policy_document.download.json
}

resource "aws_lambda_function" "upload" {
  function_name    = "${var.name}-upload"
  role             = aws_iam_role.upload.arn
  runtime          = "python3.12"
  handler          = "upload.handler"
  filename         = data.archive_file.src.output_path
  source_code_hash = data.archive_file.src.output_base64sha256
  timeout          = 10
  memory_size      = 128
  depends_on       = [aws_cloudwatch_log_group.upload]
  environment {
    variables = {
      BUCKET_NAME     = aws_s3_bucket.files.bucket
      KMS_KEY_ARN     = aws_kms_key.files.arn
      MAX_SIZE_BYTES  = tostring(var.max_size_bytes)
      URL_TTL_SECONDS = tostring(var.url_ttl_seconds)
    }
  }
}

resource "aws_lambda_function" "download" {
  function_name    = "${var.name}-download"
  role             = aws_iam_role.download.arn
  runtime          = "python3.12"
  handler          = "download.handler"
  filename         = data.archive_file.src.output_path
  source_code_hash = data.archive_file.src.output_base64sha256
  timeout          = 10
  memory_size      = 128
  depends_on       = [aws_cloudwatch_log_group.download]
  environment {
    variables = {
      BUCKET_NAME     = aws_s3_bucket.files.bucket
      URL_TTL_SECONDS = tostring(var.url_ttl_seconds)
    }
  }
}

# ---------------------------------------------------------------- API Gateway (HTTP API + JWT authorizer)
resource "aws_apigatewayv2_api" "this" {
  name          = var.name
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_authorizer" "jwt" {
  api_id           = aws_apigatewayv2_api.this.id
  name             = "cognito"
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]
  jwt_configuration {
    audience = [aws_cognito_user_pool_client.this.id]
    issuer   = "https://${aws_cognito_user_pool.this.endpoint}"
  }
}

resource "aws_apigatewayv2_integration" "upload" {
  api_id                 = aws_apigatewayv2_api.this.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.upload.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_integration" "download" {
  api_id                 = aws_apigatewayv2_api.this.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.download.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "upload" {
  api_id             = aws_apigatewayv2_api.this.id
  route_key          = "POST /files"
  target             = "integrations/${aws_apigatewayv2_integration.upload.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.jwt.id
}

resource "aws_apigatewayv2_route" "download" {
  api_id             = aws_apigatewayv2_api.this.id
  route_key          = "GET /files/{file_id}"
  target             = "integrations/${aws_apigatewayv2_integration.download.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.jwt.id
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/aws/apigateway/${var.name}"
  retention_in_days = 90
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.this.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_burst_limit = 20
    throttling_rate_limit  = 10
  }

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api.arn
    format = jsonencode({
      requestId = "$context.requestId"
      ip        = "$context.identity.sourceIp"
      route     = "$context.routeKey"
      status    = "$context.status"
      error     = "$context.authorizer.error"
    })
  }
}

resource "aws_lambda_permission" "upload" {
  statement_id  = "AllowApiGw"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.upload.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.this.execution_arn}/*/*"
}

resource "aws_lambda_permission" "download" {
  statement_id  = "AllowApiGw"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.download.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.this.execution_arn}/*/*"
}

# ---------------------------------------------------------------- CloudTrail (S3 data events)
resource "aws_s3_bucket" "trail" {
  bucket = "${var.name}-trail-${local.account}-${var.region}"
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${local.account}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket     = aws_s3_bucket.trail.id
  policy     = data.aws_iam_policy_document.trail_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.trail]
}

resource "aws_cloudtrail" "this" {
  name                          = var.name
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.files.arn}/"]
    }
  }

  depends_on = [aws_s3_bucket_policy.trail]
}

# ---------------------------------------------------------------- Alerts
resource "aws_sns_topic" "alerts" {
  name = "${var.name}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# 401/403 at the API edge (bad or missing JWT).
resource "aws_cloudwatch_log_metric_filter" "auth_failures" {
  name           = "${var.name}-auth-failures"
  log_group_name = aws_cloudwatch_log_group.api.name
  pattern        = "{ ($.status = \"401\") || ($.status = \"403\") }"
  metric_transformation {
    name      = "AuthFailures"
    namespace = var.name
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "auth_failures" {
  alarm_name          = "${var.name}-auth-failures"
  namespace           = var.name
  metric_name         = "AuthFailures"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 10
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# A user asking for a file id that is not theirs (enumeration / IDOR probing).
resource "aws_cloudwatch_log_metric_filter" "download_denied" {
  name           = "${var.name}-download-denied"
  log_group_name = aws_cloudwatch_log_group.download.name
  pattern        = "{ $.event = \"download_denied\" }"
  metric_transformation {
    name      = "DownloadDenied"
    namespace = var.name
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "download_denied" {
  alarm_name          = "${var.name}-download-denied"
  namespace           = var.name
  metric_name         = "DownloadDenied"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

output "api_url" {
  value = aws_apigatewayv2_api.this.api_endpoint
}

output "user_pool_id" {
  value = aws_cognito_user_pool.this.id
}

output "user_pool_client_id" {
  value = aws_cognito_user_pool_client.this.id
}

output "bucket" {
  value = aws_s3_bucket.files.bucket
}
