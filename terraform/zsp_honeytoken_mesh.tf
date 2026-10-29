# -----------------------------------------------------------------------------
# Ephemeral Elevated Privilege Role (Zero-Standing-Privilege)
# -----------------------------------------------------------------------------
resource "aws_iam_role" "ephemeral_admin_role" {
  name                 = "${local.name_prefix}-ephemeral-role"
  max_session_duration = var.max_session_duration_seconds

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# Decoy Honeytoken Canary IAM Principal
# -----------------------------------------------------------------------------
resource "aws_iam_user" "canary_honeytoken_user" {
  name = "${local.name_prefix}-canary-decoy-agent"
  path = "/security-canaries/"
}

resource "aws_iam_access_key" "canary_key" {
  user = aws_iam_user.canary_honeytoken_user.name
}

# Decoy policy: explicitly deny all actions so any attempted exploit is harmless
resource "aws_iam_user_policy" "canary_explicit_deny" {
  name = "CanaryTripwireTrapDenyAll"
  user = aws_iam_user.canary_honeytoken_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DecoyTripwireTrap"
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# S3 Forensic Audit Storage (Tamper-Evident SHA-256 Manifests)
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "forensic_bucket" {
  bucket        = "${local.name_prefix}-forensics-${local.account_id}"
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "forensic_bucket" {
  bucket = aws_s3_bucket.forensic_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "forensic_bucket" {
  bucket = aws_s3_bucket.forensic_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "forensic_bucket" {
  bucket = aws_s3_bucket.forensic_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# -----------------------------------------------------------------------------
# DynamoDB Active JIT Session & Honeytoken Registry
# -----------------------------------------------------------------------------
resource "aws_dynamodb_table" "jit_sessions" {
  name         = "${local.name_prefix}-active-sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "session_id"

  attribute {
    name = "session_id"
    type = "S"
  }

  ttl {
    attribute_name = "ttl_timestamp"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }
}

# -----------------------------------------------------------------------------
# High-Priority SecOps Incident Notification Topic (SNS)
# -----------------------------------------------------------------------------
resource "aws_sns_topic" "secops_breach_alerts" {
  name              = "${local.name_prefix}-breach-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email_sub" {
  topic_arn = aws_sns_topic.secops_breach_alerts.arn
  protocol  = "email"
  endpoint  = var.secops_alert_email
}

# -----------------------------------------------------------------------------
# Lambda Execution Role & Containment Permissions
# -----------------------------------------------------------------------------
resource "aws_iam_role" "lambda_remediator_role" {
  name = "${local.name_prefix}-remediator-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "lambda_containment_policy" {
  name        = "${local.name_prefix}-containment-policy"
  description = "Allows automated session revocation, inline Deny policies, and SNS alerts."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:PutUserPolicy",
          "iam:PutRolePolicy",
          "iam:AttachUserPolicy",
          "iam:AttachRolePolicy"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:Scan"
        ]
        Resource = aws_dynamodb_table.jit_sessions.arn
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.secops_breach_alerts.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.forensic_bucket.arn}/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_containment_attach" {
  role       = aws_iam_role.lambda_remediator_role.name
  policy_arn = aws_iam_policy.lambda_containment_policy.arn
}

resource "aws_iam_role_policy_attachment" "lambda_basic_logs" {
  role       = aws_iam_role.lambda_remediator_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# -----------------------------------------------------------------------------
# Lambda Deployment Package & Remediation Function
# -----------------------------------------------------------------------------
data "archive_file" "lambda_dummy_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda_payload.zip"

  source {
    content  = "def lambda_handler(event, context): return {'statusCode': 200, 'body': 'contained'}"
    filename = "index.py"
  }
}

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${local.name_prefix}-remediator"
  retention_in_days = 30
}

resource "aws_lambda_function" "honeytoken_remediator" {
  function_name    = "${local.name_prefix}-remediator"
  role             = aws_iam_role.lambda_remediator_role.arn
  handler          = "src.lambda_honeytoken_remediator.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda_dummy_zip.output_path
  source_code_hash = data.archive_file.lambda_dummy_zip.output_base64sha256
  timeout          = 15
  memory_size      = 256

  environment {
    variables = {
      ENVIRONMENT       = var.environment
      SNS_TOPIC_ARN     = aws_sns_topic.secops_breach_alerts.arn
      DYNAMO_TABLE_NAME = aws_dynamodb_table.jit_sessions.name
      FORENSIC_BUCKET   = aws_s3_bucket.forensic_bucket.bucket
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda_logs]
}

# -----------------------------------------------------------------------------
# Amazon EventBridge Rule: Honeytoken CloudTrail Tripwire Detection
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "honeytoken_breach_rule" {
  name        = "${local.name_prefix}-tripwire-rule"
  description = "Triggers immediate containment upon API activity from canary honeytoken principal."

  event_pattern = jsonencode({
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      userIdentity = {
        arn = [aws_iam_user.canary_honeytoken_user.arn]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.honeytoken_breach_rule.name
  target_id = "TriggerSessionRevocationLambda"
  arn       = aws_lambda_function.honeytoken_remediator.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.honeytoken_remediator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.honeytoken_breach_rule.arn
}
