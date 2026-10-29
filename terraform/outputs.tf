output "ephemeral_role_arn" {
  description = "ARN of the Zero-Standing-Privilege ephemeral assume role."
  value       = aws_iam_role.ephemeral_admin_role.arn
}

output "canary_user_arn" {
  description = "ARN of the Decoy Honeytoken Canary principal."
  value       = aws_iam_user.canary_honeytoken_user.arn
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge tripwire rule catching canary breaches."
  value       = aws_cloudwatch_event_rule.honeytoken_breach_rule.arn
}

output "remediator_lambda_arn" {
  description = "ARN of the automated session revocation Lambda function."
  value       = aws_lambda_function.honeytoken_remediator.arn
}

output "forensic_s3_bucket" {
  description = "S3 bucket storing SHA-256 forensic incident reports."
  value       = aws_s3_bucket.forensic_bucket.bucket
}

output "dynamodb_sessions_table" {
  description = "DynamoDB table tracking active JIT sessions."
  value       = aws_dynamodb_table.jit_sessions.name
}

output "secops_alerts_topic_arn" {
  description = "SNS topic ARN for high-priority SecOps alerts."
  value       = aws_sns_topic.secops_breach_alerts.arn
}
