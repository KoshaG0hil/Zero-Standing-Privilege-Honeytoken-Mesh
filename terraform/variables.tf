variable "aws_region" {
  description = "AWS deployment region for ZSP and Honeytoken defense mesh."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment identifier (e.g. dev, staging, prod)."
  type        = string
  default     = "prod"
}

variable "project_name" {
  description = "Base prefix for provisioned security resources."
  type        = string
  default     = "zsp-honeytoken-mesh"
}

variable "max_session_duration_seconds" {
  description = "Maximum duration for ephemeral privileged STS sessions (15-60 mins)."
  type        = number
  default     = 3600
}

variable "secops_alert_email" {
  description = "Email address for high-priority SecOps honeytoken breach notifications."
  type        = string
  default     = "secops-alerts@enterprise-defense.internal"
}
