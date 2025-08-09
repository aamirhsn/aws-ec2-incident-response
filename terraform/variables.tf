variable "region" {
    type = string
    default = "us-east-1"
}

variable "suffix" {
  description = "unique suffix for resource names"
  default     = "demo-001"
}

variable "quarantine_sg_cidr" {
  description = "CIDR for allowed admin access to quarantine SG (e.g. your office IP)"
  default     = "0.0.0.0/0"
}