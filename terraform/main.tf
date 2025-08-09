locals {
  ssm_doc_path = "${path.module}/../ssm-documents/IncidentContainmentAndForensics.yml"
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

resource "aws_s3_bucket" "forensic_bucket" {
  bucket = "my-forensic-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "forensic_bucket_sse" {
  bucket = aws_s3_bucket.forensic_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_sns_topic" "alerts" {
  name = "ec2-ir-alerts-${var.suffix}"
}

data "aws_vpc" "default" {
  default = true
}

resource "aws_security_group" "quarantine_sg" {
  name        = "quarantine-sg-${var.suffix}"
  description = "Quarantine SG: minimal inbound, no outbound"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.quarantine_sg_cidr]
    description = "SSH for investigation (restrict in prod)"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [] # no outbound allowed
    description = "Block outbound"
  }

  tags = { Name = "quarantine-sg" }
}

resource "aws_iam_role" "ssm_automation_role" {
  name = "ir-ssm-automation-role-${var.suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "ssm.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

# Tighter IAM policy: scope S3 access to the forensic bucket only; keep EC2/SSM actions with instance wildcard (cannot know instance ARNs ahead of time)
resource "aws_iam_role_policy" "ssm_automation_policy" {
  role = aws_iam_role.ssm_automation_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "ec2:DescribeInstances",
          "ec2:ModifyInstanceAttribute",
          "ec2:CreateTags",
          "ec2:DescribeVolumes",
          "ec2:CreateSnapshot",
          "ec2:DescribeTags"
        ],
        Resource = [
          "arn:aws:ec2:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:instance/*",
          "arn:aws:ec2:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:volume/*"
        ]
      },
      {
        Effect = "Allow",
        Action = [
          "ssm:SendCommand",
          "ssm:GetCommandInvocation",
          "ssm:ListCommands",
          "ssm:ListCommandInvocations",
          "ssm:GetAutomationExecution",
          "ssm:StartAutomationExecution",
          "ssm:DescribeAutomationExecutions"
        ],
        Resource = [
          "arn:aws:ssm:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:document/*",
          "arn:aws:ssm:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:automation-definition/*",
          "arn:aws:ssm:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:automation-execution/*"
        ]
      },
      {
        Effect = "Allow",
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl",
          "s3:AbortMultipartUpload",
          "s3:ListBucket"
        ],
        Resource = [
          aws_s3_bucket.forensic_bucket.arn,
          "${aws_s3_bucket.forensic_bucket.arn}/*"
        ]
      },
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role" "eventbridge_role" {
  name = "eventbridge-ssm-role-${var.suffix}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "events.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

# EventBridge role scoped to start the specific SSM document
resource "aws_iam_role_policy" "eventbridge_policy" {
  role = aws_iam_role.eventbridge_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Action = ["ssm:StartAutomationExecution"],
      Resource = aws_ssm_document.ir_document.arn
    }]
  })
}

# Import SSM document YAML
resource "aws_ssm_document" "ir_document" {
  name          = "IncidentContainmentAndForensics-${var.suffix}"
  document_type = "Automation"
  content       = file(local.ssm_doc_path)
  depends_on    = [aws_iam_role.ssm_automation_role]
}

# EventBridge rule to match Security Hub / GuardDuty findings
resource "aws_cloudwatch_event_rule" "ir_finding_rule" {
  name        = "ir-finding-rule-${var.suffix}"
  description = "Trigger SSM Automation when Security Hub/GuardDuty/Inspector finding requires containment"

  event_pattern = jsonencode({
    "source": ["aws.securityhub","aws.guardduty","aws.inspector"],
    "detail-type": ["Security Hub Findings - Imported","GuardDuty Finding","Inspector Finding"]
    # Add filters here if you want severity thresholds or product ARNs
  })
}

# EventBridge Rule to trigger the SSM Automation
resource "aws_cloudwatch_event_rule" "ir_event_rule" {
  name        = "IR-Automation-Rule"
  description = "Triggers SSM Automation on specific events"
  event_pattern = <<EOF
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"]
}
EOF
}

# IAM Role for EventBridge to trigger SSM Automation
resource "aws_iam_role" "events_role" {
  name = "IR-Events-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Policy for EventBridge role to start SSM Automation
resource "aws_iam_role_policy" "events_role_policy" {
  name = "IR-Events-Role-Policy"
  role = aws_iam_role.events_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:StartAutomationExecution"
        ]
        Resource = "*"
      }
    ]
  })
}

# EventBridge target: Start AutomationExecution (input mapping done via input_transformer)
resource "aws_cloudwatch_event_target" "ir_ssm_target" {
  rule      = aws_cloudwatch_event_rule.ir_event_rule.name
  target_id = "IRSSMAutomation"

  arn   = "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:automation-definition/${aws_ssm_document.ir_document.name}"
  role_arn = aws_iam_role.events_role.arn

  input = <<EOT
{
  "DocumentName": "${aws_ssm_document.ir_document.name}",
  "Parameters": {
    "InstanceId": ["<instanceId>"],
    "QuarantineSecurityGroup": ["${aws_security_group.quarantine_sg.id}"],
    "ForensicS3Bucket": ["${aws_s3_bucket.forensic_bucket.bucket}"],
    "CreateSnapshots": ["true"],
    "AutomationAssumeRole": ["${aws_iam_role.ssm_automation_role.arn}"],
    "PubTopicArn": ["${aws_sns_topic.alerts.arn}"]
  }
}
EOT
}