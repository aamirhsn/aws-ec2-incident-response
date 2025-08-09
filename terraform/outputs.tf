output "forensic_bucket" {
  value = aws_s3_bucket.forensic_bucket.bucket
}
output "ssm_document_name" {
  value = aws_ssm_document.ir_document.name
}
output "quarantine_sg_id" {
  value = aws_security_group.quarantine_sg.id
}
output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}