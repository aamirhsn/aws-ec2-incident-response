# EC2 Incident Containment & Forensic Collector

Mini incident-response automation for AWS:
- Quarantines a suspected EC2 instance (replace security groups, tag)
- Collects forensic logs (Linux/Windows) via SSM RunCommand and uploads to S3
- Optionally snapshots attached EBS volumes
- Notifies security team via SNS

> **WARNING:** Deploy only in sandbox/test accounts.

## How to deploy (quick)
1. Configure AWS CLI credentials with admin or necessary permissions.
2. `cd terraform`
3. `terraform init`
4. `terraform apply -var="suffix=yourname-demo" -auto-approve`
5. Note outputs (S3 bucket name, SSM Document name, Quarantine SG id, EventBridge rule ARN, SNS topic ARN).

## How to test
- Use `test/send_test_event.py` with AWS credentials (or use AWS Console → EventBridge → Put test event) to trigger automation.
- Confirm S3 objects appear and instance gets tagged `InvestigationStatus=Quarantined`.

## Files
- `terraform/` — infrastructure (S3, roles, SG, eventbridge, ssm document)
- `ssm-documents/IncidentContainmentAndForensics.yml` — SSM Automation document
- `test/` — sample test event and Python helper