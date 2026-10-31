output "instance_id" { value = aws_instance.app.id }
output "artifact_bucket" { value = aws_s3_bucket.artifacts.id }
output "log_group" { value = aws_cloudwatch_log_group.app.name }
output "connect_command" {
  value = "aws ssm start-session --region ${var.region} --target ${aws_instance.app.id} --document-name AWS-StartPortForwardingSession --parameters portNumber=8501,localPortNumber=8501"
}
