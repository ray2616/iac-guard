resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size = 10
  encrypted = true
  kms_key_id = "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000"
}

