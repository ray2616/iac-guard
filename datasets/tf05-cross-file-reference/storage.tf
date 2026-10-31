resource "aws_ebs_volume" "data" {
  availability_zone = var.zone
  size = 10
  encrypted = false
}

