resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size = 10
  encrypted = false
}

module "unavailable" {
 source = "hashicorp/consul/aws"
 version = "0.11.0"
}
