# Deliberately insecure test fixture. Do not deploy.
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = false
}

resource "aws_db_instance" "app" {
  allocated_storage   = 20
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  username            = "example_user"
  manage_master_user_password = true
  storage_encrypted   = false
  publicly_accessible = true
  skip_final_snapshot = false
}
