resource "aws_db_instance" "app" {
  engine = "postgres"
  instance_class = "db.t3.micro"
  allocated_storage = 20
  username = "example_user"
  manage_master_user_password = true
  storage_encrypted = false
  publicly_accessible = false
}

