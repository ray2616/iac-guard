data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" { state = "available" }
data "aws_ec2_instance_type" "selected" { instance_type = var.instance_type }
data "aws_ssm_parameter" "ami" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "terraform_data" "credit_gate" {
  lifecycle {
    precondition {
      condition     = var.credits_verified && var.credit_balance_usd > 0 && var.verified_session_estimate_usd > 0 && var.verified_session_estimate_usd < var.credit_balance_usd && timecmp(var.credit_expires_at, timestamp()) > 0
      error_message = "Cloud provisioning blocked until actual account eligibility, credits, expiration and full regional session costs are verified."
    }
  }
}

resource "aws_vpc" "demo" {
  depends_on           = [terraform_data.credit_gate]
  cidr_block           = "10.48.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}
resource "aws_default_security_group" "restricted" {
  vpc_id = aws_vpc.demo.id
  # No rules: future resources must explicitly choose the application's group.
}
resource "aws_subnet" "demo" {
  vpc_id                  = aws_vpc.demo.id
  cidr_block              = "10.48.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false
}
resource "aws_internet_gateway" "demo" { vpc_id = aws_vpc.demo.id }
resource "aws_route_table" "demo" {
  vpc_id = aws_vpc.demo.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.demo.id
  }
}
resource "aws_route_table_association" "demo" {
  subnet_id      = aws_subnet.demo.id
  route_table_id = aws_route_table.demo.id
}
resource "aws_security_group" "demo" {
  name_prefix = "iac-guard-"
  description = "No inbound ports; outbound TLS for SSM, S3, logs and trusted registries"
  vpc_id      = aws_vpc.demo.id
  egress {
    description = "TLS to AWS endpoints and software registries"
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "artifacts" {
  depends_on    = [terraform_data.credit_gate]
  bucket        = "iac-guard-${data.aws_caller_identity.current.account_id}-${var.region}-${terraform.workspace}"
  force_destroy = var.allow_artifact_deletion
}
resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
}
resource "aws_s3_bucket_policy" "tls" {
  bucket = aws_s3_bucket.artifacts.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Sid       = "DenyInsecureTransport", Effect = "Deny", Principal = "*", Action = "s3:*",
    Resource  = [aws_s3_bucket.artifacts.arn, "${aws_s3_bucket.artifacts.arn}/*"],
    Condition = { Bool = { "aws:SecureTransport" = "false" } }
  }] })
}
resource "aws_cloudwatch_log_group" "app" {
  depends_on        = [terraform_data.credit_gate]
  name              = "/iac-guard/${terraform.workspace}"
  retention_in_days = 3
}
resource "aws_iam_role" "app" {
  depends_on  = [terraform_data.credit_gate]
  name_prefix = "iac-guard-"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole"
  }] })
}
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
resource "aws_iam_role_policy" "runtime" {
  role = aws_iam_role.app.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = "${aws_s3_bucket.artifacts.arn}/iac-guard/*" },
    { Effect = "Allow", Action = ["s3:GetObject"], Resource = "${aws_s3_bucket.artifacts.arn}/${var.release_key}" },
    { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.app.arn}:*" }
  ] })
}
resource "aws_iam_instance_profile" "app" { role = aws_iam_role.app.name }

resource "aws_instance" "app" {
  ami                         = data.aws_ssm_parameter.ami.value
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.demo.id
  vpc_security_group_ids      = [aws_security_group.demo.id]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.app.name
  monitoring                  = true
  ebs_optimized               = true
  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
    instance_metadata_tags      = "disabled"
  }
  root_block_device {
    volume_size           = 24
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }
  user_data = templatefile("${path.module}/bootstrap.sh.tftpl", {
    bucket = aws_s3_bucket.artifacts.id, release_key = var.release_key,
    sha256 = var.release_sha256, region = var.region, log_group = aws_cloudwatch_log_group.app.name,
  })
  user_data_replace_on_change = true
  depends_on                  = [aws_route_table_association.demo, aws_iam_role_policy.runtime, aws_iam_role_policy_attachment.ssm]
  lifecycle {
    precondition {
      condition     = var.credits_verified && var.credit_balance_usd > 0 && var.verified_session_estimate_usd > 0 && var.verified_session_estimate_usd < var.credit_balance_usd && timecmp(var.credit_expires_at, timestamp()) > 0
      error_message = "Deployment blocked: verify the actual account plan, credit eligibility/balance/expiration and ALL regional session costs. Do not upgrade to a paid plan automatically."
    }
    precondition {
      condition     = data.aws_ec2_instance_type.selected.memory_size >= 4096 && contains(data.aws_ec2_instance_type.selected.supported_architectures, "x86_64")
      error_message = "Use an eligible x86-64 instance with at least 4 GiB RAM."
    }
  }
}
