resource "aws_s3_bucket_public_access_block" "access" {
 bucket = "example"
 block_public_acls = false
 block_public_policy = false
 ignore_public_acls = false
 restrict_public_buckets = false
}
