# A "share a file by link" feature, as a pull request might add it.
# This file is the *after* state of the example change; examples/public-share/plan.json is
# the matching `terraform show -json` output (see README: it was written by hand in
# Terraform's documented plan format, because Terraform could not be installed in the
# sandbox this project was built in).

variable "shares_bucket" {
  default = "acme-file-shares"
}

resource "aws_s3_bucket" "shares" {
  bucket = var.shares_bucket
}

# The PR turns Block Public Access off so the share links "just work".
resource "aws_s3_bucket_public_access_block" "shares" {
  bucket                  = aws_s3_bucket.shares.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "shares" {
  bucket = aws_s3_bucket.shares.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # "Only our web app can fetch shared files" - but aws:Referer is set by the client.
        Sid       = "ShareLinksFromOurSite"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "arn:aws:s3:::${var.shares_bucket}/shared/*"
        Condition = { StringLike = { "aws:Referer" = "https://share.example.com/*" } }
      },
      {
        Sid       = "UploadsFromTheVpcOnly"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "arn:aws:s3:::${var.shares_bucket}/incoming/*"
        Condition = { StringEquals = { "aws:SourceVpce" = "vpce-0a1b2c3d4e5f60718" } }
      },
      {
        Sid       = "DenyPlainHttp"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = ["arn:aws:s3:::${var.shares_bucket}", "arn:aws:s3:::${var.shares_bucket}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

# CI deploy role assumed from GitHub Actions through OIDC.
resource "aws_iam_role" "deploy" {
  name = "shares-deploy"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "GitHubActions"
      Effect    = "Allow"
      Principal = { Federated = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com" }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike   = { "token.actions.githubusercontent.com:sub" = "repo:*" }
      }
    }]
  })
}

resource "aws_iam_role_policy" "deploy" {
  name = "deploy"
  role = aws_iam_role.deploy.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "Everything", Effect = "Allow", Action = "s3:*", Resource = "*" },
      { Sid = "PassAnything", Effect = "Allow", Action = ["iam:PassRole", "lambda:UpdateFunctionCode"], Resource = "*" }
    ]
  })
}
