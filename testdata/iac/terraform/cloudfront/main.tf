resource "aws_cloudfront_distribution" "app" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "App distribution"
  default_root_object = "index.html"

  origin {
    domain_name = aws_s3_bucket.app.bucket_regional_domain_name
    origin_id   = "S3-${aws_s3_bucket.app.bucket}"

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.app.cloudfront_access_identity_path
    }
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-${aws_s3_bucket.app.bucket}"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
  }

  price_class = "PriceClass_All"

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

resource "aws_s3_bucket" "app" {
  bucket = "app-assets"
}

resource "aws_cloudfront_origin_access_identity" "app" {
  comment = "OAI for app bucket"
}