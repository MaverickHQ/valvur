# Deliberately misconfigured infrastructure. Planted for scanner tests.
resource "aws_s3_bucket" "logs" {
  bucket = "valvur-fixture-logs"
}

resource "aws_security_group" "wide_open" {
  name = "wide-open"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
