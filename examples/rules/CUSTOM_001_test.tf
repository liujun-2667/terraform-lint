// expect: line=3 severity=warning
// expect: line=8 severity=warning

resource "aws_instance" "bad_example" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
}

resource "aws_s3_bucket" "good_example" {
  bucket = "my-bucket"
  tags = {
    Project     = "my-project"
    Environment = "production"
  }
}

resource "aws_vpc" "partial_example" {
  cidr_block = "10.0.0.0/16"
  tags = {
    Project = "my-project"
  }
}
