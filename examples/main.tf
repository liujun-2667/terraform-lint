terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "aws_access_key" {
  type        = string
  description = "AWS access key"
  default     = "AKIAIOSFODNN7EXAMPLE"
  sensitive   = true
}

variable "environment" {
  type    = string
  default = "dev"
}

resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket-12345"
}

resource "aws_s3_bucket_acl" "public_acl" {
  bucket = aws_s3_bucket.public_bucket.id
  acl    = "public-read"
}

resource "aws_security_group" "open_sg" {
  name        = "open-security-group"
  description = "Allow all inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "public_db" {
  engine               = "mysql"
  instance_class       = "db.t2.micro"
  name                 = "mydb"
  username             = "admin"
  password             = "password123!"
  db_subnet_group_name = "my-db-subnet-group"
  publicly_accessible  = true # tflint:ignore:DB_PUBLICLY_ACCESSIBLE
  multi_az             = true
}

resource "aws_instance" "large_instance" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "p3.8xlarge"
}

resource "aws_eip" "unused_eip" {
  domain = "vpc"
}

output "db_password" {
  value     = aws_db_instance.public_db.password
  sensitive = false
}
