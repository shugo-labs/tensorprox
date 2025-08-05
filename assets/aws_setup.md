# TensorProx AWS Terraform Configuration

This directory contains a single, unified Terraform configuration file (`main.tf`) that creates all necessary AWS resources for TensorProx infrastructure.

## 1. Overview

The configuration creates:
- IAM user with minimal EC2 permissions
- VPC with public and private subnets
- Security groups supporting GRE (protocol 47) and IPIP (protocol 4)
- Budget monitoring with email alerts
- CloudWatch logging and alarms
- All necessary supporting resources

Files to deploy: 

### 1.1 terraform.tfvars
   ```terraform
   # TensorProx AWS Configuration
# Copy this file to terraform.tfvars and update with your values

# Project Configuration
project_name = "tensorprox"
region       = "us-east-1"
zone         = "us-east-1a"  # Optional - will use first available zone if not specified

# Budget Configuration
budget_amount      = 1000
notification_email = "your-email@example.com"

# Resource Quotas
max_vcpus       = 16
max_instances   = 4
max_elastic_ips = 4

# Network Configuration // 
vpc_cidr            = "10.0.0.0/16"
public_subnet_cidr  = "10.0.0.0/24"
private_subnet_cidr = "10.0.1.0/24"

# Instance Types
machine_type  = "e3.medium"
vm_size_small = "e3.small"    # For King
vm_size_large = "e3.large"    # For Traffic Generators
num_tgens     = 2
   ```

### 1.2 deploy.sh
  ```bash
  #!/bin/bash
  
  # TensorProx AWS Unified Terraform Deployment Script
  # This script wraps terraform commands and generates the environment file
  
  set -e
  
  # Colors for output
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  NC='\033[0m' # No Color
  
  # Function to print colored output
  print_message() {
      local level=$1
      local message=$2
      case $level in
          "ERROR")   echo -e "${RED}[ERROR]${NC} $message" >&2 ;;
          "SUCCESS") echo -e "${GREEN}[SUCCESS]${NC} $message" ;;
          "INFO")    echo -e "${YELLOW}[INFO]${NC} $message" ;;
          *)         echo "$message" ;;
      esac
  }
  
  # Function to check prerequisites
  check_prerequisites() {
      print_message "INFO" "Checking prerequisites..."
      
      # Check Terraform
      if ! command -v terraform &> /dev/null; then
          print_message "ERROR" "Terraform is not installed. Please install Terraform 1.0 or later."
          exit 1
      fi
      
      # Check AWS CLI
      if ! command -v aws &> /dev/null; then
          print_message "ERROR" "AWS CLI is not installed. Please install AWS CLI v2."
          exit 1
      fi
      
      # Check AWS credentials
      if ! aws sts get-caller-identity &> /dev/null; then
          print_message "ERROR" "AWS credentials not configured. Please run 'aws configure' first."
          exit 1
      fi
      
      print_message "SUCCESS" "All prerequisites met."
  }
  
  # Function to initialize Terraform
  init_terraform() {
      print_message "INFO" "Initializing Terraform..."
      if terraform init; then
          print_message "SUCCESS" "Terraform initialized successfully."
      else
          print_message "ERROR" "Terraform initialization failed."
          exit 1
      fi
  }
  
  # Function to apply Terraform
  apply_terraform() {
      local var_file=$1
      
      print_message "INFO" "Planning Terraform deployment..."
      
      # Create plan
      if [ -f "$var_file" ]; then
          terraform plan -var-file="$var_file" -out=tfplan
      else
          terraform plan -out=tfplan
      fi
      
      # Apply plan
      print_message "INFO" "Applying Terraform configuration..."
      if terraform apply -auto-approve tfplan; then
          print_message "SUCCESS" "Terraform apply completed successfully."
          rm -f tfplan
      else
          print_message "ERROR" "Terraform apply failed."
          rm -f tfplan
          exit 1
      fi
  }
  
  # Function to generate environment file
  generate_env_file() {
      local project_name=$1
      local env_file="${project_name}.env"
      
      print_message "INFO" "Generating environment file: $env_file"
      
      # Get the env file content from Terraform output
      if terraform output -raw env_file_content > "$env_file" 2>/dev/null; then
          chmod 600 "$env_file"
          print_message "SUCCESS" "Environment file generated: $env_file"
          print_message "INFO" "Keep this file secure - it contains sensitive credentials!"
      else
          print_message "ERROR" "Failed to generate environment file."
          exit 1
      fi
  }
  
  # Function to show usage
  show_usage() {
      cat << EOF
  Usage: $0 [command] [options]
  
  Commands:
      init              Initialize Terraform
      apply             Apply Terraform configuration
      destroy           Destroy all resources
      output            Show Terraform outputs
      env               Generate environment file only
  
  Options:
      -f, --var-file    Path to variables file (terraform.tfvars)
      -p, --project     Project name (default: tensorprox)
      -h, --help        Show this help message
  
  Examples:
      # Initialize and apply with default values
      $0 apply
  
      # Apply with custom variables file
      $0 apply -f custom.tfvars
  
      # Generate environment file for specific project
      $0 env -p myproject
  
      # Destroy all resources
      $0 destroy
  EOF
  }
  
  # Main script logic
  main() {
      local command=${1:-apply}
      local var_file=""
      local project_name="tensorprox"
      
      # Parse command line arguments
      shift
      while [[ $# -gt 0 ]]; do
          case $1 in
              -f|--var-file)
                  var_file="$2"
                  shift 2
                  ;;
              -p|--project)
                  project_name="$2"
                  shift 2
                  ;;
              -h|--help)
                  show_usage
                  exit 0
                  ;;
              *)
                  print_message "ERROR" "Unknown option: $1"
                  show_usage
                  exit 1
                  ;;
          esac
      done
      
      # Execute command
      case $command in
          init)
              check_prerequisites
              init_terraform
              ;;
          apply)
              check_prerequisites
              init_terraform
              apply_terraform "$var_file"
              generate_env_file "$project_name"
              print_message "SUCCESS" "Deployment complete!"
              ;;
          destroy)
              check_prerequisites
              print_message "INFO" "Destroying all resources..."
              if terraform destroy -auto-approve; then
                  print_message "SUCCESS" "All resources destroyed."
                  rm -f "${project_name}.env"
              else
                  print_message "ERROR" "Destroy operation failed."
                  exit 1
              fi
              ;;
          output)
              terraform output
              ;;
          env)
              generate_env_file "$project_name"
              ;;
          help)
              show_usage
              ;;
          *)
              print_message "ERROR" "Unknown command: $command"
              show_usage
              exit 1
              ;;
      esac
  }
  
  # Run main function
  main "$@"
  ```

### 1.3 main.tf 
  ```terraform
  terraform {
    required_version = ">= 1.0"
    required_providers {
      aws = {
        source  = "hashicorp/aws"
        version = "~> 5.0"
      }
      random = {
        source  = "hashicorp/random"
        version = "~> 3.6"
      }
    }
  }
  
  # Variables
  variable "project_name" {
    description = "Project name for all resources"
    type        = string
    default     = "tensorprox"
  }
  
  variable "region" {
    description = "AWS region for resources"
    type        = string
    default     = "us-east-1"
  }
  
  variable "budget_amount" {
    description = "Monthly budget limit in USD"
    type        = number
    default     = 1000
  }
  
  variable "notification_email" {
    description = "Email address for budget notifications"
    type        = string
  }
  
  variable "max_vcpus" {
    description = "Maximum vCPUs quota"
    type        = number
    default     = 16
  }
  
  variable "max_instances" {
    description = "Maximum concurrent EC2 instances"
    type        = number
    default     = 4
  }
  
  variable "max_elastic_ips" {
    description = "Maximum Elastic IPs"
    type        = number
    default     = 4
  }
  
  variable "vpc_cidr" {
    description = "CIDR block for VPC"
    type        = string
    default     = "10.0.0.0/16"
  }
  
  variable "public_subnet_cidr" {
    description = "CIDR block for public subnet"
    type        = string
    default     = "10.0.0.0/24"
  }
  
  variable "private_subnet_cidr" {
    description = "CIDR block for private subnet"
    type        = string
    default     = "10.0.1.0/24"
  }
  
  variable "machine_type" {
    description = "Default EC2 instance type"
    type        = string
    default     = "t3.medium"
  }
  
  variable "vm_size_small" {
    description = "Small VM size for King"
    type        = string
    default     = "t3.small"
  }
  
  variable "vm_size_large" {
    description = "Large VM size for Traffic Generators"
    type        = string
    default     = "t3.large"
  }
  
  variable "num_tgens" {
    description = "Number of traffic generators"
    type        = number
    default     = 2
  }
  
  variable "zone" {
    description = "Availability zone"
    type        = string
    default     = ""
  }
  
  # Provider configuration
  provider "aws" {
    region = var.region
    default_tags {
      tags = {
        Project     = var.project_name
        Environment = "production"
        ManagedBy   = "terraform"
        Purpose     = "tensorprox"
      }
    }
  }
  
  # Data sources
  data "aws_caller_identity" "current" {}
  data "aws_region" "current" {}
  data "aws_availability_zones" "available" {
    state = "available"
  }
  
  # Random ID for uniqueness
  resource "random_id" "unique" {
    byte_length = 4
  }
  
  # Local values
  locals {
    resource_prefix = "${var.project_name}-${random_id.unique.hex}"
    account_id      = data.aws_caller_identity.current.account_id
    region          = data.aws_region.current.name
    zone            = var.zone != "" ? var.zone : data.aws_availability_zones.available.names[0]
    
    # IAM names
    iam_user_name = "${local.resource_prefix}-vm-manager"
    policy_name   = "${local.resource_prefix}-minimal-ec2-policy"
    
    # Network names
    vpc_name    = "${local.resource_prefix}-vpc"
    subnet_name = "${local.resource_prefix}-subnet"
    sg_name     = "${local.resource_prefix}-sg"
    
    # Monitoring names
    budget_name   = "${local.resource_prefix}-monthly-budget"
    sns_topic_name = "${local.resource_prefix}-budget-alerts"
    log_group_name = "/aws/tensorprox/${local.resource_prefix}"
  }
  
  # IAM User
  resource "aws_iam_user" "vm_manager" {
    name = local.iam_user_name
    path = "/tensorprox/"
    
    tags = {
      Name = local.iam_user_name
    }
  }
  
  # IAM Access Key
  resource "aws_iam_access_key" "vm_manager" {
    user = aws_iam_user.vm_manager.name
  }
  
  # IAM Policy
  resource "aws_iam_policy" "vm_manager" {
    name        = local.policy_name
    path        = "/tensorprox/"
    description = "Minimal EC2 permissions for TensorProx VM management"
    
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Sid    = "EC2Management"
          Effect = "Allow"
          Action = [
            "ec2:RunInstances",
            "ec2:TerminateInstances",
            "ec2:StartInstances",
            "ec2:StopInstances",
            "ec2:RebootInstances",
            "ec2:DescribeInstances",
            "ec2:DescribeInstanceStatus",
            "ec2:DescribeInstanceTypes",
            "ec2:DescribeImages",
            "ec2:DescribeKeyPairs",
            "ec2:DescribeSecurityGroups",
            "ec2:DescribeSubnets",
            "ec2:DescribeVpcs",
            "ec2:DescribeVolumes",
            "ec2:DescribeSnapshots",
            "ec2:CreateTags",
            "ec2:DescribeTags",
            "ec2:ModifyInstanceAttribute",
            "ec2:DescribeInstanceAttribute",
            "ec2:DescribeAddresses",
            "ec2:AllocateAddress",
            "ec2:AssociateAddress",
            "ec2:DisassociateAddress",
            "ec2:ReleaseAddress",
            "ec2:CreateVolume",
            "ec2:DeleteVolume",
            "ec2:AttachVolume",
            "ec2:DetachVolume",
            "ec2:ModifyVolume",
            "ec2:DescribeNetworkInterfaces",
            "ec2:CreateNetworkInterface",
            "ec2:DeleteNetworkInterface",
            "ec2:AttachNetworkInterface",
            "ec2:DetachNetworkInterface",
            "ec2:ModifyNetworkInterfaceAttribute"
          ]
          Resource = "*"
          Condition = {
            StringEquals = {
              "aws:RequestedRegion" = var.region
            }
          }
        },
        {
          Sid    = "RequireProjectTag"
          Effect = "Allow"
          Action = [
            "ec2:RunInstances"
          ]
          Resource = [
            "arn:aws:ec2:${var.region}:${local.account_id}:instance/*",
            "arn:aws:ec2:${var.region}:${local.account_id}:volume/*",
            "arn:aws:ec2:${var.region}:${local.account_id}:network-interface/*"
          ]
          Condition = {
            StringEquals = {
              "ec2:ResourceTag/Project" = var.project_name
            }
          }
        },
        {
          Sid    = "AllowVPCAccess"
          Effect = "Allow"
          Action = [
            "ec2:RunInstances"
          ]
          Resource = [
            "arn:aws:ec2:${var.region}:${local.account_id}:subnet/${aws_subnet.public.id}",
            "arn:aws:ec2:${var.region}:${local.account_id}:subnet/${aws_subnet.private.id}",
            "arn:aws:ec2:${var.region}:${local.account_id}:security-group/${aws_security_group.gre_ipip.id}",
            "arn:aws:ec2:${var.region}:${local.account_id}:security-group/${aws_security_group.default.id}"
          ]
        },
        {
          Sid    = "AllowImageAccess"
          Effect = "Allow"
          Action = [
            "ec2:RunInstances"
          ]
          Resource = [
            "arn:aws:ec2:${var.region}::image/*"
          ]
        }
      ]
    })
  }
  
  # Attach policy to user
  resource "aws_iam_user_policy_attachment" "vm_manager" {
    user       = aws_iam_user.vm_manager.name
    policy_arn = aws_iam_policy.vm_manager.arn
  }
  
  # VPC
  resource "aws_vpc" "main" {
    cidr_block           = var.vpc_cidr
    enable_dns_hostnames = true
    enable_dns_support   = true
    
    tags = {
      Name = local.vpc_name
    }
  }
  
  # Internet Gateway
  resource "aws_internet_gateway" "main" {
    vpc_id = aws_vpc.main.id
    
    tags = {
      Name = "${local.vpc_name}-igw"
    }
  }
  
  # Public Subnet
  resource "aws_subnet" "public" {
    vpc_id                  = aws_vpc.main.id
    cidr_block              = var.public_subnet_cidr
    availability_zone       = local.zone
    map_public_ip_on_launch = true
    
    tags = {
      Name = "${local.subnet_name}-public"
      Type = "public"
    }
  }
  
  # Private Subnet
  resource "aws_subnet" "private" {
    vpc_id            = aws_vpc.main.id
    cidr_block        = var.private_subnet_cidr
    availability_zone = local.zone
    
    tags = {
      Name = "${local.subnet_name}-private"
      Type = "private"
    }
  }
  
  # Route Table for Public Subnet
  resource "aws_route_table" "public" {
    vpc_id = aws_vpc.main.id
    
    route {
      cidr_block = "0.0.0.0/0"
      gateway_id = aws_internet_gateway.main.id
    }
    
    tags = {
      Name = "${local.vpc_name}-public-rt"
    }
  }
  
  # Route Table Association for Public Subnet
  resource "aws_route_table_association" "public" {
    subnet_id      = aws_subnet.public.id
    route_table_id = aws_route_table.public.id
  }
  
  # Security Group for GRE/IPIP
  resource "aws_security_group" "gre_ipip" {
    name        = "${local.sg_name}-gre-ipip"
    description = "Allow all traffic for TensorProx"
    vpc_id      = aws_vpc.main.id
    
    # Allow ALL inbound traffic from anywhere
    ingress {
      description = "All inbound traffic"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
    
    # GRE Protocol - Explicit rule from anywhere
    ingress {
      description = "GRE Protocol"
      from_port   = 0
      to_port     = 0
      protocol    = "47"
      cidr_blocks = ["0.0.0.0/0"]
    }
    
    # IPIP Protocol - Explicit rule from anywhere
    ingress {
      description = "IPIP Protocol"
      from_port   = 0
      to_port     = 0
      protocol    = "4"
      cidr_blocks = ["0.0.0.0/0"]
    }
    
    # All outbound traffic
    egress {
      description = "All outbound traffic"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
    
    tags = {
      Name = "${local.sg_name}-gre-ipip"
    }
  }
  
  # Default Security Group
  resource "aws_security_group" "default" {
    name        = "${local.sg_name}-default"
    description = "Default security group for TensorProx"
    vpc_id      = aws_vpc.main.id
    
    # Allow ALL inbound traffic from anywhere
    ingress {
      description = "All inbound traffic"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
    
    # All outbound traffic
    egress {
      description = "All outbound traffic"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
    
    tags = {
      Name = "${local.sg_name}-default"
    }
  }
  
  # SNS Topic for Budget Alerts
  resource "aws_sns_topic" "budget_alerts" {
    name = local.sns_topic_name
    
    tags = {
      Name = local.sns_topic_name
    }
  }
  
  # SNS Topic Subscription
  resource "aws_sns_topic_subscription" "budget_alerts_email" {
    topic_arn = aws_sns_topic.budget_alerts.arn
    protocol  = "email"
    endpoint  = var.notification_email
  }
  
  # Budget
  resource "aws_budgets_budget" "monthly" {
    name         = local.budget_name
    budget_type  = "COST"
    limit_amount = tostring(var.budget_amount)
    limit_unit   = "USD"
    time_unit    = "MONTHLY"
    
    notification {
      comparison_operator        = "GREATER_THAN"
      threshold                  = 50
      threshold_type            = "PERCENTAGE"
      notification_type         = "ACTUAL"
      subscriber_sns_topic_arns = [aws_sns_topic.budget_alerts.arn]
    }
    
    notification {
      comparison_operator        = "GREATER_THAN"
      threshold                  = 80
      threshold_type            = "PERCENTAGE"
      notification_type         = "ACTUAL"
      subscriber_sns_topic_arns = [aws_sns_topic.budget_alerts.arn]
    }
    
    notification {
      comparison_operator        = "GREATER_THAN"
      threshold                  = 100
      threshold_type            = "PERCENTAGE"
      notification_type         = "ACTUAL"
      subscriber_sns_topic_arns = [aws_sns_topic.budget_alerts.arn]
    }
    
    notification {
      comparison_operator        = "GREATER_THAN"
      threshold                  = 100
      threshold_type            = "PERCENTAGE"
      notification_type         = "FORECASTED"
      subscriber_sns_topic_arns = [aws_sns_topic.budget_alerts.arn]
    }
  }
  
  # CloudWatch Log Group
  resource "aws_cloudwatch_log_group" "main" {
    name              = local.log_group_name
    retention_in_days = 7
    
    tags = {
      Name = local.log_group_name
    }
  }
  
  # VPC Flow Logs
  resource "aws_flow_log" "vpc" {
    iam_role_arn    = aws_iam_role.flow_logs.arn
    log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn
    traffic_type    = "ALL"
    vpc_id          = aws_vpc.main.id
    
    tags = {
      Name = "${local.vpc_name}-flow-logs"
    }
  }
  
  # CloudWatch Log Group for VPC Flow Logs
  resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
    name              = "/aws/vpc/${local.vpc_name}"
    retention_in_days = 7
    
    tags = {
      Name = "${local.vpc_name}-flow-logs"
    }
  }
  
  # IAM Role for VPC Flow Logs
  resource "aws_iam_role" "flow_logs" {
    name = "${local.resource_prefix}-flow-logs-role"
    
    assume_role_policy = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }]
    })
    
    tags = {
      Name = "${local.resource_prefix}-flow-logs-role"
    }
  }
  
  # IAM Policy for VPC Flow Logs
  resource "aws_iam_role_policy" "flow_logs" {
    name = "${local.resource_prefix}-flow-logs-policy"
    role = aws_iam_role.flow_logs.id
    
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Effect   = "Allow"
        Resource = "*"
      }]
    })
  }
  
  # CloudWatch Alarm for High CPU
  resource "aws_cloudwatch_metric_alarm" "high_cpu" {
    alarm_name          = "${local.resource_prefix}-high-cpu"
    comparison_operator = "GreaterThanThreshold"
    evaluation_periods  = "2"
    metric_name         = "CPUUtilization"
    namespace           = "AWS/EC2"
    period              = "300"
    statistic           = "Average"
    threshold           = "80"
    alarm_description   = "This metric monitors EC2 cpu utilization"
    treat_missing_data  = "notBreaching"
    
    alarm_actions = [aws_sns_topic.budget_alerts.arn]
    
    dimensions = {
      InstanceType = var.machine_type
    }
    
    tags = {
      Name = "${local.resource_prefix}-high-cpu"
    }
  }
  
  # CloudWatch Alarm for vCPU Usage
  resource "aws_cloudwatch_metric_alarm" "vcpu_usage" {
    alarm_name          = "${local.resource_prefix}-vcpu-usage"
    comparison_operator = "GreaterThanThreshold"
    evaluation_periods  = "1"
    metric_name         = "ResourceCount"
    namespace           = "AWS/Usage"
    period              = "300"
    statistic           = "Maximum"
    threshold           = tostring(var.max_vcpus * 0.8)
    alarm_description   = "Alert when vCPU usage exceeds 80% of quota"
    treat_missing_data  = "notBreaching"
    
    alarm_actions = [aws_sns_topic.budget_alerts.arn]
    
    dimensions = {
      Type     = "Resource"
      Resource = "vCPU"
      Service  = "EC2"
      Class    = "Standard/OnDemand"
    }
    
    tags = {
      Name = "${local.resource_prefix}-vcpu-usage"
    }
  }
  
  # Secrets Manager Secret for Access Keys
  resource "aws_secretsmanager_secret" "access_keys" {
    name = "${local.resource_prefix}-access-keys"
    
    tags = {
      Name = "${local.resource_prefix}-access-keys"
    }
  }
  
  # Secrets Manager Secret Version
  resource "aws_secretsmanager_secret_version" "access_keys" {
    secret_id = aws_secretsmanager_secret.access_keys.id
    secret_string = jsonencode({
      access_key_id     = aws_iam_access_key.vm_manager.id
      secret_access_key = aws_iam_access_key.vm_manager.secret
    })
  }
  
  # Outputs
  output "project_id" {
    description = "Project identifier"
    value       = var.project_name
  }
  
  output "region" {
    description = "AWS region"
    value       = var.region
  }
  
  output "zone" {
    description = "Availability zone"
    value       = local.zone
  }
  
  output "vpc_name" {
    description = "VPC name"
    value       = local.vpc_name
  }
  
  output "subnet_name" {
    description = "Subnet name"
    value       = "${local.subnet_name}-public"
  }
  
  output "vpc_id" {
    description = "VPC ID"
    value       = aws_vpc.main.id
  }
  
  output "public_subnet_id" {
    description = "Public subnet ID"
    value       = aws_subnet.public.id
  }
  
  output "private_subnet_id" {
    description = "Private subnet ID"
    value       = aws_subnet.private.id
  }
  
  output "security_group_id" {
    description = "GRE/IPIP security group ID"
    value       = aws_security_group.gre_ipip.id
  }
  
  output "service_account_email" {
    description = "IAM user name (service account equivalent)"
    value       = aws_iam_user.vm_manager.name
  }
  
  output "service_account_key_path" {
    description = "Path to service account key (not applicable for AWS)"
    value       = "Use AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables"
  }
  
  output "iam_user_arn" {
    description = "IAM user ARN"
    value       = aws_iam_user.vm_manager.arn
  }
  
  output "access_key_id" {
    description = "IAM access key ID"
    value       = aws_iam_access_key.vm_manager.id
    sensitive   = true
  }
  
  output "secret_access_key" {
    description = "IAM secret access key"
    value       = aws_iam_access_key.vm_manager.secret
    sensitive   = true
  }
  
  output "resource_prefix" {
    description = "Resource prefix for all created resources"
    value       = local.resource_prefix
  }
  
  output "budget_name" {
    description = "Budget name"
    value       = local.budget_name
  }
  
  output "sns_topic_arn" {
    description = "SNS topic ARN for alerts"
    value       = aws_sns_topic.budget_alerts.arn
  }
  
  output "machine_type" {
    description = "Default EC2 instance type"
    value       = var.machine_type
  }
  
  output "vm_size_small" {
    description = "Small VM size for King"
    value       = var.vm_size_small
  }
  
  output "vm_size_large" {
    description = "Large VM size for Traffic Generators"
    value       = var.vm_size_large
  }
  
  output "max_instances" {
    description = "Maximum concurrent instances"
    value       = var.max_instances
  }
  
  output "num_tgens" {
    description = "Number of traffic generators"
    value       = var.num_tgens
  }
  
  output "env_file_content" {
    description = "Environment file content for miner configuration"
    sensitive   = true
    value = <<-EOF
  # Bittensor Configuration
  NETUID=234/91
  SUBTENSOR_NETWORK="test/finney"
  SUBTENSOR_CHAIN_ENDPOINT="wss://test.finney.opentensor.ai:443"
  WALLET_NAME="start"
  HOTKEY="test-miner2"
  AXON_PORT="22181"
  
  # Cloud Provider Selection
  PROVIDER=AWS
  
  # Generic Cloud Credentials
  CLOUD_PROJECT_ID=${data.aws_caller_identity.current.account_id}
  CLOUD_AUTH_ID=${aws_iam_access_key.vm_manager.id}
  CLOUD_AUTH_SECRET="${aws_iam_access_key.vm_manager.secret}"
  CLOUD_RESOURCE_GROUP=${aws_security_group.gre_ipip.id}
  
  # Generic Network Configuration
  VPC_NAME=${aws_vpc.main.id}
  SUBNET_NAME=${aws_subnet.public.id}
  
  # Generic Compute Configuration
  REGION=${local.zone}
  VM_SIZE_SMALL=${var.vm_size_small}
  VM_SIZE_LARGE=${var.vm_size_large}
  NUM_TGENS=${var.num_tgens}
  
  # Optional: Custom VM Specifications for King
  # CUSTOM_KING_CPU_COUNT=2
  # CUSTOM_KING_RAM_MB=4096
  
  # Optional: Custom VM Specifications for TGens
  # CUSTOM_TGEN_CPU_COUNT=8
  # CUSTOM_TGEN_RAM_MB=16384
  
  # ===== END OF MINER RELEVANT SECTION =====
  # Additional AWS-specific information below
  
  # AWS Specific Details
  AWS_REGION=${var.region}
  AWS_ZONE=${local.zone}
  AWS_ACCESS_KEY_ID=${aws_iam_access_key.vm_manager.id}
  AWS_SECRET_ACCESS_KEY=${aws_iam_access_key.vm_manager.secret}
  VPC_ID=${aws_vpc.main.id}
  PUBLIC_SUBNET_ID=${aws_subnet.public.id}
  PRIVATE_SUBNET_ID=${aws_subnet.private.id}
  SECURITY_GROUP_ID=${aws_security_group.gre_ipip.id}
  
  # Project Information
  PROJECT_NAME=${var.project_name}
  RESOURCE_PREFIX=${local.resource_prefix}
  MACHINE_TYPE=${var.machine_type}
  MAX_INSTANCES=${var.max_instances}
  
  # IAM Resources
  IAM_USER_ARN=${aws_iam_user.vm_manager.arn}
  IAM_POLICY_ARN=${aws_iam_policy.vm_manager.arn}
  SERVICE_ACCOUNT_EMAIL=${aws_iam_user.vm_manager.name}
  
  # Monitoring Resources
  SNS_TOPIC_ARN=${aws_sns_topic.budget_alerts.arn}
  BUDGET_NAME=${local.budget_name}
  CLOUDWATCH_LOG_GROUP=${local.log_group_name}
  EOF
  }
  ```

## 2. Quick Start

 ### 2.1 Prerequisites
   - Terraform 1.0 or later
   - AWS CLI v2 configured with credentials
   - An AWS account with appropriate permissions
   
   Example setup in AWS native (GUI-)Shell:
   ```bash
   wget https://releases.hashicorp.com/terraform/1.12.2/terraform_1.12.2_linux_amd64.zip
   unzip terraform_1.12.2_linux_amd64.zip
   chmod +x terraform
   ./terraform version
   export PATH=$PATH:.
   ```   

 ### 2.2 Configuration
   ```bash
   mkdir anything
   cd anything
   # Create the variables file
   cat > terraform.tfvars
   
   # Edit terraform.tfvars with your values
   # IMPORTANT: Set your notification_email
   ```

### 2.3 Deploy
   ```bash
   # Initialize and deploy everything
   ./deploy.sh apply
   
   # Or with custom variables file
   ./deploy.sh apply -f custom.tfvars
   ```

### 2.4 Get Environment File
   The deployment automatically generates a `${project_name}.env` file with all necessary configuration for TensorProx miners.

## 3. Usage

### Deploy Infrastructure
```bash
./deploy.sh apply
```

### Destroy Infrastructure
```bash
./deploy.sh destroy
```

### View Outputs
```bash
./deploy.sh output
```

### Regenerate Environment File
```bash
./deploy.sh env -p myproject
```

## Configuration Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `project_name` | Project identifier | tensorprox |
| `region` | AWS region | us-east-1 |
| `zone` | Availability zone | First available |
| `budget_amount` | Monthly budget in USD | 1000 |
| `notification_email` | Email for alerts | Required |
| `max_vcpus` | vCPU quota | 16 |
| `max_instances` | Instance quota | 4 |
| `machine_type` | Default EC2 type | e3.medium |
| `vm_size_small` | King instance type | e3.small |
| `vm_size_large` | TGen instance type | e3.large |

### Environment File Format

The generated `.env` file is compatible with TensorProx miners and includes:
- Bittensor configuration placeholders
- Cloud provider credentials
- Network configuration
- Compute specifications
- AWS-specific settings

### Security Notes

1. The IAM user has minimal permissions scoped to EC2 operations
2. All resources are tagged for easy identification
3. Network access is controlled via security groups

## 4. Upload an SSH Key

Browse to KeyPairs and upload your public SSH Key

## 5. Deploying EC2 Instances

With the generated credentials, you can deploy EC2 instances with the 10.0.0.4 IP for your moat:

Example includes launch from local shell. Exports can be skipped if navigating in AWS native shell. 

Replace:
- `moat` → instance name
- `e3.medium` → with desired instance type for your moat
- `subnet-007ba1o1fb80j9d5e` → from your run.tf `.env` + replace in `subnet-id` 
- `sg-04170bcffe7cf58f3` → from your run.tf `.env` + replace in `security-group-ids`  
- `your_key_name_here` → name of your ssh key, uploaded to aws 


```bash
# Example using AWS CLI with the generated credentials
export AWS_ACCESS_KEY_ID=<from-env-file>
export AWS_SECRET_ACCESS_KEY=<from-env-file>

# Launch instance with specific private IP
aws ec2 run-instances \
    --image-id $(aws ec2 describe-images --owners 099720109477 --filters "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*" "Name=state,Values=available" --query 'Images | sort_by(@, 
  &CreationDate) | [-1].ImageId' --output text) \
    --instance-type e3.medium \
    --subnet-id subnet-007ba1o1fb80j9d5e \
    --security-group-ids sg-04170bcffe7cf58f3 \
    --private-ip-address 10.0.0.4 \
    --key-name your_key_name_here \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Project,Value=tensorprox},{Key=Name,Value=moat}]' 
```
standard user on aws: `ubuntu`


### 6. System Setup

```bash
sudo apt update && sudo apt install python3-pip -y && sudo apt install python3-venv -y
sudo apt install npm -y && sudo npm install -g pm2 
python3 -m venv tp && source tp/bin/activate
```

---

### 7. Clone Miner and Install Dependencies

```bash
git clone https://github.com/shugo-labs/tensorprox.git
cd tensorprox
pip install -r requirements.txt
```

---

### 8. Create `.env.miner`

Simply copy the relevant parts from [your Shell .env](https://github.com/shugo-labs/tensorprox/edit/hyperscaler2/assets/aws_setup.md#24-get-environment-file)

```bash
nano .env.miner // use .env.miner.example
```

copy contents from Shell .env  
Paste

---

### 9. Start the Miner

```bash
pm2 start "python3 neurons/miner.py" --name miner
```

---

### 10. Check Miner Status

```bash
pm2 list
```

---

### 11. View Miner Logs

```bash
pm2 logs miner
```

---

**Done.** You have a miner running in a controlled AWS environment, provisioned end-to-end using Terraform and PM2.


## Troubleshooting

1. **Terraform init fails**: Check AWS credentials and internet connectivity
2. **Apply fails**: Verify you have permissions to create IAM resources
3. **Budget alerts not working**: Confirm email subscription in AWS SNS
4. **Can't assign private IPs**: Ensure the IP is within the subnet CIDR range

## Cost Estimates

- VPC and networking: ~$0/month (no NAT Gateway)
- EC2 instances: Variable based on usage
- CloudWatch: ~$5/month
- SNS/Budget: <$1/month
- Total fixed costs: ~$6/month + instance usage
