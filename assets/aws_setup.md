# TensorProx AWS Unified Terraform Configuration

This directory contains a single, unified Terraform configuration file (`main.tf`) that creates all necessary AWS resources for TensorProx infrastructure.

## Overview

The configuration creates:
- IAM user with minimal EC2 permissions
- VPC with public and private subnets
- Security groups supporting GRE (protocol 47) and IPIP (protocol 4)
- Budget monitoring with email alerts
- CloudWatch logging and alarms
- All necessary supporting resources

## Quick Start

1. **Prerequisites**
   - Terraform 1.0 or later
   - AWS CLI v2 configured with credentials
   - An AWS account with appropriate permissions

2. **Configuration**
   ```bash
   # Copy the example variables file
   cp terraform.tfvars.example terraform.tfvars
   
   # Edit terraform.tfvars with your values
   # IMPORTANT: Set your notification_email
   ```

3. **Deploy**
   ```bash
   # Initialize and deploy everything
   ./deploy.sh apply
   
   # Or with custom variables file
   ./deploy.sh apply -f custom.tfvars
   ```

4. **Get Environment File**
   The deployment automatically generates a `${project_name}.env` file with all necessary configuration for TensorProx miners.

## Usage

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
| `max_vcpus` | vCPU quota | 8 |
| `max_instances` | Instance quota | 4 |
| `machine_type` | Default EC2 type | t3.medium |
| `vm_size_small` | King instance type | t3.small |
| `vm_size_large` | TGen instance type | t3.large |

## Environment File Format

The generated `.env` file is compatible with TensorProx miners and includes:
- Bittensor configuration placeholders
- Cloud provider credentials
- Network configuration
- Compute specifications
- AWS-specific settings

## Security Notes

1. The generated `.env` file contains sensitive credentials - keep it secure!
2. The IAM user has minimal permissions scoped to EC2 operations
3. All resources are tagged for easy identification
4. Network access is controlled via security groups

## Deploying EC2 Instances

With the generated credentials, you can deploy EC2 instances with predetermined private IPs:

```bash
# Example using AWS CLI with the generated credentials
export AWS_ACCESS_KEY_ID=<from-env-file>
export AWS_SECRET_ACCESS_KEY=<from-env-file>

# Launch instance with specific private IP
aws ec2 run-instances \
  --image-id ami-xxxxxxxxx \
  --instance-type t3.medium \
  --subnet-id <PUBLIC_SUBNET_ID> \
  --security-group-ids <SECURITY_GROUP_ID> \
  --private-ip-address 10.0.0.10 \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Project,Value=tensorprox}]'
```

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
