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

## 2. Quick Start

 ### 2.1 Prerequisites
   - Terraform 1.0 or later
   - AWS CLI v2 configured with credentials
   - An AWS account with appropriate permissions

 ### 2.2 Configuration
   ```bash
   # Copy the example variables file
   cp terraform.tfvars.example terraform.tfvars
   
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
| `max_vcpus` | vCPU quota | 8 |
| `max_instances` | Instance quota | 4 |
| `machine_type` | Default EC2 type | t3.medium |
| `vm_size_small` | King instance type | t3.small |
| `vm_size_large` | TGen instance type | t3.large |

### Environment File Format

The generated `.env` file is compatible with TensorProx miners and includes:
- Bittensor configuration placeholders
- Cloud provider credentials
- Network configuration
- Compute specifications
- AWS-specific settings

### Security Notes

1. The generated `.env` file contains sensitive credentials - keep it secure!
2. The IAM user has minimal permissions scoped to EC2 operations
3. All resources are tagged for easy identification
4. Network access is controlled via security groups

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
