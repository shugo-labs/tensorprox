# Miners

🐧 **Required OS:** Ubuntu 22.04  |  🐍 **Required Python:** Python 3.10

## Compute Requirements

### 🛡️ What the Miner Firewall Does ?

The Miner machine acts as a real-time traffic firewall during challenge rounds:

- 🕵️‍♂️ Sniffs live traffic using tools like libpcap, AF_PACKET, nfqueue, or raw sockets
- 🤖 Analyzes packets on the fly using a lightweight ML or rule-based DDoS detection model
- 🚦 Makes immediate decisions to allow, block, or drop traffic
- 🔌 Listens on multiple interfaces (e.g., gre-tgen-0, gre-tgen-1, ...) — one per traffic generator

| Resource  | Requirement   |
|-----------|---------------|
| VRAM      | None          |
| vCPU      | 8 vCPU        |
| RAM       | 8 GB          |
| Storage   | 80 GB         |
| Network   | >= 1 Gbps     |

## 🚀 Scalable Participation

Miners must provide access to the traffic generation and King machines via Service Accounts on Cloud Providers. 
However, they can insert machines of any size or capacity into their .env.miner files. The traffic generation automatically scales to the capability of the machines, ensuring lightweight traffic on lower-tier setups and progressively increasing load as performance scales.
This makes it possible to get started with even modest VPS, while encouraging scale-up for higher rewards.

## Overview

This document provides a complete setup guide for deploying a miner on Google Cloud using Terraform and a wrapper Shell script.

---

## SECTION 1: Prepare the Environment (Cloud Shell Setup)
Repeat this Section for every UID you want to operate on GCP. Create a project in a different Region and keep files in their distinct directory via `mkir`.
startup.tf processes every GCP operation including: 

- Project Setup (Name, Region, links to default Billing Account)
- VPC Setup
- Firewall Rules for flexible usage
- Least, but working Permissions on Service Account
- Restricts Service Account to Project Region (= Subject to regional Quota = low damage if malused)
- Sets up Budget Alert (Please adjust `variable "base_amount"` - default is 1000 - Currency is dynamic) 
- Sets up monitoring logs for Service Account (you can follow up with custom Actions to refine Account restrictions / Security) 

### 0. Pre-Requisites

- Ensure a **Billing Account** exists and is active.
- visit [Google Library](https://console.cloud.google.com/apis/library/) 
- Enable the following APIs (use Searchbar):
  - `Cloud Billing API`
  - `Cloud Billing Budget API`
  - `Cloud Resource Manager API`
  - `Cloud Pub/Sub API`
  - `Identity and Access Management (IAM) API`
    
- Cloud Shell Session with an already active Project set. This is indicated by a yellow `(projectid)`
- If no active Session, please run `gcloud config set project projectid`
  This must be a project were you have Billing Account active + the above mentioned APIs. 

---

### 1. Open Google Cloud Shell

Click the terminal icon in the top right corner, or press `G` then `S`.

---

### 2. Prepare Project Directory

```bash
mkdir ProjectOne
cd ProjectOne
```

---

### 3. Create Required Files

#### 3.1 Create `startup.tf`

```bash
cat > startup.tf
```

Paste the full `startup.tf` contents below, then press `Enter`, followed by `CTRL+D`.

```terraform
# startup.tf - Comprehensive One-Click Project Setup

# Provider Configuration
terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.0"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2.0"
    }
  }
}

provider "google" {
  # Credentials via GOOGLE_APPLICATION_CREDENTIALS or gcloud auth
}

# Variables
variable "project_name" {
  description = "Name of the project (e.g., My-Project-Name). Used to derive unique Project ID and resource names."
  type        = string
}

variable "region" {
  description = "GCP region for resources. If unset, Terraform prompts. Available regions: us-central1, us-east1, us-west1, europe-west1, asia-east1, etc. See https://cloud.google.com/compute/docs/regions-zones"
  type        = string
  default     = null  # Prompts if not set
}

variable "max_vcpus" {
  description = "Maximum vCPUs quota."
  type        = number
  default     = 8
}

variable "max_concurrent_vms" {
  description = "Maximum concurrent VMs quota."
  type        = number
  default     = 4
}

variable "base_amount" {
  description = "Base budget amount."
  type        = number
  default     = 1000
}

variable "budget_name" {
  description = "Name of the budget."
  type        = string
  default     = "TensorProx Monthly Budget"
}

variable "topic_name" {
  description = "Name of the Pub/Sub topic for budget alerts."
  type        = string
  default     = "budget-alerts"
}

variable "billing_account_id" {
  description = "Optional manual billing account ID (e.g., 01C509-917B5F-913AA1). If not set, auto-fetches."
  type        = string
  default     = ""
}

# Derived Project ID (unique, compliant: lowercase, hyphens)
locals {
  project_id       = lower(replace(var.project_name, " ", "-"))
  derived_vpc_name = "${local.project_id}-vpc"
  sa_name          = "${local.project_id}-vm-manager"
  sa_email         = "${local.sa_name}@${local.project_id}.iam.gserviceaccount.com"
  custom_role_id   = "tensorproxMinimalValidator"
  # Extract only the private key from the decoded JSON
  decoded_key      = jsondecode(base64decode(google_service_account_key.vm_manager_key.private_key))
  private_key      = local.decoded_key.private_key
}

# Fetch First Open Billing Account ID (via gcloud, with fallback if empty)
data "external" "get_billing_account" {
  program = ["bash", "-c", "gcloud billing accounts list --filter='open=true' --format='value(name)' | head -1 | jq -R '{id: .}' || echo '{\"id\": \"\"}'"]
}

# Propagation delay for billing fetch
resource "null_resource" "billing_propagation_delay" {
  provisioner "local-exec" {
    command = "sleep 10"  # Short delay for auth propagation
  }
  depends_on = [data.external.get_billing_account]
}

# Data: Billing Account (using fetched or manual ID)
data "google_billing_account" "billing" {
  count           = (var.billing_account_id != "" ? 1 : (data.external.get_billing_account.result["id"] != "" ? 1 : 0))
  billing_account = (var.billing_account_id != "" ? var.billing_account_id : data.external.get_billing_account.result["id"])
  depends_on      = [null_resource.billing_propagation_delay]
}

# Fetch Currency Code from Billing Account (conditional)
data "external" "get_currency_code" {
  count      = length(data.google_billing_account.billing) > 0 ? 1 : 0
  program    = ["bash", "-c", "gcloud billing accounts describe ${data.google_billing_account.billing[0].billing_account} --format='value(currencyCode)' | jq -R '{currency: .}' || echo '{\"currency\": \"USD\"}'"]
  depends_on = [data.google_billing_account.billing]
}

# Step 1: Create Project with Billing Linked (always, but idempotent with lifecycle)
resource "google_project" "project" {
  name            = var.project_name
  project_id      = local.project_id
  billing_account = try(data.google_billing_account.billing[0].id, null)
  depends_on      = [data.external.get_billing_account]

  lifecycle {
    prevent_destroy = true
    ignore_changes  = [number, auto_create_network]  # Ignore if already exists
  }
}

# Delay for project propagation
resource "null_resource" "project_delay" {
  provisioner "local-exec" {
    command = "sleep 30"  # Wait for project to propagate
  }
  depends_on = [google_project.project]
}

# Reference Project (after creation)
data "google_project" "project" {
  project_id = local.project_id
  depends_on = [null_resource.project_delay]
}

# Use project ID
locals {
  effective_project_id = data.google_project.project.project_id
  effective_project_number = data.google_project.project.number
}

# Enable Cloud Resource Manager API (idempotent)
resource "google_project_service" "resource_manager" {
  project                    = local.effective_project_id
  service                    = "cloudresourcemanager.googleapis.com"
  disable_dependent_services = false
  disable_on_destroy         = false

  lifecycle {
    prevent_destroy = true
  }
  depends_on = [null_resource.project_delay]
}

# Enable IAM API (idempotent)
resource "google_project_service" "iam" {
  project                    = local.effective_project_id
  service                    = "iam.googleapis.com"
  disable_dependent_services = false
  disable_on_destroy         = false

  lifecycle {
    prevent_destroy = true
  }
  depends_on = [null_resource.project_delay]
}

# Enable Pub/Sub API (idempotent)
resource "google_project_service" "pubsub" {
  project                    = local.effective_project_id
  service                    = "pubsub.googleapis.com"
  disable_dependent_services = false
  disable_on_destroy         = false

  lifecycle {
    prevent_destroy = true
  }
  depends_on = [null_resource.project_delay]
}

# Step 2: Enable Critical APIs (idempotent)
resource "google_project_service" "compute" {
  project                    = local.effective_project_id
  service                    = "compute.googleapis.com"
  disable_dependent_services = false
  depends_on                 = [null_resource.project_delay]

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_project_service" "serviceusage" {
  project                    = local.effective_project_id
  service                    = "serviceusage.googleapis.com"
  disable_dependent_services = false
  depends_on                 = [null_resource.project_delay]

  lifecycle {
    prevent_destroy = true
  }
}

# Step 3: Enable Additional APIs (idempotent)
resource "google_project_service" "additional_apis" {
  for_each = toset([
    "iam.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "billingbudgets.googleapis.com",
    "cloudbilling.googleapis.com",
    "pubsub.googleapis.com"  # Added for Pub/Sub topic
  ])
  project                    = local.effective_project_id
  service                    = each.value
  disable_dependent_services = false
  depends_on                 = [google_project_service.compute, google_project_service.serviceusage, null_resource.project_delay]

  lifecycle {
    prevent_destroy = true
  }
}

# Propagation Delay for API Enablement
resource "null_resource" "api_propagation_delay" {
  provisioner "local-exec" {
    command = "sleep 60"  # Wait 1 minute for API propagation
  }
  depends_on = [google_project_service.compute, google_project_service.serviceusage, google_project_service.additional_apis]
}

# Step 4: Set Quotas (local-exec; no direct resource)
resource "null_resource" "set_quotas" {
  provisioner "local-exec" {
    command = <<EOT
gcloud alpha services quota update --service=compute.googleapis.com \
  --consumer="projects/${local.effective_project_id}" \
  --limit-name=CPUS --dimensions="regions=${var.region}" \
  --value=${var.max_vcpus} || echo "Quota update failed; check permissions"

gcloud alpha services quota update --service=compute.googleapis.com \
  --consumer="projects/${local.effective_project_id}" \
  --limit-name=INSTANCES --dimensions="regions=${var.region}" \
  --value=${var.max_concurrent_vms} || echo "Quota update failed; check permissions"
EOT
  }
  depends_on = [null_resource.api_propagation_delay]
}

# Step 5: Service Account Creation
resource "google_service_account" "vm_manager" {
  account_id   = local.sa_name
  display_name = "VM Manager"
  project      = local.effective_project_id
  depends_on   = [null_resource.set_quotas, google_project_service.iam]  # Ensure IAM API is enabled
}

# Fetch the default Compute Engine service account
data "google_compute_default_service_account" "default" {
  project = local.effective_project_id
  depends_on = [google_project_service.compute]
}

# Bind iam.serviceAccountUser role to the custom SA on the default Compute SA
resource "google_service_account_iam_member" "default_sa_user" {
  service_account_id = data.google_compute_default_service_account.default.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.vm_manager.email}"
  depends_on         = [google_service_account.vm_manager, data.google_compute_default_service_account.default]
}

# Create Service Account Key
resource "google_service_account_key" "vm_manager_key" {
  service_account_id = google_service_account.vm_manager.name
  public_key_type    = "TYPE_X509_PEM_FILE"
  depends_on         = [google_service_account.vm_manager]
}

# Create Custom IAM Role (using native Terraform resource for better integration)
resource "google_project_iam_custom_role" "custom_role" {
  role_id     = local.custom_role_id
  title       = "TensorProx Minimal Validator Role"
  description = "Minimal permissions for validators"
  permissions = [
    "compute.networks.get",
    "compute.subnetworks.get",
    "compute.subnetworks.use",  # Added for subnetwork access during VM creation
    "compute.subnetworks.useExternalIp",
    "compute.addresses.create",
    "compute.addresses.get",
    "compute.addresses.list",
    "compute.addresses.delete",
    "compute.addresses.use", 
    "compute.instances.create",
    "compute.instances.list",
    "compute.instances.get",
    "compute.instances.delete",
    "compute.instances.setMetadata",
    "compute.disks.create",
    "compute.machineTypes.get",
    "compute.images.useReadOnly",
    "compute.zoneOperations.get",
    "compute.regionOperations.get",
    "compute.acceleratorTypes.get",
    "compute.acceleratorTypes.list",
    "compute.instances.setServiceAccount"
  ]
  project = local.effective_project_id
  stage   = "GA"
  depends_on = [google_service_account.vm_manager, google_project_service.compute]
}

# Bind Custom Role to Service Account with Region Restriction (for zonal resources like instances)
resource "google_project_iam_member" "bind_custom_role_zonal" {
  project = local.effective_project_id
  role    = google_project_iam_custom_role.custom_role.name
  member  = "serviceAccount:${google_service_account.vm_manager.email}"
  condition {
    title       = "Restrict to Project Region"
    description = "Allow VM creations only in ${var.region} zones"
    expression  = "resource.service == \"compute.googleapis.com\" && resource.name.startsWith(\"projects/${local.project_id}/zones/${var.region}-\")"
  }
  depends_on = [google_project_iam_custom_role.custom_role]
}

# Bind Custom Role to Service Account without condition (for regional/project-level permissions like addresses.create and instances.list)
resource "google_project_iam_member" "bind_custom_role_unrestricted" {
  project = local.effective_project_id
  role    = google_project_iam_custom_role.custom_role.name
  member  = "serviceAccount:${google_service_account.vm_manager.email}"
  # No condition here to allow regional and project-wide access
  depends_on = [google_project_iam_custom_role.custom_role]
}

# Bind compute.networkUser role to Service Account (equivalent to the manual gcloud command)
resource "google_project_iam_member" "network_user" {
  project = local.effective_project_id
  role    = "roles/compute.networkUser"
  member  = "serviceAccount:${google_service_account.vm_manager.email}"
  depends_on = [google_project_iam_member.bind_custom_role_zonal, google_project_iam_member.bind_custom_role_unrestricted]
}

# Create Logging Metrics (idempotent via local-exec)
resource "null_resource" "logging_metrics" {
  provisioner "local-exec" {
    command = <<EOT
gcloud logging metrics create tensorprox_vm_creations --quiet \
  --project=${local.effective_project_id} \
  --description="VM creations by service account" \
  --log-filter="resource.type=\\\"gce_instance\\\" AND \
protoPayload.methodName=\\\"v1.compute.instances.insert\\\" AND \
protoPayload.authenticationInfo.principalEmail=\\\"${google_service_account.vm_manager.email}\\\"" \
  >/dev/null 2>&1 || true

gcloud logging metrics create tensorprox_vm_count --quiet \
  --project=${local.effective_project_id} \
  --description="Count of VMs created by service account" \
  --log-filter="resource.type=\\\"gce_instance\\\" AND \
protoPayload.methodName=\\\"v1.compute.instances.insert\\\" AND \
protoPayload.authenticationInfo.principalEmail=\\\"${google_service_account.vm_manager.email}\\\"" \
  --metric-kind="CUMULATIVE" \
  --value-type="INT64" \
  >/dev/null 2>&1 || true
EOT
  }
  depends_on = [google_project_iam_member.bind_custom_role_zonal, google_project_iam_member.bind_custom_role_unrestricted]
}

# Create Pub/Sub Topic
resource "google_pubsub_topic" "budget_alerts" {
  name    = var.topic_name
  project = local.effective_project_id
  depends_on = [google_project_service.pubsub]  # Ensure Pub/Sub API is enabled
}

# Create Budget (using native Terraform resource, with validation)
resource "google_billing_budget" "budget" {
  count           = length(data.google_billing_account.billing) > 0 ? 1 : 0
  billing_account = data.google_billing_account.billing[0].id
  display_name    = var.budget_name
  amount {
    specified_amount {
      currency_code = try(data.external.get_currency_code[0].result["currency"], "USD")
      units         = var.base_amount
      nanos         = 0  # Explicitly set to avoid invalid argument
    }
  }
  budget_filter {
    projects = ["projects/${local.effective_project_number}"]
  }
  threshold_rules {
    threshold_percent = 0.5
  }
  threshold_rules {
    threshold_percent = 0.8
  }
  threshold_rules {
    threshold_percent = 1.0
    spend_basis = "CURRENT_SPEND"
  }
  all_updates_rule {
    pubsub_topic = google_pubsub_topic.budget_alerts.id
  }
  depends_on = [google_pubsub_topic.budget_alerts, data.external.get_currency_code, google_project_service.additional_apis["billingbudgets.googleapis.com"], google_project_service.additional_apis["cloudbilling.googleapis.com"]]
}

# Original VPC/Subnet/Firewall (Runs After SA Setup)
data "google_client_config" "current" {}

resource "google_compute_network" "vpc" {
  name                                      = local.derived_vpc_name
  project                                   = local.effective_project_id
  auto_create_subnetworks                   = false
  mtu                                       = 1500
  routing_mode                              = "REGIONAL"
  network_firewall_policy_enforcement_order = "AFTER_CLASSIC_FIREWALL"
  depends_on                                = [google_billing_budget.budget, google_project_service.compute]  # Explicit dependency on compute API
}

resource "google_compute_firewall" "allow_gre_ipip_out" {
  name               = "${local.derived_vpc_name}-allow-gre-ipip-out"
  network            = google_compute_network.vpc.self_link
  project            = local.effective_project_id
  direction          = "EGRESS"
  priority           = 99
  destination_ranges = ["0.0.0.0/0"]
  allow { protocol = "ipip" }
  allow { protocol = "47" }
  depends_on         = [google_compute_network.vpc]
}

resource "google_compute_firewall" "allow_gre_ipip_in" {
  name          = "${local.derived_vpc_name}-allow-gre-ipip-in"
  network       = google_compute_network.vpc.self_link
  project       = local.effective_project_id
  direction     = "INGRESS"
  priority      = 100
  source_ranges = ["0.0.0.0/0"]
  allow { protocol = "ipip" }
  allow { protocol = "47" }
  depends_on    = [google_compute_network.vpc]
}

resource "google_compute_firewall" "standard_out" {
  name               = "${local.derived_vpc_name}-standard-out"
  network            = google_compute_network.vpc.self_link
  project            = local.effective_project_id
  direction          = "EGRESS"
  priority           = 100
  destination_ranges = ["0.0.0.0/0"]
  allow { protocol = "all" }
  depends_on         = [google_compute_network.vpc]
}

resource "google_compute_firewall" "standard_in" {
  name          = "${local.derived_vpc_name}-standard-in"
  network       = google_compute_network.vpc.self_link
  project       = local.effective_project_id
  direction     = "INGRESS"
  priority      = 100
  source_ranges = ["0.0.0.0/0"]
  allow { protocol = "all" }
  depends_on    = [google_compute_network.vpc]
}

resource "google_compute_subnetwork" "battleground_24" {
  name                     = "${local.derived_vpc_name}-24"
  ip_cidr_range            = "10.0.0.0/24"
  region                   = var.region
  network                  = google_compute_network.vpc.self_link
  project                  = local.effective_project_id
  private_ip_google_access = true
  purpose                  = "PRIVATE"
  stack_type               = "IPV4_ONLY"
  secondary_ip_range {
    range_name    = "ipip-range"
    ip_cidr_range = "192.168.0.0/16"
  }
  depends_on = [google_compute_network.vpc]
}

# Outputs for .env.miner Block
output "env_miner_non_sensitive" {
  value = <<EOF
CLOUD_PROJECT_ID=${local.effective_project_id}
CLOUD_AUTH_ID=${google_service_account.vm_manager.email}
VPC_NAME=${google_compute_network.vpc.name}
SUBNET_NAME=${google_compute_subnetwork.battleground_24.name}
REGION=${var.region}
CLOUD_RESOURCE_GROUP=  # Not used by GCP, leave empty
EOF
  depends_on = [google_compute_subnetwork.battleground_24]
}

output "cloud_auth_secret" {
  sensitive = true
  value     = local.private_key
}
```


---

#### 3.2 Create `deploy.sh`

```bash
cat > deploy.sh
```

Paste the full `deploy.sh` contents below, then press `Enter`, followed by `CTRL+D`.

```bash
#!/bin/bash

# Function to display and select region interactively
select_region() {
  echo "Select a GCP region (use arrows and Enter):"
  regions=(
    "asia-east1"
    "asia-east2"
    "asia-northeast1"
    "asia-northeast2"
    "asia-northeast3"
    "asia-south1"
    "asia-southeast1"
    "asia-southeast2"
    "australia-southeast1"
    "australia-southeast2"
    "europe-central2"
    "europe-north1"
    "europe-west1"
    "europe-west2"
    "europe-west3"
    "europe-west4"
    "europe-west6"
    "northamerica-northeast1"
    "northamerica-northeast2"
    "southamerica-east1"
    "southamerica-west1"
    "us-central1"
    "us-east1"
    "us-east4"
    "us-west1"
    "us-west2"
    "us-west3"
    "us-west4"
  )
  select region in "${regions[@]}"; do
    if [[ -n $region ]]; then
      echo "Selected region: $region"
      break
    else
      echo "Invalid selection. Please try again."
    fi
  done
}

# Check for valid GCP credentials with token fallback
check_auth() {
  echo "Checking GCP authentication..."
  
  # Detect if running in Cloud Shell
  if [ -n "$GOOGLE_CLOUD_SHELL" ]; then
    echo "Detected Cloud Shell environment. Using access token for auth."
  fi
  
  # Check for active gcloud account
  ACTIVE_ACCOUNT=$(gcloud config get-value account 2>/dev/null)
  if [ -z "$ACTIVE_ACCOUNT" ]; then
    echo "No active gcloud account found. Run 'gcloud auth login' and answer 'Y' to any prompts."
    exit 1
  fi
  
  # Use token for Terraform
  export GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth print-access-token)
  export GOOGLE_APPLICATION_CREDENTIALS=""  # Clear any file path
  
  echo "GCP authentication is valid (active account: $ACTIVE_ACCOUNT). Using access token for Terraform."
}

# Prompt for project name
read -p "Enter project name (e.g., My-Project-Name): " project_name

# Select region
select_region

# Run auth check
check_auth

# Derive Project ID in Bash
PROJECT_ID=$(echo "$project_name" | sed 's/ /-/g' | tr 'A-Z' 'a-z')

# Check project status and handle deletion
PROJECT_STATUS=$(gcloud projects describe "$PROJECT_ID" --format="value(lifecycleState)" 2>/dev/null || echo "NOT_FOUND")
if [ "$PROJECT_STATUS" == "DELETE_REQUESTED" ]; then
  echo "Project $PROJECT_ID is pending deletion."
  read -p "Would you like to undelete it? (Y/n): " confirm
  if [[ $confirm =~ ^[Yy]$ || -z $confirm ]]; then
    gcloud projects undelete "$PROJECT_ID"
    echo "Project undeleted. Waiting 30 seconds for propagation..."
    sleep 30
  else
    echo "Skipping undelete. Use a new project name to create one."
    exit 1
  fi
elif [ "$PROJECT_STATUS" == "NOT_FOUND" ]; then
  echo "Project $PROJECT_ID does not exist. The script will create it."
else
  echo "Project $PROJECT_ID is active. Proceeding with updates."
fi

# Prompt for manual billing account ID if needed
read -p "Enter billing account ID (leave empty to auto-fetch, e.g., 01C509-917B5F-913AA1): " billing_id
BILLING_VAR=""
if [ -n "$billing_id" ]; then
  BILLING_VAR="-var=billing_account_id=$billing_id"
  if [ "$PROJECT_STATUS" != "NOT_FOUND" ]; then
    gcloud beta billing projects link "$PROJECT_ID" --billing-account="$billing_id" || echo "Billing already linked or minor error; continuing."
    echo "Billing linked. Waiting 30 seconds for propagation..."
    sleep 30
  fi
fi

# Run Terraform init with upgrade to handle lock file issues
INIT_EXIT_CODE=0
terraform init -upgrade || INIT_EXIT_CODE=$?

if [ $INIT_EXIT_CODE -ne 0 ]; then
  echo "Error: Terraform init failed. This may be due to provider version conflicts."
  read -p "Delete lock file and retry? (Y/n): " confirm
  if [[ $confirm =~ ^[Yy]$ || -z $confirm ]]; then
    rm .terraform.lock.hcl
    terraform init -upgrade || { echo "Init still failed. Check startup.tf provider versions."; exit 1; }
  else
    echo "Aborted."
    exit 1
  fi
fi

# Run Terraform plan to check for destructions
terraform plan -var="project_name=$project_name" -var="region=$region" $BILLING_VAR -out=plan.tfplan

# Check for destructive actions
if grep -q "destroy" plan.tfplan; then
  echo "Warning: Plan includes destructive actions. This may be due to state mismatch."
  read -p "Clean Terraform state and re-import resources? (Y/n): " clean_confirm
  if [[ $clean_confirm =~ ^[Yy]$ || -z $clean_confirm ]]; then
    terraform state rm 'google_project.project' 'google_project_service.*' || true  # Remove conflicting state
    if [ "$PROJECT_STATUS" != "NOT_FOUND" ]; then
      terraform import 'data.google_project.existing_project' "$PROJECT_ID" || true  # Re-import project
    fi
    echo "State cleaned. Re-running plan..."
    terraform plan -var="project_name=$project_name" -var="region=$region" $BILLING_VAR -out=plan.tfplan
  fi
  read -p "Continue with apply? (Y/n): " confirm
  if [[ ! $confirm =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
  fi
fi

# Run Terraform apply
terraform apply "plan.tfplan" | while IFS= read -r line; do
  echo "$line"
  if [[ "$line" == "Outputs:" ]]; then
    break
  fi
done

# Check if terraform apply succeeded (exit code from last command)
if [ ${PIPESTATUS[0]} -ne 0 ]; then
  echo "Error: Terraform apply failed. Check the logs above for details. No .env file generated."
  exit 1
fi

# Fetch outputs
NON_SENSITIVE=$(terraform output -raw env_miner_non_sensitive)
AUTH_SECRET=$(terraform output -raw cloud_auth_secret)

# Escape newlines in AUTH_SECRET as \n and make it a single-line string
escaped_auth_secret=$(echo "$AUTH_SECRET" | sed ':a;N;$!ba;s/\n/\\n/g')

# Write to $project_name.env with formatted content
cat <<EOF > "$project_name.env"
Copy the block below into your .env.miner:
--------------------------------------------------------
--------------------------------------------------------
$NON_SENSITIVE
CLOUD_AUTH_SECRET="$escaped_auth_secret"
--------------------------------------------------------
--------------------------------------------------------
EOF

echo "Deployment complete. Full configuration written to $project_name.env"
```


```bash
chmod +x deploy.sh
```

---

### 4. Execute Deployment

```bash
./deploy.sh
```

- Enter a project name when prompted.
- Select a GCP region.
- Provide billing account ID or leave empty to auto-fetch (works most times).
- Follow CLI prompts and confirm steps.
- Use "Cloud Assist" to resolve small errors. It's very helpful!  

---

### 5. Extract Deployment Output

After successful deployment, you’ll see:

```
Deployment complete. Full configuration written to $project_name.env
```

To display the environment configuration:

```bash
cat $project_name.env
```

---

### 6. Prepare `.env.miner`

Later, copy contents line by line into your local `.env.miner.example` or `.env.miner`.

---

### 7. Deploy Your Moat (Miner Host VM)

#### 7.1 Customize Parameters

Replace:
- `moat` → instance name
- `projectid` → from your cloud shell `.env` + replace in `project=` & in `network-interface=subnet=` 
- `n2d-standard-8` → your desired machine type for moat 
- `us-central1-a` → zone in your selected region (from project) 
- `username:ssh-rsa ...` → replace username with your desired user / login name + your SSH key 

#### 7.2 Miner / Moat Deployment Command

```bash
gcloud compute instances create moat \
  --project=projectid \
  --zone=us-central1-a \
  --machine-type=n2d-standard-4 \
  --network-interface=subnet=projectid-vpc-24,network-tier=PREMIUM,stack-type=IPV4_ONLY,nic-type=VIRTIO_NET,private-network-ip=10.0.0.4,aliases="ipip-range:192.168.101.1/32;ipip-range:192.168.110.2/32" \
  --can-ip-forward \
  --maintenance-policy=MIGRATE \
  --provisioning-model=STANDARD \
  --no-service-account \
  --no-scopes \
  --create-disk=auto-delete=yes,boot=yes,device-name=moat,image=projects/ubuntu-os-cloud/global/images/ubuntu-2204-jammy-v20250722,mode=rw,size=10,type=pd-balanced \
  --no-shielded-secure-boot \
  --no-shielded-vtpm \
  --no-shielded-integrity-monitoring \
  --reservation-affinity=any \
  --metadata="ssh-keys=validator:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDJy3EwymI7vFX7gVHwepoaOfbRja+G0B0ky3TGuWZ7ObO8u+gCJIvfOwJ8233SmOh215agAWPzBcMZnic7Bl7NbHta0JY62+R+9ZpXoQTbcyNf7MpPjFeBJsWCWjbmcXI5JgF4sZsrv2Uw4jTub3S/6Hnl35moCIpxL70wUr5RLco5f6ctXbao/I6BQNzBVMFcZw+lDQe8HQBe+5Gr5UN3FCSJDDz6I71o8d091cUF7tKQHFXT/qNOOe74YqgqloUxHxPzWqNcDr4is/JMsUiXUvrTOvssX5RNI9SJUaWPr2GEISOu2iH2MfEykuvM6Rczfit7UEGxxA472P1KTMffci6M/mJpsbx4y3pY2sy3Nmu35FTGKtfomw99Xc1OeHrQSj6Ay8ZXjprStDXx2wl3Tx+/LnglB97OcBUrPdpSWMMyFEe78aRTt0UHalIRksTjD4+PgEI8TVBvL6R5kcgnkONm71rIoJG9zZi8F0ICYJPOkz+HsC/ef+Zc1+SpqUCJZkKORQZJ/S0g9RC39hms9eJxAH7eDqN5Zu+jPC4QK3sctmm0Ln+JK8UIOTIU5ERLrHU/IbAXEWII3FQ21olLEx/5VZz6zJyZWAoVGJMg4fulj9jebWaho6ES/DSm3LOqOY7noggZfVCrTOqJPzLS14Vnh0NxHEWPJES8h4vIwQ== user@localhost"
```

Important:
Whatever you customise, make sure your moat remains with private ip = 10.0.0.4 or it will be unreachable in challenge phase. 

---

### 8. GCP Region & Zone Lookup

```bash
gcloud compute regions list
gcloud compute zones list --filter="region:( us-central1 )"
```

---

## SECTION 2: Prepare the Miner

---

### 9. Connect to the Moat (VM)

```bash
gcloud compute ssh username@moat --project=projectid --zone=us-central1-a
```

---

### 10. System Setup

```bash
sudo apt update && sudo apt install python3-pip -y && sudo apt install python3-venv -y
sudo apt install npm -y && sudo npm install -g pm2 
python3 -m venv tp && source tp/bin/activate
```

---

### 11. Clone Miner and Install Dependencies

```bash
git clone https://github.com/shugo-labs/tensorprox.git
cd tensorprox
pip install -r requirements.txt
```

---

### 12. Create `.env.miner`

```bash
nano .env.miner // use .env.miner.example
```

Paste:

```env
# Bittensor Configuration
NETUID=234/91
SUBTENSOR_NETWORK="test/finney"
SUBTENSOR_CHAIN_ENDPOINT="wss://test.finney.opentensor.ai:443"
WALLET_NAME="start"
HOTKEY="test-miner2"
AXON_PORT="22181"

# Cloud Provider Selection
PROVIDER=GCP

# Generic Cloud Credentials
CLOUD_PROJECT_ID=can-copy-from-cloud-shell
CLOUD_AUTH_ID=can-copy-from-cloud-shell
CLOUD_AUTH_SECRET="can-copy-from-cloud-shell"
CLOUD_RESOURCE_GROUP=  # Not used by GCP, leave empty

# Generic Network Configuration
VPC_NAME=can-copy-from-cloud-shell
SUBNET_NAME=can-copy-from-cloud-shell

# Generic Compute Configuration
REGION=europe-central2-a           #= ZONE in GCP. Put Moat "Zone" 
VM_SIZE_SMALL=e2-medium        # For King 
VM_SIZE_LARGE=n2-standard-4    # For Traffic Generators (can be different/larger)
NUM_TGENS=2

# Optional: Custom VM Specifications for King
# CUSTOM_KING_CPU_COUNT=2
# CUSTOM_KING_RAM_MB=4096

# Optional: Custom VM Specifications for TGens
# CUSTOM_TGEN_CPU_COUNT=8
# CUSTOM_TGEN_RAM_MB=16384
```



---

### 13. Start the Miner

```bash
pm2 start "python3 neurons/miner.py" --name miner
```

---

### 14. Check Miner Status

```bash
pm2 list
```

---

### 15. View Miner Logs

```bash
pm2 logs miner
```

---

**Done.** You have a miner running in a controlled GCP environment, provisioned end-to-end using Terraform and PM2.
