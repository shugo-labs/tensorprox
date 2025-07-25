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
