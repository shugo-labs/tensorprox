# Linode Web Client Configuration for Tensorprox MVP
# Development Plan Requirements: Lines 6, 37, 44-50, 120-129

terraform {
  required_version = ">= 1.0"
  required_providers {
    linode = {
      source  = "linode/linode"
      version = "~> 2.0"
    }
  }
}

# Provider configuration for standalone deployment
provider "linode" {
  token = var.linode_token
}

# Variables
variable "linode_token" {
  description = "Linode API token"
  type        = string
  sensitive   = true
}

variable "region" {
  description = "Linode region for deployment"
  type        = string
  default     = "us-east"
}

variable "deployment_id" {
  description = "Unique deployment identifier"
  type        = string
  default     = "mvp"
}

variable "instance_type" {
  description = "Linode instance type"
  type        = string
  default     = "g6-standard-1"
}

variable "ssh_public_key_path" {
  description = "Path to SSH public key"
  type        = string
  default     = "/home/claudius/ovh.pub"
}


variable "tags" {
  description = "Tags to apply to resources"
  type        = list(string)
  default     = ["tensorprox-mvp", "webclient"]
}

# SSH Key
resource "linode_sshkey" "webclient" {
  label   = "tp-webclient-key-${var.deployment_id}"
  ssh_key = chomp(file(var.ssh_public_key_path))
}

# Web Client Instance - L3/L4 Traffic Generator
# Simple public-to-public IP traffic generation and capture
resource "linode_instance" "webclient" {
  label           = "tp-webclient-${var.deployment_id}"
  image           = "linode/ubuntu22.04"
  region          = var.region
  type            = var.instance_type
  authorized_keys = [linode_sshkey.webclient.ssh_key]
  tags            = var.tags

  # No private IP needed - public-to-public traffic only
  private_ip = false

  # Swap disk
  swap_size = 1024

  # Bootstrap script with modular traffic generation setup
  metadata {
    user_data = base64encode(file("${path.module}/bootstrap.sh"))
  }
}

# Firewall for Web Client - DISABLED for MVP deployment
/* resource "linode_firewall" "webclient" {
  label = "tp-webclient-fw-${var.deployment_id}"
  tags  = var.tags

  inbound {
    label    = "allow-ssh"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "22"
    ipv4     = ["0.0.0.0/0"]
  }

  inbound {
    label    = "allow-icmp"
    action   = "ACCEPT"
    protocol = "ICMP"
    ipv4     = ["0.0.0.0/0"]
  }

  inbound_policy = "DROP"

  outbound {
    label    = "allow-all"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "1-65535"
    ipv4     = ["0.0.0.0/0"]
  }

  outbound {
    label    = "allow-all-udp"
    action   = "ACCEPT"
    protocol = "UDP"
    ports    = "1-65535"
    ipv4     = ["0.0.0.0/0"]
  }

  outbound {
    label    = "allow-icmp-out"
    action   = "ACCEPT"
    protocol = "ICMP"
    ipv4     = ["0.0.0.0/0"]
  }

  outbound_policy = "ACCEPT"
} */

# Outputs
output "webclient_public_ip" {
  description = "Public IP of Web Client"
  value       = one(linode_instance.webclient.ipv4)
}


output "webclient_id" {
  description = "ID of Web Client instance"
  value       = linode_instance.webclient.id
}