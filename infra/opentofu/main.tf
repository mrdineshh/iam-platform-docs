terraform {
  required_version = ">= 1.6.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Cloud SQL migration (2026-10-26, see docs/DECISIONS.md) -- an explicit,
# logged override of this project's own documented "self-hosted Postgres,
# not Cloud SQL" decision (AP-5 portability reasoning in CLAUDE.md). Kept
# as real infrastructure-as-code rather than a one-off gcloud command so
# the decision is reviewable and reproducible, same as everything else
# this project runs through OpenTofu.
resource "google_sql_database_instance" "iam_platform" {
  name             = "iam-platform-db"
  project          = var.project_id
  region           = var.region
  database_version = "POSTGRES_16"

  settings {
    tier = var.db_tier
    # The project's default Cloud SQL edition (ENTERPRISE_PLUS) doesn't
    # support shared-core tiers like db-f1-micro at all -- only the
    # classic ENTERPRISE edition does. Found live: the first apply attempt
    # failed with "Invalid Tier (db-f1-micro) for (ENTERPRISE_PLUS)
    # Edition."
    edition           = "ENTERPRISE"
    availability_type = "ZONAL" # single-zone -- matches the demo-scale db-f1-micro tier; REGIONAL requires a non-shared-core tier.
    disk_autoresize   = true
    disk_size         = 10
    disk_type         = "PD_SSD"

    backup_configuration {
      enabled    = true
      start_time = "03:00"
    }

    ip_configuration {
      ipv4_enabled = true
      # No authorized_networks entries -- deliberately no direct public
      # access. Every connection goes through the Cloud SQL Auth Proxy,
      # which authenticates via the Cloud SQL Admin API (IAM + a short
      # -lived TLS cert) rather than a raw open port, see docs/DECISIONS.md.
    }
  }

  deletion_protection = true
}

# One logical database per service, mirroring the existing self-hosted
# layout exactly (tenant_db, identity_db, policy_db, device_db, audit_db)
# so no application code or connection string shape changes, only the
# host.
resource "google_sql_database" "databases" {
  for_each = toset(["tenant_db", "identity_db", "policy_db", "device_db", "audit_db"])
  project  = var.project_id
  name     = each.value
  instance = google_sql_database_instance.iam_platform.name
}

resource "random_password" "db_password" {
  length  = 28
  special = false # Cloud SQL Auth Proxy's connection string handles any
  # character fine, but keeping this alphanumeric-only sidesteps any
  # shell-escaping surprises wherever this value gets referenced (.env,
  # docker-compose, this state file).
}

resource "google_sql_user" "iam" {
  project  = var.project_id
  name     = "iam"
  instance = google_sql_database_instance.iam_platform.name
  password = random_password.db_password.result
}

# Lets the demo VM's own (default compute) service account authenticate
# the Cloud SQL Auth Proxy without a separate downloaded key file -- the
# proxy running on that VM already has this identity available to it.
resource "google_project_iam_member" "cloudsql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${var.vm_service_account}"
}
