variable "project_id" {
  description = "GCP project ID"
  type        = string
  default     = "testing-ratnesh"
}

variable "region" {
  description = "GCP region for the Cloud SQL instance -- matches the demo VM's zone (us-central1-a)."
  type        = string
  default     = "us-central1"
}

variable "db_tier" {
  description = "Cloud SQL machine tier."
  type        = string
  default     = "db-f1-micro"
}

variable "vm_service_account" {
  description = "Service account the demo VM runs as -- granted roles/cloudsql.client so the Auth Proxy running on it can authenticate."
  type        = string
  default     = "546580006264-compute@developer.gserviceaccount.com"
}
