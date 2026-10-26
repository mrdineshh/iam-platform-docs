output "instance_connection_name" {
  description = "Used by the Cloud SQL Auth Proxy (format: project:region:instance)."
  value       = google_sql_database_instance.iam_platform.connection_name
}

output "db_password" {
  description = "The generated password for the 'iam' Cloud SQL user. Sensitive -- read with `tofu output -raw db_password` when needed, never logged in plain CI output."
  value       = random_password.db_password.result
  sensitive   = true
}
