output "grafana_url" {
  description = "Default local Grafana URL."
  value       = "http://localhost:3000"
}

output "prometheus_url" {
  description = "Default local Prometheus URL."
  value       = "http://localhost:9090"
}

output "intentgate_api_url" {
  description = "Default local Intent Gate API URL."
  value       = "http://localhost:8787"
}

output "compose_project" {
  description = "Managed Docker Compose project identifier."
  value       = docker_compose.intentgate.id
}

