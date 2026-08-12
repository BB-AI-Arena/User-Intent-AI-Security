variable "project_name" {
  description = "Docker Compose project name used to namespace containers, networks, and volumes."
  type        = string
  default     = "user-intent-ai-security"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9_-]*$", var.project_name))
    error_message = "project_name must contain only lowercase letters, numbers, underscores, and hyphens."
  }
}

variable "docker_host" {
  description = "Optional Docker daemon URI. Leave null to use the provider or DOCKER_HOST default."
  type        = string
  default     = null
  nullable    = true
}

variable "docker_context" {
  description = "Optional Docker CLI context name. When set, it takes precedence over docker_host."
  type        = string
  default     = null
  nullable    = true
}

variable "environment_file" {
  description = "Optional path to a local, untracked Compose environment file containing deployment secrets."
  type        = string
  default     = null
  nullable    = true
}

variable "profiles" {
  description = "Optional Compose profiles to enable, such as collectors and notifications."
  type        = list(string)
  default     = []
}

variable "wait_timeout" {
  description = "Maximum time for the Docker provider to wait for services during apply."
  type        = string
  default     = "2m"

  validation {
    condition     = can(regex("^[1-9][0-9]*(s|m|h)$", var.wait_timeout))
    error_message = "wait_timeout must be a positive duration such as 30s, 2m, or 1h."
  }
}

