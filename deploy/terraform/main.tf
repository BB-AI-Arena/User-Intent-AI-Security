locals {
  repository_root = abspath("${path.module}/../..")
  compose_file    = "${local.repository_root}/docker-compose.observability.yml"
  env_files       = var.environment_file == null ? [] : [abspath(var.environment_file)]
}

resource "docker_compose" "intentgate" {
  project_name      = var.project_name
  project_directory = local.repository_root
  config_paths      = [local.compose_file]
  env_files         = local.env_files
  profiles          = var.profiles
  remove_orphans    = true
  wait              = true
  wait_timeout      = var.wait_timeout
}

