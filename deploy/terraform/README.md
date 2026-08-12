# Terraform deployment

This root module manages the existing Docker Compose application through the `kreuzwerker/docker` provider. It intentionally reuses `docker-compose.observability.yml` so service definitions remain canonical in one place, including the OWASP CRS WAF and internal application network.

## Requirements

- Terraform 1.6+
- A reachable Docker Engine
- Docker provider 4.5+

## Deploy

```bash
cd deploy/terraform
terraform init
terraform plan
terraform apply
```

For an alternate engine, copy `terraform.tfvars.example` to an untracked `terraform.tfvars` and set either `docker_context` or `docker_host`.

To enable collectors or notifications, first create the untracked environment and integration configuration described in the main README, then set:

```hcl
environment_file = "../../.env.integrations"
profiles          = ["collectors", "notifications"]
```

Terraform state can contain infrastructure metadata and must be stored in an approved encrypted backend for shared or production use. State files and local variable files are excluded from Git.

> Do not use Terraform to adopt the same Compose project while it is already managed independently. Stop the manually managed stack first or select a different `project_name`.

