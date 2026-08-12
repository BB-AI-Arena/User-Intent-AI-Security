# Ansible deployment

This playbook configures a Debian-family Linux host, optionally installs Docker Engine with Compose v2, checks out an approved repository version, renders protected environment configuration, deploys the stack, and verifies its health endpoint.

## Controller requirements

- Ansible Core 2.15+
- `community.docker` collection 5.2+
- SSH access and privilege escalation on the target

```bash
cd deploy/ansible
ansible-galaxy collection install -r requirements.yml
```

## Configure

1. Copy `inventories/example.ini` to an untracked inventory.
2. Copy `group_vars/all.example.yml` to `group_vars/all.yml`.
3. Replace example values and encrypt the variable file:

```bash
ansible-vault encrypt group_vars/all.yml
```

Pin `intentgate_version` to an approved tag or commit for production deployments. Set `intentgate_manage_docker: false` on non-Debian hosts where Docker Engine and Compose v2 are already managed separately.

## Deploy

```bash
ansible-playbook -i inventories/production.ini deploy.yml --ask-vault-pass
```

The role avoids printing deployment secrets with `no_log`. Review your Ansible callback, fact cache, and controller logging configuration before using real credentials.

