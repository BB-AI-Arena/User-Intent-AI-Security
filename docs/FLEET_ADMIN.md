# Fleet administration

The Fleet Admin POC adds an authenticated deployment control plane to the Intent Gate service. It demonstrates scoped software distribution without turning the console into a general-purpose remote shell.

## How it works

1. Endpoint agents register hostname, address, operating system, security groups, and installed version with `POST /v1/endpoints/register`.
2. A discovery session snapshots enrolled inventory and summarizes group, online, and managed coverage.
3. An administrator targets a security group or explicit endpoint IDs and creates a dry-run plan.
4. An executed plan creates one fixed `install-or-upgrade-intentgate` manifest per endpoint.
5. Endpoint agents poll `GET /v1/deployment-jobs/next?endpoint_id=...` and report lifecycle state to `POST /v1/deployment-jobs/{job_id}`.

The repository implements the control plane, API contract, demo inventory, network CLI, and UI. A production endpoint agent and artifact repository are intentionally separate trust components.

## Network administration command

Set the bearer token without putting it in shell history:

```powershell
$env:UIG_ADMIN_SERVER = "https://intentgate.example"
$env:UIG_INGEST_TOKEN = "replace-with-a-secret-from-your-vault"
```

Run discovery and inspect inventory:

```powershell
uig-admin discover
uig-admin inventory
```

Plan a deployment, then explicitly queue it:

```powershell
uig-admin deploy --group engineering --version 0.4.0
uig-admin deploy --group engineering --version 0.4.0 --execute
uig-admin deployments
```

Repeat `--endpoint` to target explicit enrolled endpoint IDs instead of a group. The token is accepted through `--token`, but environment or secret-store injection is preferred.

## API routes

| Route | Purpose |
|---|---|
| `GET /v1/endpoints` | Inventory, security groups, and coverage summary |
| `POST /v1/endpoints/register` | Agent registration and heartbeat |
| `POST /v1/discovery-sessions` | Create an inventory snapshot |
| `GET /v1/deployments` | Recent deployment waves |
| `POST /v1/deployments` | Plan or queue a scoped deployment |
| `GET /v1/deployment-jobs/next` | Fetch the next queued endpoint manifest |
| `POST /v1/deployment-jobs/{id}` | Record endpoint deployment state |

Every route requires the existing bearer token. WAF, rate limiting, enterprise identity, and separate endpoint credentials should be applied before this control plane is exposed beyond a lab.

## Safety properties

- No endpoint accepts arbitrary command text from this API.
- Deployment jobs contain a fixed package/action manifest.
- Planning is the default; queueing requires the explicit `execute` field or `--execute` flag.
- Offline endpoints are deferred rather than treated as successful.
- Every deployment records the selector, requestor, target version, endpoint jobs, timestamps, and state transitions.
- Discovery uses enrolled inventory and heartbeats; it does not perform unauthenticated subnet scanning.

## Production additions

Before real enterprise rollout, add mutual TLS and per-agent identity, signed artifacts and manifests, RBAC with approval separation, maintenance windows, phased rings/canaries, health-based pause and rollback, durable encrypted storage, rate limits, immutable audit export, inventory connectors for Entra ID/Intune/AD/CMDB, and an endpoint service that verifies signatures before installation.
