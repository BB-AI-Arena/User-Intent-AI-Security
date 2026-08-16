[CmdletBinding()]
param(
    [string]$BaseUrl = "http://127.0.0.1:8787",
    [string]$Token = "local-dev-change-me",
    [string]$WorkingDirectory = "/app"
)

$ErrorActionPreference = "Stop"
$headers = @{ Authorization = "Bearer $Token" }
function Invoke-Assessment {
    param(
        [string[]]$Arguments,
        [string]$Purpose,
        [string]$UserName
    )
    $payload = @{
        argv = $Arguments
        purpose = $Purpose
        cwd = $WorkingDirectory
        execution_context = @{
            user_name = $UserName
            endpoint_name = switch ($UserName) {
                "demo-release-manager" { "RELEASE-JUMP-01" }
                "demo-platform-engineer" { "PLATFORM-ADMIN-03" }
                "demo-security-lab" { "SECURITY-LAB-07" }
                "demo-automation-agent" { "BUILD-RUNNER-12" }
                default { "DEV-WS-042" }
            }
            privilege_level = "standard"
            is_root = $false
            is_admin = $false
        }
    } | ConvertTo-Json -Depth 5
    Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/assess" -Headers $headers -ContentType "application/json" -Body $payload
}

$scenarios = @(
    @{ Args = @("git", "status"); Purpose = "Inspect repository health"; User = "demo-developer" },
    @{ Args = @("git", "diff"); Purpose = "Review changes before release"; User = "demo-developer" },
    @{ Args = @("git", "log", "--oneline", "-5"); Purpose = "Review recent project history"; User = "demo-developer" },
    @{ Args = @("python", "--version"); Purpose = "Verify the project runtime"; User = "demo-developer" },
    @{ Args = @("docker", "--version"); Purpose = "Verify the container runtime"; User = "demo-developer" },
    @{ Args = @("rg", "TODO", "src"); Purpose = "Find unfinished implementation notes"; User = "demo-developer" },
    @{ Args = @("git", "branch"); Purpose = "Inspect available release branches"; User = "demo-developer" },
    @{ Args = @("Get-ChildItem", "src"); Purpose = "Inspect project source files"; User = "demo-developer" },
    @{ Args = @("git", "show", "HEAD"); Purpose = "Inspect the current release commit"; User = "demo-developer" },
    @{ Args = @("whoami"); Purpose = "Confirm the active operator identity"; User = "demo-developer" },
    @{ Args = @("Set-Content", "src/auth.py", "# automated identity update"); Purpose = "Apply an automated identity refactor"; User = "demo-automation-agent" },
    @{ Args = @("Add-Content", "src/policy.py", "# automated policy update"); Purpose = "Apply an automated policy refactor"; User = "demo-automation-agent" },
    @{ Args = @("Set-Content", "config/permissions.yml", "roles: updated"); Purpose = "Update service permissions"; User = "demo-automation-agent" },
    @{ Args = @("Add-Content", ".github/workflows/release.yml", "# release update"); Purpose = "Update release automation"; User = "demo-automation-agent" },
    @{ Args = @("git", "push"); Purpose = "Publish reviewed application changes"; User = "demo-release-manager" },
    @{ Args = @("npm", "publish"); Purpose = "Release the approved package"; User = "demo-release-manager" },
    @{ Args = @("docker", "push", "registry.example/intentgate:0.4.0"); Purpose = "Publish the approved container image"; User = "demo-release-manager" },
    @{ Args = @("kubectl", "apply", "-f", "deploy.yaml"); Purpose = "Deploy the reviewed staging manifest"; User = "demo-platform-engineer" },
    @{ Args = @("terraform", "apply"); Purpose = "Apply the approved staging infrastructure plan"; User = "demo-platform-engineer" },
    @{ Args = @("vssadmin", "delete", "shadows", "/all", "/quiet"); Purpose = "Free temporary disk space"; User = "demo-security-lab" },
    @{ Args = @("Set-MpPreference", "-DisableRealtimeMonitoring", "true"); Purpose = "Troubleshoot application startup"; User = "demo-security-lab" },
    @{ Args = @("format", "C:"); Purpose = "Clean generated build output"; User = "demo-security-lab" },
    @{ Args = @("terraform", "destroy", "-auto-approve"); Purpose = "Retire the obsolete staging environment"; User = "demo-security-lab" }
)

$results = foreach ($scenario in $scenarios) {
    Invoke-Assessment -Arguments $scenario.Args -Purpose $scenario.Purpose -UserName $scenario.User
}

$signals = @(
    @{
        source = "microsoft-defender-xdr"
        event_id = "demo-defender-showcase"
        score = 60
        confidence = 0.95
        ttl_seconds = 14400
        detail = "Suspicious credential access was contained on the demo endpoint"
    },
    @{
        source = "crowdstrike-falcon"
        event_id = "demo-falcon-showcase"
        score = 72
        confidence = 0.90
        ttl_seconds = 14400
        detail = "Unusual administrative process chain requires operator review"
    },
    @{
        source = "microsoft-sentinel"
        event_id = "demo-sentinel-showcase"
        score = 38
        confidence = 0.80
        ttl_seconds = 14400
        detail = "Identity risk correlation from a new sign-in location"
    }
) | ConvertTo-Json -Depth 5

$null = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/signals" -Headers $headers -ContentType "application/json" -Body $signals
$posture = Invoke-RestMethod -Method Get -Uri "$BaseUrl/v1/posture"
$summary = $results | Group-Object decision | Sort-Object Name | ForEach-Object { "{0}={1}" -f $_.Name.ToUpperInvariant(), $_.Count }

Write-Host "Intent Gate demo data loaded."
Write-Host ($summary -join "  ")
Write-Host "External posture=$($posture.risk_score)  active signals=$($posture.active_signals)"
Write-Host "Operator console: $BaseUrl/"
Write-Host "Grafana: http://127.0.0.1:3000/"
