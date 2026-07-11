#Requires -Version 7.3
<#
.SYNOPSIS
    Validates the CCF Push connector lab end-to-end.

.DESCRIPTION
    Checks:
    1. Workspace and Sentinel are accessible
    2. FeodoTracker_CL table exists and has data
    3. Analytics rules are deployed and enabled
    4. Workbook exists

.PARAMETER ResourceGroup
    Resource group containing the Sentinel workspace.

.PARAMETER WorkspaceName
    Name of the Log Analytics workspace.

.EXAMPLE
    ./Test-CCFPush.ps1 -ResourceGroup "ccf-push-lab-rg" -WorkspaceName "ccf-push-lab-law"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ResourceGroup,

    [Parameter(Mandatory)]
    [string]$WorkspaceName
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$passed = 0
$failed = 0

function Test-Check {
    param([string]$Name, [scriptblock]$Check)
    try {
        $result = & $Check
        if ($result) {
            Write-Host "  PASS: $Name" -ForegroundColor Green
            $script:passed++
        } else {
            Write-Host "  FAIL: $Name" -ForegroundColor Red
            $script:failed++
        }
    } catch {
        Write-Host "  FAIL: $Name ($_)" -ForegroundColor Red
        $script:failed++
    }
}

Write-Host "`n=== CCF Push Connector Lab Validation ===" -ForegroundColor Cyan
Write-Host "Resource Group: $ResourceGroup"
Write-Host "Workspace:      $WorkspaceName"
Write-Host ""

# Get workspace
$workspace = az monitor log-analytics workspace show `
    --resource-group $ResourceGroup `
    --workspace-name $WorkspaceName 2>$null | ConvertFrom-Json

if (-not $workspace) {
    Write-Error "Workspace '$WorkspaceName' not found"
}
$workspaceId = $workspace.id

Write-Host "--- Infrastructure ---" -ForegroundColor Yellow

Test-Check "Workspace exists" {
    $null -ne $workspace.id
}

Test-Check "Sentinel onboarded" {
    $sentinel = az rest --method GET `
        --url "$workspaceId/providers/Microsoft.SecurityInsights/onboardingStates?api-version=2024-03-01" `
        2>$null | ConvertFrom-Json
    ($sentinel.value | Measure-Object).Count -gt 0
}

Write-Host "`n--- Data Connector ---" -ForegroundColor Yellow

Test-Check "Connector definition exists" {
    $connectors = az rest --method GET `
        --url "$workspaceId/providers/Microsoft.SecurityInsights/dataConnectorDefinitions?api-version=2024-01-01-preview" `
        2>$null | ConvertFrom-Json
    ($connectors.value | Where-Object { $_.properties.connectorUiConfig.title -like "*Feodotracker*" } | Measure-Object).Count -gt 0
}

Write-Host "`n--- Data Ingestion ---" -ForegroundColor Yellow

Test-Check "FeodoTracker_CL table has data" {
    $query = "FeodoTracker_CL | take 1"
    $result = az monitor log-analytics query `
        --workspace $workspace.customerId `
        --analytics-query $query `
        2>$null | ConvertFrom-Json
    ($result | Measure-Object).Count -gt 0
}

Test-Check "Data ingested in last 24h" {
    $query = "FeodoTracker_CL | where TimeGenerated > ago(24h) | count"
    $result = az monitor log-analytics query `
        --workspace $workspace.customerId `
        --analytics-query $query `
        2>$null | ConvertFrom-Json
    [int]($result[0].Count) -gt 0
}

Write-Host "`n--- Analytics Rules ---" -ForegroundColor Yellow

$rules = az rest --method GET `
    --url "$workspaceId/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-03-01" `
    2>$null | ConvertFrom-Json

$expectedRules = @(
    "LAB - New Botnet Family Detected",
    "LAB - C2 Infrastructure Surge",
    "LAB - High-Confidence Active C2",
    "LAB - Geographic C2 Concentration",
    "LAB - Network Traffic to Known Botnet C2"
)

foreach ($ruleName in $expectedRules) {
    Test-Check "Rule: $ruleName" {
        $match = $rules.value | Where-Object { $_.properties.displayName -eq $ruleName }
        ($match | Measure-Object).Count -gt 0 -and $match.properties.enabled -eq $true
    }
}

Write-Host "`n--- Workbook ---" -ForegroundColor Yellow

Test-Check "Threat Intelligence Dashboard workbook" {
    $workbooks = az resource list `
        --resource-group $ResourceGroup `
        --resource-type Microsoft.Insights/workbooks `
        2>$null | ConvertFrom-Json
    ($workbooks | Where-Object { $_.tags.'hidden-title' -eq 'Threat Intelligence Dashboard' } | Measure-Object).Count -gt 0
}

# Summary
Write-Host "`n=== Results ===" -ForegroundColor Cyan
Write-Host "  Passed: $passed" -ForegroundColor Green
Write-Host "  Failed: $failed" -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Green" })
Write-Host ""

if ($failed -gt 0) {
    Write-Host "Some checks failed. See above for details." -ForegroundColor Yellow
    Write-Host "If FeodoTracker_CL has no data, run Send-ThreatIntel.py and wait 5-10 minutes." -ForegroundColor DarkGray
    exit 1
}

exit 0
