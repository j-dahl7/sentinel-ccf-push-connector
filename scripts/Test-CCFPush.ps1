#Requires -Version 7.3
<#
.SYNOPSIS
    Validates the exact CCF Push connector resources recorded by Deploy-Lab.ps1.

.DESCRIPTION
    Reads the local ownership manifest and checks the exact resource group,
    workspace, Sentinel onboarding state, connector definition, rules, workbook,
    table, and recent data. It never passes based on a display-name wildcard.

.PARAMETER ProjectName
    Project name used for deployment. The ownership manifest is keyed by this value.

.PARAMETER ResourceGroup
    Optional assertion. If supplied, it must exactly match the manifest.

.PARAMETER WorkspaceName
    Optional assertion. If supplied, it must exactly match the manifest.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ProjectName = 'ccf-push-lab',

    [Parameter()]
    [string]$ResourceGroup,

    [Parameter()]
    [string]$WorkspaceName
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LabRoot = Split-Path -Parent $ScriptDir
$StatePath = Join-Path $LabRoot ".ccf-push-lab-state-$ProjectName.json"
$passed = 0
$failed = 0

if ($ProjectName -notmatch '^[a-z0-9][a-z0-9-]{2,30}[a-z0-9]$') {
    throw 'ProjectName must be 4-32 lowercase letters, numbers, or hyphens, and cannot begin or end with a hyphen.'
}
if (-not (Test-Path -LiteralPath $StatePath)) {
    throw "Ownership state '$StatePath' is missing. Refusing to validate unrelated resources."
}
try {
    $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
}
catch {
    throw "Ownership state '$StatePath' is unreadable or invalid JSON."
}
if ($state.schemaVersion -ne 1 -or
    $state.projectName -ne $ProjectName -or
    $state.ownerToken -notmatch '^[0-9a-fA-F-]{36}$' -or
    $state.workbookId -notmatch '^[0-9a-fA-F-]{36}$' -or
    $state.connectorDefinitionName -ne 'FeodotrackerCCFPush') {
    throw "Ownership state '$StatePath' has an unsupported or inconsistent schema."
}
if ($ResourceGroup -and $ResourceGroup -ne $state.resourceGroup) {
    throw "ResourceGroup '$ResourceGroup' does not match the owned group '$($state.resourceGroup)'."
}
if ($WorkspaceName -and $WorkspaceName -ne $state.workspaceName) {
    throw "WorkspaceName '$WorkspaceName' does not match the owned workspace '$($state.workspaceName)'."
}
$ResourceGroup = $state.resourceGroup
$WorkspaceName = $state.workspaceName

function Test-Check {
    param([Parameter(Mandatory)] [string]$Name, [Parameter(Mandatory)] [scriptblock]$Check)
    try {
        if (& $Check) {
            Write-Host "  PASS: $Name" -ForegroundColor Green
            $script:passed++
        }
        else {
            Write-Host "  FAIL: $Name" -ForegroundColor Red
            $script:failed++
        }
    }
    catch {
        Write-Host "  FAIL: $Name ($($_.Exception.Message))" -ForegroundColor Red
        $script:failed++
    }
}

function Get-LabResourceGuid {
    param([Parameter(Mandatory)] [string]$ResourceKey)
    $seed = "$($state.ownerToken)|$ResourceKey"
    $hash = [System.Security.Cryptography.SHA256]::HashData(
        [System.Text.Encoding]::UTF8.GetBytes($seed)
    )
    return [guid]::new([byte[]]$hash[0..15]).ToString()
}

function Get-PagedAzRestValues {
    param([Parameter(Mandatory)] [string]$InitialUrl)
    $items = [System.Collections.Generic.List[object]]::new()
    $nextUrl = $InitialUrl
    $pageCount = 0
    while ($nextUrl) {
        $pageCount++
        if ($pageCount -gt 100) {
            throw 'Azure REST pagination exceeded 100 pages.'
        }
        if ($nextUrl -match '^https?://') {
            $parsed = [uri]$nextUrl
            if ($parsed.Scheme -ne 'https' -or $parsed.Host -ne 'management.azure.com' -or $parsed.UserInfo) {
                throw "Azure returned an untrusted pagination URL '$nextUrl'."
            }
        }
        $page = az rest --method GET --url $nextUrl 2>$null | ConvertFrom-Json
        foreach ($item in @($page.value)) {
            $items.Add($item)
        }
        $nextUrl = [string]$page.nextLink
    }
    return @($items)
}

$account = az account show --output json 2>$null | ConvertFrom-Json
if (-not $account -or $account.id -ne $state.subscriptionId -or $account.tenantId -ne $state.tenantId) {
    throw 'The active Azure subscription or tenant does not match the ownership manifest.'
}

$group = az group show --name $ResourceGroup --output json 2>$null | ConvertFrom-Json
$workspace = az monitor log-analytics workspace show `
    --resource-group $ResourceGroup `
    --workspace-name $WorkspaceName `
    --output json 2>$null | ConvertFrom-Json
$workspaceId = $workspace.id
$ownerMarker = "[nlzt-owner:$($state.ownerToken)]"

Write-Host "`n=== CCF Push Connector Lab Validation ===" -ForegroundColor Cyan
Write-Host "Resource Group: $ResourceGroup"
Write-Host "Workspace:      $WorkspaceName"

Write-Host "`n--- Infrastructure ---" -ForegroundColor Yellow
Test-Check 'Exact resource group is owner tagged' {
    $group.name -eq $ResourceGroup -and $group.tags.'nlzt-owner' -eq $state.ownerToken
}
Test-Check 'Exact workspace exists in the owned group' {
    $workspace.name -eq $WorkspaceName -and
    $workspaceId -match "/resourceGroups/$([regex]::Escape($ResourceGroup))/" -and
    $workspace.tags.'nlzt-owner' -eq $state.ownerToken
}
Test-Check 'Exact Sentinel onboarding state exists' {
    $sentinel = az rest --method GET `
        --url "$workspaceId/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2024-03-01" `
        2>$null | ConvertFrom-Json
    $sentinel.name -eq 'default'
}

Write-Host "`n--- Data Connector ---" -ForegroundColor Yellow
Test-Check 'Exact Feodotracker connector definition exists' {
    $connector = az rest --method GET `
        --url "$workspaceId/providers/Microsoft.SecurityInsights/dataConnectorDefinitions/$($state.connectorDefinitionName)?api-version=2024-01-01-preview" `
        2>$null | ConvertFrom-Json
    $connector.name -eq $state.connectorDefinitionName -and
    $connector.properties.connectorUiConfig.id -eq 'FeodotrackerCCFPush' -and
    $connector.properties.connectorUiConfig.title -eq 'Feodotracker Botnet C2 Feed (CCF Push)'
}

Write-Host "`n--- Data Ingestion ---" -ForegroundColor Yellow
Test-Check 'FeodoTracker_CL table has data' {
    $result = az monitor log-analytics query `
        --workspace $workspace.customerId `
        --analytics-query 'FeodoTracker_CL | take 1' `
        2>$null | ConvertFrom-Json
    @($result).Count -gt 0
}
Test-Check 'Data was ingested in the last 24 hours' {
    $result = az monitor log-analytics query `
        --workspace $workspace.customerId `
        --analytics-query 'FeodoTracker_CL | where TimeGenerated > ago(24h) | count' `
        2>$null | ConvertFrom-Json
    @($result).Count -gt 0 -and [int]$result[0].Count -gt 0
}

Write-Host "`n--- Analytics Rules ---" -ForegroundColor Yellow
$rules = @(Get-PagedAzRestValues `
    -InitialUrl "$workspaceId/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-03-01")
$expectedRules = @(
    'LAB - New Feed Malware Label Observed',
    'LAB - Feed Indicator Count Increase',
    'LAB - Recent Feed Indicators on 443 or 8443',
    'LAB - Feed Country Concentration',
    'LAB - Network Traffic Match to Feed Indicator'
)
foreach ($ruleName in $expectedRules) {
    Test-Check "Exact owned rule: $ruleName" {
        $expectedId = Get-LabResourceGuid -ResourceKey "rule:$ruleName"
        $matches = @($rules | Where-Object { $_.name -eq $expectedId })
        $matches.Count -eq 1 -and
        $matches[0].properties.displayName -eq $ruleName -and
        ([string]$matches[0].properties.description).Contains($ownerMarker) -and
        [bool]$matches[0].properties.enabled -eq [bool]$state.sentinelRulesEnabled
    }
}

Write-Host "`n--- Workbook ---" -ForegroundColor Yellow
Test-Check 'Exact owned Threat Intelligence Dashboard workbook' {
    $subscriptionId = $state.subscriptionId
    $workbook = az rest --method GET `
        --url "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/workbooks/$($state.workbookId)?api-version=2022-04-01" `
        2>$null | ConvertFrom-Json
    $workbook.name -eq $state.workbookId -and
    $workbook.tags.'nlzt-owner' -eq $state.ownerToken -and
    $workbook.tags.'hidden-title' -eq 'Threat Intelligence Dashboard' -and
    $workbook.properties.displayName -eq 'Threat Intelligence Dashboard' -and
    $workbook.properties.sourceId -eq $workspaceId
}

Write-Host "`n=== Results ===" -ForegroundColor Cyan
Write-Host "  Passed: $passed" -ForegroundColor Green
Write-Host "  Failed: $failed" -ForegroundColor $(if ($failed -gt 0) { 'Red' } else { 'Green' })

if ($failed -gt 0) {
    Write-Host 'Validation failed. The portal-generated connector resources and ingestion must exist before the data checks can pass.' -ForegroundColor Yellow
    exit 1
}

exit 0
