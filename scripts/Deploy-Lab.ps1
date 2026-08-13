#Requires -Version 7.3
<#
.SYNOPSIS
    Deploys the CCF Push Connector Lab.

.DESCRIPTION
    Validates a CCF Push artifact set and deploys its owned Sentinel sandbox:
    1. Infrastructure (Bicep: Log Analytics workspace + Sentinel onboarding)
    2. Sentinel onboarding state
    3. Local CCF Push artifacts (validated, not packaged or installed)
    4. Sentinel analytics rules (5 scheduled rules for botnet C2 detection)
    5. Sentinel workbook (Threat Intelligence Dashboard)

    The four connector artifacts must be packaged and deployed with Microsoft's
    current Azure-Sentinel solution tooling before the portal deployment button
    can provision the DCE, DCR, custom table, and Entra app. This script does
    not download or execute that external tooling.

    Then run Send-ThreatIntel.py with the provided credentials.

.PARAMETER Location
    Azure region (default: eastus).

.PARAMETER ProjectName
    Resource naming prefix (default: ccf-push-lab).

.PARAMETER SkipSentinel
    Skip deploying analytics rules and workbook.

.PARAMETER EnableSentinelRules
    Deploy analytics rules enabled. Rules are disabled by default so the lab
    cannot create incidents until an operator has reviewed the queries.

.PARAMETER Destroy
    Tear down all lab resources.

.PARAMETER WhatIf
    Preview the target resource group operation without changing Azure.

.EXAMPLE
    ./Deploy-Lab.ps1 -Location "eastus"

.EXAMPLE
    ./Deploy-Lab.ps1 -Destroy
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$Location = 'eastus',

    [Parameter()]
    [string]$ProjectName = 'ccf-push-lab',

    [Parameter()]
    [switch]$SkipSentinel,

    [Parameter()]
    [switch]$EnableSentinelRules,

    [Parameter()]
    [switch]$Destroy
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LabRoot = Split-Path -Parent $ScriptDir
$StatePath = Join-Path $LabRoot ".ccf-push-lab-state-$ProjectName.json"
$ResourceGroup = "$ProjectName-rg"
$WorkspaceName = "$ProjectName-law"
$ConnectorDefinitionName = 'FeodotrackerCCFPush'
$WorkbookDisplayName = 'Threat Intelligence Dashboard'

if ($ProjectName -notmatch '^[a-z0-9][a-z0-9-]{2,30}[a-z0-9]$') {
    throw 'ProjectName must be 4-32 lowercase letters, numbers, or hyphens, and cannot begin or end with a hyphen.'
}

function Write-JsonAtomic {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [object]$Value
    )

    $temporaryPath = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        [System.IO.File]::WriteAllText(
            $temporaryPath,
            ($Value | ConvertTo-Json -Depth 12),
            [System.Text.UTF8Encoding]::new($false)
        )
        Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}

function Get-AzureResourceGroup {
    param([Parameter(Mandatory)] [string]$Name)

    $previousPreference = $PSNativeCommandUseErrorActionPreference
    try {
        $PSNativeCommandUseErrorActionPreference = $false
        $json = az group show --name $Name --output json 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $json) {
            return $null
        }
        return ($json | ConvertFrom-Json)
    }
    finally {
        $PSNativeCommandUseErrorActionPreference = $previousPreference
    }
}

function Get-LabResourceGuid {
    param([Parameter(Mandatory)] [string]$ResourceKey)

    $seed = "$($script:state.ownerToken)|$ResourceKey"
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
            throw 'Azure REST pagination exceeded 100 pages. Refusing an unbounded inventory request.'
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

function Assert-StateMatchesAccount {
    param(
        [Parameter(Mandatory)] [object]$State,
        [Parameter(Mandatory)] [object]$Account
    )

    if ($State.schemaVersion -ne 1 -or
        $State.projectName -ne $ProjectName -or
        $State.resourceGroup -ne $ResourceGroup -or
        $State.workspaceName -ne $WorkspaceName -or
        $State.subscriptionId -ne $Account.id -or
        $State.tenantId -ne $Account.tenantId -or
        $State.ownerToken -notmatch '^[0-9a-fA-F-]{36}$') {
        throw "State file '$StatePath' does not match this project, subscription, tenant, or ownership schema. Refusing to continue."
    }
}

function Assert-OwnedResourceGroup {
    param(
        [Parameter(Mandatory)] [object]$Group,
        [Parameter(Mandatory)] [object]$State
    )

    if ($Group.name -ne $State.resourceGroup -or $Group.tags.'nlzt-owner' -ne $State.ownerToken) {
        throw "Resource group '$ResourceGroup' exists without this lab's exact ownership token. Refusing to adopt, overwrite, or delete it."
    }
}

function Assert-ConnectorArtifacts {
    $connectorRoot = Join-Path $LabRoot 'connector'
    try {
        $definition = Get-Content -LiteralPath (Join-Path $connectorRoot 'connectorDefinition.json') -Raw | ConvertFrom-Json
        $table = Get-Content -LiteralPath (Join-Path $connectorRoot 'table.json') -Raw | ConvertFrom-Json
        $dcr = Get-Content -LiteralPath (Join-Path $connectorRoot 'dcr.json') -Raw | ConvertFrom-Json
        $dataConnector = Get-Content -LiteralPath (Join-Path $connectorRoot 'dataConnector.json') -Raw | ConvertFrom-Json
    }
    catch {
        throw "A required CCF connector artifact is missing or invalid JSON: $($_.Exception.Message)"
    }

    $definitionResource = @($definition.resources)
    $tableResource = @($table.resources)
    $dcrResource = @($dcr.resources)
    $dataConnectorResource = @($dataConnector.resources)
    $streamName = 'Custom-FeodoTrackerStream'
    if ($definitionResource.Count -ne 1 -or
        $definitionResource[0].name -ne $ConnectorDefinitionName -or
        $definitionResource[0].properties.connectorUiConfig.id -ne $ConnectorDefinitionName -or
        $tableResource.Count -ne 1 -or
        $tableResource[0].apiVersion -ne '2025-07-01' -or
        $tableResource[0].properties.schema.name -ne 'FeodoTracker_CL' -or
        @($tableResource[0].properties.schema.columns | Where-Object { $_.name -eq 'TimeGenerated' -and $_.type -eq 'datetime' }).Count -ne 1 -or
        $dcrResource.Count -ne 1 -or
        -not $dcrResource[0].properties.streamDeclarations.$streamName -or
        $dcrResource[0].properties.dataFlows[0].outputStream -ne 'Custom-FeodoTracker_CL' -or
        $dataConnectorResource.Count -ne 1 -or
        $dataConnectorResource[0].kind -ne 'Push' -or
        $dataConnectorResource[0].properties.connectorDefinitionName -ne $ConnectorDefinitionName -or
        $dataConnectorResource[0].properties.dcrConfig.streamName -ne $streamName) {
        throw 'The four CCF artifacts disagree on the connector ID, table, stream, API version, or resource kind.'
    }
}

Write-Host "`n=== CCF Push Connector Lab ===" -ForegroundColor Cyan
Write-Host "Project:        $ProjectName"
Write-Host "Resource Group: $ResourceGroup"
Write-Host "Location:       $Location"
Write-Host ""

# --- Pre-flight checks ---
Write-Host "[0/6] Pre-flight checks..." -ForegroundColor Yellow

$account = az account show 2>$null | ConvertFrom-Json
if (-not $account) {
    Write-Error "Not logged in. Run 'az login' first."
}
Write-Host "  Subscription: $($account.name) ($($account.id))" -ForegroundColor DarkGray

$state = $null
if (Test-Path -LiteralPath $StatePath) {
    try {
        $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    }
    catch {
        throw "State file '$StatePath' is unreadable or invalid JSON. Refusing to continue."
    }
    Assert-StateMatchesAccount -State $state -Account $account
}

$resourceGroupObject = Get-AzureResourceGroup -Name $ResourceGroup
Assert-ConnectorArtifacts
Write-Host '  Local CCF artifact consistency: passed' -ForegroundColor DarkGray

# --- Destroy ---
if ($Destroy) {
    if (-not $state) {
        throw "Ownership state '$StatePath' is missing. Refusing to delete '$ResourceGroup'."
    }
    if ($resourceGroupObject) {
        Assert-OwnedResourceGroup -Group $resourceGroupObject -State $state
    }

    if (-not $PSCmdlet.ShouldProcess($ResourceGroup, 'Delete the exact owner-tagged resource group and wait for completion')) {
        Write-Host "`nCleanup preview complete; no resources were deleted." -ForegroundColor Yellow
        return
    }

    if ($resourceGroupObject) {
        Write-Host "  Deleting owner-tagged resource group: $ResourceGroup"
        az group delete --name $ResourceGroup --yes --output none
        az group wait --name $ResourceGroup --deleted
        if (Get-AzureResourceGroup -Name $ResourceGroup) {
            throw "Azure still reports resource group '$ResourceGroup' after the deletion wait completed. State was retained."
        }
    }
    Remove-Item -LiteralPath $StatePath -Force
    Write-Host "`nCleanup complete. The exact owner-tagged resource group was removed and verified." -ForegroundColor Green
    Write-Host 'Portal-generated tenant objects and GitHub secrets remain manual cleanup items.' -ForegroundColor Yellow
    return
}

if ($resourceGroupObject -and -not $state) {
    throw "Resource group '$ResourceGroup' already exists but ownership state '$StatePath' is missing. Refusing to adopt, overwrite, or delete it."
}
if ($resourceGroupObject) {
    Assert-OwnedResourceGroup -Group $resourceGroupObject -State $state
}

# Check Python without making the optional sender prerequisite fatal to Azure preview.
$pythonVersion = $null
foreach ($pythonCandidate in @('python3', 'python')) {
    $pythonCommand = Get-Command $pythonCandidate -ErrorAction SilentlyContinue
    if (-not $pythonCommand) {
        continue
    }
    $previousPreference = $PSNativeCommandUseErrorActionPreference
    try {
        $PSNativeCommandUseErrorActionPreference = $false
        $candidateVersion = & $pythonCommand.Source --version 2>$null
        if ($LASTEXITCODE -eq 0 -and $candidateVersion) {
            $pythonVersion = $candidateVersion
            break
        }
    }
    finally {
        $PSNativeCommandUseErrorActionPreference = $previousPreference
    }
}
if (-not $pythonVersion) {
    Write-Host "  Warning: Python 3 not found. Send-ThreatIntel.py requires Python 3.10+" -ForegroundColor Yellow
} else {
    Write-Host "  Python: $pythonVersion" -ForegroundColor DarkGray
}

if (-not $PSCmdlet.ShouldProcess($ResourceGroup, 'Create or update the exact owner-tagged CCF Push lab')) {
    Write-Host "`nDeployment preview complete; no Azure resources or local state were changed." -ForegroundColor Green
    return
}

if (-not $state) {
    $state = [ordered]@{
        schemaVersion           = 1
        projectName             = $ProjectName
        subscriptionId          = $account.id
        tenantId                = $account.tenantId
        resourceGroup           = $ResourceGroup
        workspaceName           = $WorkspaceName
        ownerToken              = [guid]::NewGuid().ToString()
        connectorDefinitionName = $ConnectorDefinitionName
        workbookId              = $null
        sentinelRulesEnabled    = $false
    }
    $state.workbookId = Get-LabResourceGuid -ResourceKey 'workbook'
    Write-JsonAtomic -Path $StatePath -Value $state
    Write-Host "  Created local ownership state: $StatePath" -ForegroundColor DarkGray
}

# --- Step 1: Deploy infrastructure ---
Write-Host "`n[1/6] Deploying infrastructure (Bicep)..." -ForegroundColor Yellow

if (-not $resourceGroupObject) {
    az group create `
        --name $ResourceGroup `
        --location $Location `
        --tags "nlzt-owner=$($state.ownerToken)" 'nlzt-lab=sentinel-ccf-push' `
        --output none 2>$null
    $resourceGroupObject = Get-AzureResourceGroup -Name $ResourceGroup
    if (-not $resourceGroupObject) {
        throw "Resource group '$ResourceGroup' was not readable after creation."
    }
}
Assert-OwnedResourceGroup -Group $resourceGroupObject -State $state
Write-Host "  Resource group: $ResourceGroup"

$bicepPath = Join-Path $LabRoot 'bicep' 'main.bicep'
$deployment = az deployment group create `
    --resource-group $ResourceGroup `
    --template-file $bicepPath `
    --parameters location=$Location projectName=$ProjectName ownerToken=$($state.ownerToken) `
    --output json 2>$null | ConvertFrom-Json

if (-not $deployment.properties.outputs.workspaceName.value) {
    Write-Error "Bicep deployment failed"
}

$workspaceName = $deployment.properties.outputs.workspaceName.value
$workspaceResourceId = $deployment.properties.outputs.workspaceResourceId.value
$workspaceCustomerId = $deployment.properties.outputs.workspaceCustomerId.value
Write-Host "  Workspace: $workspaceName ($workspaceCustomerId)" -ForegroundColor Green

# --- Step 2: Verify Sentinel onboarding from the owned Bicep deployment ---
Write-Host "`n[2/6] Verifying Microsoft Sentinel onboarding..." -ForegroundColor Yellow
$onboardingState = az rest --method GET `
    --url "$workspaceResourceId/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2024-03-01" `
    2>$null | ConvertFrom-Json
if ($onboardingState.name -ne 'default') {
    throw 'The owned Bicep deployment did not return the exact Sentinel onboarding state.'
}
Write-Host "  Sentinel onboarding verified" -ForegroundColor Green

# --- Step 3: Preflight any separately packaged CCF Push connector ---
Write-Host "`n[3/6] Preflighting packaged CCF Push connector state..." -ForegroundColor Yellow
$connectorDefinitions = Get-PagedAzRestValues `
    -InitialUrl "$workspaceResourceId/providers/Microsoft.SecurityInsights/dataConnectorDefinitions?api-version=2024-01-01-preview"
$expectedConnectorTitle = 'Feodotracker Botnet C2 Feed (CCF Push)'
$sameTitleConnectors = @($connectorDefinitions | Where-Object {
    $_.properties.connectorUiConfig.title -eq $expectedConnectorTitle
})
$exactConnectors = @($connectorDefinitions | Where-Object { $_.name -eq $ConnectorDefinitionName })
if ($sameTitleConnectors.Count -gt 1) {
    throw "Multiple connector definitions already use title '$expectedConnectorTitle'. Refusing an ambiguous deployment."
}
if ($sameTitleConnectors.Count -eq 1 -and $sameTitleConnectors[0].name -ne $ConnectorDefinitionName) {
    throw "A non-lab connector definition already uses title '$expectedConnectorTitle'. Refusing to adopt or overwrite it."
}
if ($exactConnectors.Count -gt 1) {
    throw "Multiple connector definitions returned ID '$ConnectorDefinitionName'. Refusing to continue."
}
if ($exactConnectors.Count -eq 1 -and (
    $exactConnectors[0].properties.connectorUiConfig.id -ne $ConnectorDefinitionName -or
    $exactConnectors[0].properties.connectorUiConfig.publisher -ne 'Nine Lives, Zero Trust (Lab)' -or
    $exactConnectors[0].properties.connectorUiConfig.title -ne $expectedConnectorTitle
)) {
    throw "Connector definition '$ConnectorDefinitionName' exists without this lab's exact provenance. Refusing to overwrite it."
}
Write-Host "  Connector definition collision check passed" -ForegroundColor Green
Write-Host '  Local artifacts were validated; this script does not package or install the connector solution.' -ForegroundColor DarkGray

# --- Step 4: Deploy analytics rules ---
if (-not $SkipSentinel) {
    Write-Host "`n[4/6] Deploying Sentinel analytics rules..." -ForegroundColor Yellow

    $rules = @(
        @{
            displayName = "LAB - New Feed Malware Label Observed"
            description = "Selects a malware label present in the last hour but absent from the preceding 14-day workspace lookback. Ingestion gaps and label changes can produce the same result."
            severity    = "High"
            query       = @"
let KnownFamilies = FeodoTracker_CL
    | where TimeGenerated > ago(14d) and TimeGenerated < ago(1h)
    | where isnotempty(malware)
    | distinct malware;
FeodoTracker_CL
| where TimeGenerated > ago(1h)
| summarize arg_max(TimeGenerated, *) by ip_address
| where malware !in (KnownFamilies)
| summarize IndicatorCount = dcount(ip_address), FirstIP = min(ip_address), Countries = make_set(country, 10) by malware
| project TimeGenerated = now(), malware, IndicatorCount, FirstIP, Countries
"@
            queryPeriod    = "P14D"
            tactics        = @()
            techniques     = @()
            subTechniques  = @()
        },
        @{
            displayName = "LAB - Feed Indicator Count Increase"
            description = "Selects a greater than 50 percent increase in distinct online feed IPs between adjacent 24-hour windows. Feed coverage changes can produce the same result."
            severity    = "Medium"
            query       = @"
let Current = FeodoTracker_CL
    | where TimeGenerated > ago(1d)
    | where status == "online"
    | summarize CurrentCount = dcount(ip_address)
    | extend _key = 1;
let Previous = FeodoTracker_CL
    | where TimeGenerated between (ago(2d) .. ago(1d))
    | where status == "online"
    | summarize PreviousCount = dcount(ip_address)
    | extend _key = 1;
Current | join kind=inner (Previous) on _key
| where PreviousCount > 0
| extend ChangePercent = round(100.0 * (CurrentCount - PreviousCount) / PreviousCount, 1)
| where ChangePercent > 50
| project TimeGenerated = now(), CurrentCount, PreviousCount, ChangePercent
"@
            queryPeriod    = "P2D"
            tactics        = @()
            techniques     = @()
            subTechniques  = @()
        },
        @{
            displayName = "LAB - Recent Feed Indicators on 443 or 8443"
            description = "Selects recent online feed indicators on ports commonly associated with TLS. Port alone does not prove encryption, evasion, or current compromise."
            severity    = "High"
            query       = @"
FeodoTracker_CL
| where TimeGenerated > ago(1h)
| summarize arg_max(TimeGenerated, *) by ip_address
| where status == "online"
| where port in (443, 8443)
| where last_seen > ago(7d)
| project TimeGenerated, ip_address, port, malware, country, first_seen, last_seen
"@
            tactics        = @()
            techniques     = @()
            subTechniques  = @()
        },
        @{
            displayName = "LAB - Feed Country Concentration"
            description = "Selects countries associated with at least 10 distinct feed IPs in the last hour. It is a geographic aggregation, not attribution."
            severity    = "Medium"
            query       = @"
FeodoTracker_CL
| where TimeGenerated > ago(1h)
| summarize C2Count = dcount(ip_address), Families = make_set(malware, 10), Ports = make_set(port, 10), SampleIPs = make_set(ip_address, 5) by country
| where C2Count >= 10
| project TimeGenerated = now(), country, C2Count, Families, Ports, SampleIPs
"@
            tactics        = @()
            techniques     = @()
            subTechniques  = @()
        },
        @{
            displayName = "LAB - Network Traffic Match to Feed Indicator"
            description = "Correlates recent Feodotracker IPs with supported network-log fields. A match is a triage lead, not proof of compromise."
            severity    = "High"
            query       = @"
let ActiveC2 = FeodoTracker_CL
    | where TimeGenerated > ago(7d)
    | where status == "online"
    | distinct ip_address, malware, port;
union isfuzzy=true
    (datatable(TimeGenerated:datetime, SourceIP:string, DestinationIP:string, LogSource:string, Details:string)[]),
    (CommonSecurityLog | where TimeGenerated > ago(1d) | where isnotempty(DestinationIP) | project TimeGenerated, SourceIP, DestinationIP, LogSource = DeviceProduct, Details = Activity),
    (DnsEvents | where TimeGenerated > ago(1d) | where isnotempty(IPAddresses) | mv-expand IPAddress = split(IPAddresses, ",") | project TimeGenerated, SourceIP = ClientIP, DestinationIP = tostring(IPAddress), LogSource = "DNS", Details = Name)
| join kind=inner ActiveC2 on `$left.DestinationIP == `$right.ip_address
| project TimeGenerated, SourceIP, DestinationIP, malware, LogSource, Details
"@
            queryPeriod    = "P7D"
            tactics        = @()
            techniques     = @()
            subTechniques  = @()
        }
    )

    $ownerMarker = "[nlzt-owner:$($state.ownerToken)]"
    $existingRules = @(Get-PagedAzRestValues `
        -InitialUrl "$workspaceResourceId/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-03-01")
    $deprecatedRuleNames = @(
        'LAB - New Botnet Family Detected',
        'LAB - C2 Infrastructure Surge',
        'LAB - High-Confidence Active C2',
        'LAB - Geographic C2 Concentration',
        'LAB - Network Traffic to Known Botnet C2'
    )
    foreach ($deprecatedRuleName in $deprecatedRuleNames) {
        $deprecatedId = Get-LabResourceGuid -ResourceKey "rule:$deprecatedRuleName"
        $deprecatedMatches = @($existingRules | Where-Object { $_.name -eq $deprecatedId })
        if ($deprecatedMatches.Count -eq 1 -and
            ([string]$deprecatedMatches[0].properties.description).Contains($ownerMarker)) {
            throw "An owned rule from the earlier overstated detection set still exists ('$deprecatedRuleName'). Run the exact manifest-bound -Destroy flow, then redeploy; this script will not leave or silently delete it."
        }
    }
    foreach ($rule in $rules) {
        $rule.ruleId = Get-LabResourceGuid -ResourceKey "rule:$($rule.displayName)"
        $sameName = @($existingRules | Where-Object { $_.properties.displayName -eq $rule.displayName })
        $exactId = @($existingRules | Where-Object { $_.name -eq $rule.ruleId })

        if ($sameName.Count -gt 1) {
            throw "Multiple analytics rules already use display name '$($rule.displayName)'. Refusing an ambiguous deployment."
        }
        if ($sameName.Count -eq 1 -and $sameName[0].name -ne $rule.ruleId) {
            throw "A non-lab analytics rule already uses display name '$($rule.displayName)'. Refusing to adopt or overwrite it."
        }
        if ($exactId.Count -gt 1) {
            throw "Multiple analytics rules returned the deterministic ID '$($rule.ruleId)'. Refusing to continue."
        }
        if ($exactId.Count -eq 1) {
            $existingDescription = [string]$exactId[0].properties.description
            if ($exactId[0].properties.displayName -ne $rule.displayName -or -not $existingDescription.Contains($ownerMarker)) {
                throw "Analytics rule '$($rule.ruleId)' exists but its ownership marker does not match this lab. Refusing to overwrite it."
            }
        }
    }

    $existingWorkbooks = @(
        az resource list `
            --resource-group $ResourceGroup `
            --resource-type Microsoft.Insights/workbooks `
            --output json 2>$null | ConvertFrom-Json
    )
    $sameTitleWorkbooks = @($existingWorkbooks | Where-Object {
        $_.properties.displayName -eq $WorkbookDisplayName -or $_.tags.'hidden-title' -eq $WorkbookDisplayName
    })
    $exactWorkbook = @($existingWorkbooks | Where-Object { $_.name -eq $state.workbookId })
    if ($sameTitleWorkbooks.Count -gt 1) {
        throw "Multiple workbooks already use title '$WorkbookDisplayName'. Refusing an ambiguous deployment."
    }
    if ($sameTitleWorkbooks.Count -eq 1 -and $sameTitleWorkbooks[0].name -ne $state.workbookId) {
        throw "A non-lab workbook already uses title '$WorkbookDisplayName'. Refusing to adopt or overwrite it."
    }
    if ($exactWorkbook.Count -gt 1) {
        throw "Multiple workbooks returned the deterministic ID '$($state.workbookId)'. Refusing to continue."
    }
    if ($exactWorkbook.Count -eq 1 -and (
        $exactWorkbook[0].tags.'nlzt-owner' -ne $state.ownerToken -or
        $exactWorkbook[0].tags.'hidden-title' -ne $WorkbookDisplayName
    )) {
        throw "Workbook '$($state.workbookId)' exists but its ownership marker does not match this lab. Refusing to overwrite it."
    }

    foreach ($rule in $rules) {
        Write-Host "  Deploying: $($rule.displayName)"

        $ruleBody = @{
            kind       = "Scheduled"
            properties = @{
                displayName           = $rule.displayName
                description           = "$($rule.description)`n`nOwnership: $ownerMarker"
                severity              = $rule.severity
                query                 = $rule.query
                queryFrequency        = "PT1H"
                # A scheduled rule only evaluates records whose TimeGenerated falls
                # inside queryPeriod, so any rule whose query reaches further back
                # than one day must widen it or its baseline subquery silently
                # resolves to an empty set. Sentinel caps the lookback at 14 days.
                queryPeriod           = if ($rule.queryPeriod) { $rule.queryPeriod } else { "P1D" }
                triggerOperator       = "GreaterThan"
                triggerThreshold      = 0
                suppressionDuration   = "PT5H"
                suppressionEnabled    = $false
                tactics               = $rule.tactics
                techniques            = $rule.techniques
                subTechniques         = $rule.subTechniques
                enabled               = [bool]$EnableSentinelRules
                incidentConfiguration = @{
                    createIncident        = $true
                    groupingConfiguration = @{
                        enabled               = $true
                        reopenClosedIncident  = $false
                        lookbackDuration      = "PT5H"
                        matchingMethod        = "AllEntities"
                    }
                }
            }
        } | ConvertTo-Json -Depth 10

        $bodyFile = New-TemporaryFile
        try {
            [System.IO.File]::WriteAllText($bodyFile.FullName, $ruleBody, [System.Text.UTF8Encoding]::new($false))
            $ruleAction = if (@($existingRules | Where-Object { $_.name -eq $rule.ruleId }).Count -eq 1) { 'Updated' } else { 'Created' }
            $result = az rest --method PUT `
                --url "$workspaceResourceId/providers/Microsoft.SecurityInsights/alertRules/$($rule.ruleId)?api-version=2024-03-01" `
                --body "@$($bodyFile.FullName)" `
                --headers 'Content-Type=application/json' 2>$null | ConvertFrom-Json
            if ($result.name -ne $rule.ruleId) {
                throw "Azure did not confirm analytics rule '$($rule.ruleId)'."
            }
            Write-Host "    ${ruleAction}: $($result.name) (enabled=$([bool]$EnableSentinelRules))" -ForegroundColor Green
        }
        finally {
            Remove-Item -LiteralPath $bodyFile.FullName -Force -ErrorAction SilentlyContinue
        }
    }
} else {
    Write-Host "`n[4/6] Skipping analytics rules (-SkipSentinel)" -ForegroundColor DarkGray
}

# --- Step 5: Deploy workbook ---
if (-not $SkipSentinel) {
    Write-Host "`n[5/6] Deploying Sentinel workbook..." -ForegroundColor Yellow

    $workbookContent = Get-Content -Raw (Join-Path $LabRoot 'workbook' 'ccf-push-threat-intel-workbook.json')

    $workbookAction = if ($exactWorkbook.Count -eq 1) { 'Updated' } else { 'Created' }

    $workspace = az monitor log-analytics workspace show `
        --resource-group $ResourceGroup `
        --workspace-name $workspaceName 2>$null | ConvertFrom-Json

    $workbookBody = @{
        location   = $workspace.location
        kind       = "shared"
        tags       = @{
            'hidden-title' = $WorkbookDisplayName
            'nlzt-owner'   = $state.ownerToken
            'nlzt-lab'     = 'sentinel-ccf-push'
        }
        properties = @{
            displayName    = $WorkbookDisplayName
            serializedData = $workbookContent
            category       = "sentinel"
            sourceId       = $workspaceResourceId
        }
    } | ConvertTo-Json -Depth 10

    $bodyFile = New-TemporaryFile
    try {
        [System.IO.File]::WriteAllText($bodyFile.FullName, $workbookBody, [System.Text.UTF8Encoding]::new($false))
        $subscriptionId = ($workspaceResourceId -split '/')[2]
        $wbResult = az rest --method PUT `
            --url "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/workbooks/$($state.workbookId)?api-version=2022-04-01" `
            --body "@$($bodyFile.FullName)" `
            --headers 'Content-Type=application/json' 2>$null | ConvertFrom-Json
        if ($wbResult.name -ne $state.workbookId -or $wbResult.tags.'nlzt-owner' -ne $state.ownerToken) {
            throw "Azure did not confirm the exact owned workbook '$($state.workbookId)'."
        }
        Write-Host "  Workbook $($workbookAction.ToLower()): $($wbResult.properties.displayName)" -ForegroundColor Green
    }
    finally {
        Remove-Item -LiteralPath $bodyFile.FullName -Force -ErrorAction SilentlyContinue
    }

    $state.sentinelRulesEnabled = [bool]$EnableSentinelRules
    Write-JsonAtomic -Path $StatePath -Value $state
} else {
    Write-Host "`n[5/6] Skipping workbook (-SkipSentinel)" -ForegroundColor DarkGray
}

# --- Step 6: Summary ---
Write-Host "`n[6/6] Deployment complete!" -ForegroundColor Green
Write-Host ""
Write-Host "=== Deployed Resources ===" -ForegroundColor Cyan
Write-Host "  Resource Group:    $ResourceGroup"
Write-Host "  Workspace:         $workspaceName ($workspaceCustomerId)"
Write-Host "  Connector artifacts: validated locally (not packaged or installed)"
if (-not $SkipSentinel) {
    Write-Host "  Analytics Rules:   5 scheduled rules (enabled=$([bool]$EnableSentinelRules))"
    Write-Host "  Workbook:          Threat Intelligence Dashboard"
}
Write-Host ""
Write-Host "=== IMPORTANT: Manual Step Required ===" -ForegroundColor Yellow
Write-Host @"
  1. Package the four files under connector/ as a Microsoft Sentinel solution
     with Microsoft's current Azure-Sentinel Create-Azure-Sentinel-Solution tooling.
  2. Deploy that generated package to this exact owned resource group/workspace.
  3. Open Microsoft Sentinel > Data Connectors, find the Feodotracker connector,
     and click "Deploy Push Connector Resources".
  4. Copy the connection credentials (shown once) and store them securely.
  5. Set environment variables:
       $env:CCF_TENANT_ID = "<tenant-id>"
       $env:CCF_CLIENT_ID = "<client-id>"
       $env:CCF_CLIENT_SECRET = "<client-secret>"
       $env:CCF_DCE_URI = "<dce-uri>"
       $env:CCF_DCR_ID = "<dcr-immutable-id>"
  6. Run: python3 $ScriptDir/Send-ThreatIntel.py
  7. Allow for ingestion latency, then run Test-CCFPush.ps1.

  Official guide:
  https://learn.microsoft.com/azure/sentinel/isv/create-push-codeless-connector
"@
Write-Host ""
Write-Host "Cleanup:" -ForegroundColor Yellow
Write-Host "  ./Deploy-Lab.ps1 -ProjectName '$ProjectName' -Destroy"
Write-Host ""
