#Requires -Version 7.0
<#
.SYNOPSIS
    Deploys the CCF Push Connector Lab.

.DESCRIPTION
    Deploys a complete custom Sentinel connector using CCF Push mode:
    1. Infrastructure (Bicep: Log Analytics workspace + Sentinel onboarding)
    2. Sentinel onboarding state
    3. CCF Push connector definition (data connector auto-provisioned via portal)
    4. Sentinel analytics rules (5 scheduled rules for botnet C2 detection)
    5. Sentinel workbook (Threat Intelligence Dashboard)

    After deployment, open the Sentinel Data Connectors gallery and click
    "Deploy Push Connector Resources" on the Feodotracker connector to
    auto-provision the DCE, DCR, custom table, and Entra app.

    Then run Send-ThreatIntel.py with the provided credentials.

.PARAMETER Location
    Azure region (default: eastus).

.PARAMETER ProjectName
    Resource naming prefix (default: ccf-push-lab).

.PARAMETER SkipSentinel
    Skip deploying analytics rules and workbook.

.PARAMETER Destroy
    Tear down all lab resources.

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
    [switch]$Destroy
)

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LabRoot = Split-Path -Parent $ScriptDir
$ResourceGroup = "$ProjectName-rg"
$WorkspaceName = "$ProjectName-law"

Write-Host "`n=== CCF Push Connector Lab ===" -ForegroundColor Cyan
Write-Host "Project:        $ProjectName"
Write-Host "Resource Group: $ResourceGroup"
Write-Host "Location:       $Location"
Write-Host ""

# --- Destroy ---
if ($Destroy) {
    Write-Host "Destroying lab resources..." -ForegroundColor Red

    $rgExists = az group exists --name $ResourceGroup 2>$null
    if ($rgExists -eq 'true') {
        Write-Host "  Deleting resource group: $ResourceGroup"
        az group delete --name $ResourceGroup --yes --no-wait
        Write-Host "  Resource group deletion initiated (async)" -ForegroundColor Green
    } else {
        Write-Host "  Resource group '$ResourceGroup' not found" -ForegroundColor DarkGray
    }

    Write-Host "`nCleanup complete." -ForegroundColor Green
    return
}

# --- Pre-flight checks ---
Write-Host "[0/6] Pre-flight checks..." -ForegroundColor Yellow

$account = az account show 2>$null | ConvertFrom-Json
if (-not $account) {
    Write-Error "Not logged in. Run 'az login' first."
}
Write-Host "  Subscription: $($account.name) ($($account.id))" -ForegroundColor DarkGray

# Check Python
$pythonVersion = python3 --version 2>$null
if (-not $pythonVersion) {
    Write-Host "  Warning: Python 3 not found. Send-ThreatIntel.py requires Python 3.10+" -ForegroundColor Yellow
} else {
    Write-Host "  Python: $pythonVersion" -ForegroundColor DarkGray
}

# --- Step 1: Deploy infrastructure ---
Write-Host "`n[1/6] Deploying infrastructure (Bicep)..." -ForegroundColor Yellow

az group create --name $ResourceGroup --location $Location --output none 2>$null
Write-Host "  Resource group: $ResourceGroup"

$bicepPath = Join-Path $LabRoot 'bicep' 'main.bicep'
$deployment = az deployment group create `
    --resource-group $ResourceGroup `
    --template-file $bicepPath `
    --parameters location=$Location projectName=$ProjectName `
    --output json 2>$null | ConvertFrom-Json

if (-not $deployment.properties.outputs.workspaceName.value) {
    Write-Error "Bicep deployment failed"
}

$workspaceName = $deployment.properties.outputs.workspaceName.value
$workspaceResourceId = $deployment.properties.outputs.workspaceResourceId.value
$workspaceCustomerId = $deployment.properties.outputs.workspaceCustomerId.value
Write-Host "  Workspace: $workspaceName ($workspaceCustomerId)" -ForegroundColor Green

# --- Step 2: Sentinel onboarding ---
Write-Host "`n[2/6] Onboarding Microsoft Sentinel..." -ForegroundColor Yellow

$onboardBody = @{
    properties = @{
        customerManagedKey = $false
    }
} | ConvertTo-Json

$onboardFile = New-TemporaryFile
[System.IO.File]::WriteAllText($onboardFile.FullName, $onboardBody, [System.Text.Encoding]::UTF8)

az rest --method PUT `
    --url "$workspaceResourceId/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2024-03-01" `
    --body "@$($onboardFile.FullName)" `
    --headers 'Content-Type=application/json' 2>$null | Out-Null

Remove-Item $onboardFile.FullName -ErrorAction SilentlyContinue
Write-Host "  Sentinel onboarded" -ForegroundColor Green

# --- Step 3: Deploy CCF Push connector ---
Write-Host "`n[3/6] Deploying CCF Push connector definition..." -ForegroundColor Yellow

$connectorDefPath = Join-Path $LabRoot 'connector' 'connectorDefinition.json'
az deployment group create `
    --resource-group $ResourceGroup `
    --template-file $connectorDefPath `
    --parameters workspaceName=$workspaceName `
    --output none 2>$null

Write-Host "  Connector definition deployed" -ForegroundColor Green
Write-Host "  Data connector will be auto-provisioned when you click 'Deploy Push Connector Resources' in the portal" -ForegroundColor DarkGray

# --- Step 4: Deploy analytics rules ---
if (-not $SkipSentinel) {
    Write-Host "`n[4/6] Deploying Sentinel analytics rules..." -ForegroundColor Yellow

    $rules = @(
        @{
            displayName = "LAB - New Botnet Family Detected"
            description = "Fires when a malware family appears in the Feodotracker feed for the first time — no historical records in the last 30 days."
            severity    = "High"
            query       = @"
let KnownFamilies = FeodoTracker_CL
    | where TimeGenerated > ago(30d) and TimeGenerated < ago(1h)
    | summarize arg_max(TimeGenerated, *) by ip_address
    | distinct malware;
FeodoTracker_CL
| where TimeGenerated > ago(1h)
| summarize arg_max(TimeGenerated, *) by ip_address
| where malware !in (KnownFamilies)
| summarize IndicatorCount = dcount(ip_address), FirstIP = min(ip_address), Countries = make_set(country, 10) by malware
| project TimeGenerated = now(), malware, IndicatorCount, FirstIP, Countries
"@
            tactics        = @("CommandAndControl")
            techniques     = @("T1071")
            subTechniques  = @()
        },
        @{
            displayName = "LAB - C2 Infrastructure Surge"
            description = "Detects a greater than 50 percent increase in active C2 IPs compared to the previous 24-hour window."
            severity    = "Medium"
            query       = @"
let Current = FeodoTracker_CL
    | where TimeGenerated > ago(1h)
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
            tactics        = @("ResourceDevelopment")
            techniques     = @("T1583")
            subTechniques  = @()
        },
        @{
            displayName = "LAB - High-Confidence Active C2"
            description = "Flags recently active C2 servers using encrypted communication ports (443, 8443) that are the most likely to evade network detection."
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
            tactics        = @("CommandAndControl")
            techniques     = @("T1071", "T1573")
            subTechniques  = @()
        },
        @{
            displayName = "LAB - Geographic C2 Concentration"
            description = "Alerts when 10 or more C2 IPs from the same country appear in a single ingestion batch, indicating concentrated hosting infrastructure."
            severity    = "Medium"
            query       = @"
FeodoTracker_CL
| where TimeGenerated > ago(1h)
| summarize C2Count = dcount(ip_address), Families = make_set(malware, 10), Ports = make_set(port, 10), SampleIPs = make_set(ip_address, 5) by country
| where C2Count >= 10
| project TimeGenerated = now(), country, C2Count, Families, Ports, SampleIPs
"@
            tactics        = @("ResourceDevelopment")
            techniques     = @("T1583")
            subTechniques  = @()
        },
        @{
            displayName = "LAB - Network Traffic to Known Botnet C2"
            description = "Correlates active Feodotracker C2 IPs with network traffic logs. Fires when any device communicates with a known C2 server."
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
            tactics        = @("CommandAndControl")
            techniques     = @("T1071", "T1102")
            subTechniques  = @()
        }
    )

    $existingRulesResponse = az rest --method GET `
        --url "$workspaceResourceId/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-03-01" `
        2>$null | ConvertFrom-Json
    $existingRuleIdsByName = @{}
    foreach ($existingRule in @($existingRulesResponse.value)) {
        $existingDisplayName = $existingRule.properties.displayName
        if ($existingDisplayName) {
            $existingRuleIdsByName[$existingDisplayName] = $existingRule.name
        }
    }

    foreach ($rule in $rules) {
        Write-Host "  Deploying: $($rule.displayName)"

        $ruleBody = @{
            kind       = "Scheduled"
            properties = @{
                displayName           = $rule.displayName
                description           = $rule.description
                severity              = $rule.severity
                query                 = $rule.query
                queryFrequency        = "PT1H"
                queryPeriod           = "P1D"
                triggerOperator       = "GreaterThan"
                triggerThreshold      = 0
                suppressionDuration   = "PT5H"
                suppressionEnabled    = $false
                tactics               = $rule.tactics
                techniques            = $rule.techniques
                subTechniques         = $rule.subTechniques
                enabled               = $true
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
        [System.IO.File]::WriteAllText($bodyFile.FullName, $ruleBody, [System.Text.Encoding]::UTF8)

        $ruleId = if ($existingRuleIdsByName[$rule.displayName]) {
            $existingRuleIdsByName[$rule.displayName]
        } else {
            [guid]::NewGuid().ToString()
        }
        $ruleAction = if ($existingRuleIdsByName[$rule.displayName]) { "Updated" } else { "Created" }
        $result = az rest --method PUT `
            --url "$workspaceResourceId/providers/Microsoft.SecurityInsights/alertRules/${ruleId}?api-version=2024-03-01" `
            --body "@$($bodyFile.FullName)" `
            --headers 'Content-Type=application/json' 2>$null | ConvertFrom-Json

        Remove-Item $bodyFile.FullName -ErrorAction SilentlyContinue

        if ($result.name) {
            Write-Host "    ${ruleAction}: $($result.name)" -ForegroundColor Green
        } else {
            Write-Host "    Warning: Rule may not have deployed correctly" -ForegroundColor Red
        }
    }
} else {
    Write-Host "`n[4/6] Skipping analytics rules (-SkipSentinel)" -ForegroundColor DarkGray
}

# --- Step 5: Deploy workbook ---
if (-not $SkipSentinel) {
    Write-Host "`n[5/6] Deploying Sentinel workbook..." -ForegroundColor Yellow

    $workbookContent = Get-Content -Raw (Join-Path $LabRoot 'workbook' 'ccf-push-threat-intel-workbook.json')

    $workbookDisplayName = "Threat Intelligence Dashboard"
    $existingWorkbook = @(
        az resource list `
            --resource-group $ResourceGroup `
            --resource-type Microsoft.Insights/workbooks `
            2>$null | ConvertFrom-Json
    ) | Where-Object {
        $_.properties.displayName -eq $workbookDisplayName -or $_.tags.'hidden-title' -eq $workbookDisplayName
    } | Select-Object -First 1
    $workbookId = if ($existingWorkbook) { $existingWorkbook.name } else { [guid]::NewGuid().ToString() }
    $workbookAction = if ($existingWorkbook) { "Updated" } else { "Created" }

    $workspace = az monitor log-analytics workspace show `
        --resource-group $ResourceGroup `
        --workspace-name $workspaceName 2>$null | ConvertFrom-Json

    $workbookBody = @{
        location   = $workspace.location
        kind       = "shared"
        tags       = @{
            'hidden-title' = $workbookDisplayName
        }
        properties = @{
            displayName    = $workbookDisplayName
            serializedData = $workbookContent
            category       = "sentinel"
            sourceId       = $workspaceResourceId
        }
    } | ConvertTo-Json -Depth 10

    $bodyFile = New-TemporaryFile
    [System.IO.File]::WriteAllText($bodyFile.FullName, $workbookBody, [System.Text.Encoding]::UTF8)

    $subscriptionId = ($workspaceResourceId -split '/')[2]
    $wbResult = az rest --method PUT `
        --url "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/workbooks/${workbookId}?api-version=2022-04-01" `
        --body "@$($bodyFile.FullName)" `
        --headers 'Content-Type=application/json' 2>$null | ConvertFrom-Json

    Remove-Item $bodyFile.FullName -ErrorAction SilentlyContinue

    if ($wbResult.name) {
        Write-Host "  Workbook $($workbookAction.ToLower()): $($wbResult.properties.displayName)" -ForegroundColor Green
    } else {
        Write-Host "  Warning: Workbook may not have deployed correctly" -ForegroundColor Red
    }
} else {
    Write-Host "`n[5/6] Skipping workbook (-SkipSentinel)" -ForegroundColor DarkGray
}

# --- Step 6: Summary ---
Write-Host "`n[6/6] Deployment complete!" -ForegroundColor Green
Write-Host ""
Write-Host "=== Deployed Resources ===" -ForegroundColor Cyan
Write-Host "  Resource Group:    $ResourceGroup"
Write-Host "  Workspace:         $workspaceName ($workspaceCustomerId)"
Write-Host "  Connector:         Feodotracker Botnet C2 Feed (CCF Push)"
if (-not $SkipSentinel) {
    Write-Host "  Analytics Rules:   5 scheduled rules"
    Write-Host "  Workbook:          Threat Intelligence Dashboard"
}
Write-Host ""
Write-Host "=== IMPORTANT: Manual Step Required ===" -ForegroundColor Yellow
Write-Host @"
  1. Open Microsoft Sentinel > Data Connectors
  2. Find "Feodotracker Botnet C2 Feed (CCF Push)"
  3. Click "Deploy Push Connector Resources"
  4. Copy the connection credentials (shown once)
  5. Set environment variables:
       $env:CCF_TENANT_ID = "<tenant-id>"
       $env:CCF_CLIENT_ID = "<client-id>"
       $env:CCF_CLIENT_SECRET = "<client-secret>"
       $env:CCF_DCE_URI = "<dce-uri>"
       $env:CCF_DCR_ID = "<dcr-immutable-id>"
  6. Run: python3 $ScriptDir/Send-ThreatIntel.py
  7. Wait 5-10 minutes, then query: FeodoTracker_CL | take 10
"@
Write-Host ""
Write-Host "Cleanup:" -ForegroundColor Yellow
Write-Host "  ./Deploy-Lab.ps1 -Destroy"
Write-Host ""
