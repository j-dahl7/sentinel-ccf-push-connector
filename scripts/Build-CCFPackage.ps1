#Requires -Version 7.6
<#
.SYNOPSIS
  Generates a local CCF package using an explicitly supplied, pinned Microsoft tooling checkout.
.DESCRIPTION
  No Azure login, deployment, catalog API, or credential discovery is performed.
  Microsoft's validation stage can download its checksum-pinned ARM-TTK archive.
  A new Solutions folder is required; existing folders are never overwritten or deleted.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$AzureSentinelRoot,
    [ValidatePattern('^[A-Za-z][A-Za-z0-9]{3,60}$')]
    [string]$SolutionName = 'NineLivesFeodoTrackerLab'
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$labRoot = Split-Path -Parent $PSScriptRoot
$toolRoot = (Resolve-Path -LiteralPath $AzureSentinelRoot).Path
$lock = Get-Content -LiteralPath (Join-Path $labRoot 'packaging/tooling.lock.json') -Raw | ConvertFrom-Json
$actualCommit = (& git -C $toolRoot rev-parse HEAD).Trim()
if ($actualCommit -cne $lock.commit) { throw "Expected Microsoft tooling revision $($lock.commit); found $actualCommit." }
if (& git -C $toolRoot status --porcelain -- 'Tools/Create-Azure-Sentinel-Solution') {
    throw 'Microsoft packaging tools are modified; refusing to execute an unreviewed tool tree.'
}
$tool = Join-Path $toolRoot 'Tools/Create-Azure-Sentinel-Solution/V3/createSolutionV3.ps1'
if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw 'The supplied checkout does not contain the Microsoft V3 packager.' }
if (-not (Test-Path -LiteralPath (Join-Path $toolRoot 'Solutions/Templates') -PathType Container)) { throw 'Include Solutions/Templates in the Microsoft tooling checkout for ARM-TTK validation.' }
$solutionRoot = Join-Path (Join-Path $toolRoot 'Solutions') $SolutionName
if (Test-Path -LiteralPath $solutionRoot) { throw "Output '$solutionRoot' already exists; choose a new SolutionName. No files were overwritten." }
$dataRoot = Join-Path $solutionRoot 'Data'
$connectorRoot = Join-Path $solutionRoot 'Data Connectors/NineLivesFeodoTrackerLogs_ccp'
New-Item -ItemType Directory -Path $dataRoot, $connectorRoot | Out-Null
foreach ($name in @('connectorDefinition.json','dataConnector.json','dcr.json','table.json')) {
    Copy-Item -LiteralPath (Join-Path $labRoot "connector/$name") -Destination (Join-Path $connectorRoot $name)
}
$metadata = @{
    publisherId = 'nineliveszerotrust'; offerId = 'nine-lives-feodo-lab'
    version = '3.0.0'
    providers = @('Nine Lives, Zero Trust'); categories = @{ domains = @('Security - Threat Intelligence'); verticals = @() }
    support = @{ name = 'Nine Lives, Zero Trust'; tier = 'Community'; link = 'https://github.com/j-dahl7/sentinel-ccf-push-connector/issues' }
}
$data = [ordered]@{
    Name = $SolutionName; Author = 'Nine Lives, Zero Trust'
    Logo = ''
    Description = 'Educational Feodo CCF Push connector. Offline package generation is not tenant deployment validation.'
    'Data Connectors' = @('Data Connectors/NineLivesFeodoTrackerLogs_ccp/connectorDefinition.json')
    Workbooks = @(); 'Analytic Rules' = @(); Playbooks = @(); Parsers = @(); 'Hunting Queries' = @(); Watchlists = @()
    Metadata = 'SolutionMetadata.json'; BasePath = $solutionRoot.Replace('\','/')
    Version = '3.0.0'; TemplateSpec = $true; Is1PConnector = $false
}
$metadata | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $solutionRoot 'SolutionMetadata.json') -Encoding utf8
$data | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $dataRoot 'Solution_Feodo.json') -Encoding utf8
Push-Location -LiteralPath $toolRoot
try {
    # Metadata intentionally follows Data Connectors in the ordered input. The
    # pinned provider tool collapses a lone metadata resource to a scalar if it
    # processes Metadata first, breaking later resource-array appends.
    & $tool -SolutionDataFolderPath $dataRoot -VersionMode local -VersionBump patch
}
finally { Pop-Location }
$packageRoot = Join-Path $solutionRoot 'Package'
foreach ($name in @('mainTemplate.json','createUiDefinition.json','testParameters.json')) {
    $file = Join-Path $packageRoot $name
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Microsoft packager did not produce '$name'. Keep the output for diagnosis." }
    Get-Content -LiteralPath $file -Raw | ConvertFrom-Json -Depth 100 | Out-Null
}
& (Join-Path $PSScriptRoot 'Test-CCFPackage.ps1') -PackagePath $packageRoot
Write-Host "Generated JSON package: $packageRoot"
Write-Host 'Review generated scopes, identity permissions and credentials before any deployment. No Azure resources were created.'
