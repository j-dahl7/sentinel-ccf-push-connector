#Requires -Version 7.6
[CmdletBinding()]
param([Parameter(Mandatory)] [string]$PackagePath)
$ErrorActionPreference = 'Stop'
$resources = [System.Collections.Generic.List[object]]::new()
function Read-NestedResource {
    param([object]$Node)
    if ($Node -is [array]) { foreach ($entry in $Node) { Read-NestedResource $entry }; return }
    if ($Node -isnot [pscustomobject]) { return }
    if ($Node.PSObject.Properties['type'] -and $Node.PSObject.Properties['properties']) { $resources.Add($Node) }
    foreach ($property in $Node.PSObject.Properties) { Read-NestedResource $property.Value }
}
$text = Get-Content -LiteralPath (Join-Path $PackagePath 'mainTemplate.json') -Raw
if ($text.Contains('<auto-provisioned>')) { throw 'Unresolved literal auto-provisioned placeholder in generated package.' }
Read-NestedResource ($text | ConvertFrom-Json -Depth 100)
$definitions = @($resources | Where-Object { $_.type -match '/dataConnectorDefinitions$' })
$push = @($resources | Where-Object { $_.type -match '/dataConnectors$' -and $_.kind -eq 'Push' })
$dcr = @($resources | Where-Object { $_.type -eq 'Microsoft.Insights/dataCollectionRules' })
$tables = @($resources | Where-Object { $_.type -eq 'Microsoft.OperationalInsights/workspaces/tables' })
if (-not $definitions -or -not $push -or -not $dcr -or -not $tables) {
    throw 'Generated package is missing a connector definition, Push resource, DCR or table.'
}
if (@($push | Where-Object {
    $_.properties.dcrConfig.streamName -eq 'Custom-FeodoTrackerStream' -and
    $_.properties.dcrConfig.dataCollectionEndpoint -eq "[[parameters('dcrConfig').dataCollectionEndpoint]" -and
    $_.properties.auth.appId -eq "[[parameters('auth').appId]"
}).Count -ne 1) { throw 'Generated Push connector lost its stream or runtime identity expressions.' }
if (@($dcr | Where-Object { $_.properties.dataFlows.outputStream -contains 'Custom-FeodoTracker_CL' }).Count -ne 1) { throw 'Generated DCR does not target the expected table stream.' }
if (@($tables | Where-Object { $_.properties.schema.name -eq 'FeodoTracker_CL' }).Count -ne 1) { throw 'Generated table schema is missing or duplicated.' }
Write-Host 'Generated CCF resource/stream/runtime-expression checks passed; this is not a cloud deployment test.'
