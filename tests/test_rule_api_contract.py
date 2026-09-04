"""Capture the real rule serialization block with local Azure mocks only."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest


DEPLOY_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "Deploy-Lab.ps1"
HARNESS = r"""
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($env:CCF_DEPLOY_SCRIPT, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Deployment script did not parse' }
$guidFunction = @($ast.EndBlock.Statements | Where-Object {
    $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq 'Get-LabResourceGuid'
})
$ruleBlock = @($ast.EndBlock.Statements | Where-Object {
    $_ -is [System.Management.Automation.Language.IfStatementAst] -and $_.Extent.Text -match '\$rules\s*=\s*@\('
})
if ($guidFunction.Count -ne 1 -or $ruleBlock.Count -ne 1) { throw 'Expected one real GUID helper and one rule deployment block' }
. ([scriptblock]::Create($guidFunction[0].Extent.Text))
$script:state = @{ ownerToken = '00000000-0000-0000-0000-000000000001'; workbookId = '00000000-0000-0000-0000-000000000002' }
$workspaceResourceId = '/subscriptions/mock/resourceGroups/mock/providers/Microsoft.OperationalInsights/workspaces/mock'
$ResourceGroup = 'mock'
$WorkbookDisplayName = 'Mock workbook'
$SkipSentinel = $false
$EnableSentinelRules = $env:CCF_ENABLE_RULES -eq 'true'
$global:RuleRequests = [System.Collections.Generic.List[object]]::new()
function Get-PagedAzRestValues { param([string]$InitialUrl) return @() }
function global:az {
    $arguments = @($args | ForEach-Object { [string]$_ })
    $global:LASTEXITCODE = 0
    if ($arguments[0] -eq 'resource' -and $arguments[1] -eq 'list') { return '[]' }
    if ($arguments[0] -ne 'rest' -or $arguments[[array]::IndexOf($arguments, '--method') + 1] -ne 'PUT') {
        throw ('Unexpected mocked Azure call: ' + ($arguments -join ' '))
    }
    $url = $arguments[[array]::IndexOf($arguments, '--url') + 1]
    if ($url -notmatch '/alertRules/([^?]+)\?api-version=2024-03-01$') { throw 'Unexpected resource or API version' }
    $name = $Matches[1]
    $bodyArg = $arguments[[array]::IndexOf($arguments, '--body') + 1]
    if (-not $bodyArg.StartsWith('@')) { throw 'Expected a local JSON body file' }
    $body = Get-Content -LiteralPath $bodyArg.Substring(1) -Raw | ConvertFrom-Json
    $global:RuleRequests.Add(@{ url = $url; body = $body })
    return (@{ name = $name } | ConvertTo-Json -Compress)
}
& ([scriptblock]::Create($ruleBlock[0].Extent.Text))
'RESULT:' + (ConvertTo-Json -InputObject @($global:RuleRequests.ToArray()) -Depth 20 -Compress)
"""


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is not available")
class RuleApiContractTests(unittest.TestCase):
    def test_all_five_put_bodies_use_supported_stable_properties(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                result = subprocess.run(
                    ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", HARNESS],
                    env={**os.environ, "CCF_DEPLOY_SCRIPT": str(DEPLOY_SCRIPT),
                         "CCF_ENABLE_RULES": str(enabled).lower()},
                    text=True, capture_output=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                lines = [line[7:] for line in result.stdout.splitlines() if line.startswith("RESULT:")]
                self.assertEqual(len(lines), 1, result.stdout)
                requests = json.loads(lines[0])
                self.assertEqual(len(requests), 5)
                for request in requests:
                    body = request["body"]
                    self.assertEqual(body["kind"], "Scheduled")
                    self.assertNotIn("subTechniques", body["properties"])
                    self.assertEqual(body["properties"]["tactics"], [])
                    self.assertEqual(body["properties"]["techniques"], [])
                    self.assertEqual(body["properties"]["enabled"], enabled)
                    self.assertIn("FeodoTracker_CL", body["properties"]["query"])


if __name__ == "__main__":
    unittest.main()
