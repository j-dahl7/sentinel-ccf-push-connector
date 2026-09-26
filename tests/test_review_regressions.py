"""Behavioral regressions using only fixtures and local PowerShell Azure mocks."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sender_review', ROOT/'scripts/Send-ThreatIntel.py')
sender = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sender)
ENV = dict(CCF_TENANT_ID='tenant', CCF_CLIENT_ID='client', CCF_CLIENT_SECRET='fixture-only',
           CCF_DCE_URI='https://fixture.ingest.monitor.azure.com', CCF_DCR_ID='dcr-fixture')

class EmptySourceTests(unittest.TestCase):
    def test_empty_source_does_not_authenticate_or_ingest(self):
        with patch.dict(os.environ, ENV), patch.object(sender, 'fetch_indicators', return_value=[]), \
                patch.object(sender, 'get_oauth_token') as auth, patch.object(sender, 'send_batch') as send:
            sender.main()
            auth.assert_not_called()
            send.assert_not_called()

    def test_nonempty_malformed_source_is_not_silently_successful(self):
        with patch.dict(os.environ, ENV), patch.object(sender, 'fetch_indicators', return_value=[{'ip_address':'invalid'}]), \
                patch.object(sender, 'get_oauth_token') as auth, patch.object(sender, 'send_batch') as send:
            with self.assertRaisesRegex(RuntimeError, 'nonempty'):
                sender.main()
            auth.assert_not_called()
            send.assert_not_called()

@unittest.skipUnless(shutil.which('pwsh'), 'PowerShell required')
class DeploymentBoundaryTests(unittest.TestCase):
    def test_summary_does_not_expand_existing_client_secret(self):
        harness = r'''
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($env:CCF_TEST_DEPLOY,[ref]$tokens,[ref]$errors)
$summary=@($ast.EndBlock.Statements | Where-Object { $_.Extent.Text -match '^Write-Host @"' -and $_.Extent.Text.Contains('CCF_CLIENT_SECRET') })
if ($summary.Count -ne 1) { throw 'Expected one real summary block' }
$ScriptDir='fixture-script-directory'
& ([scriptblock]::Create($summary[0].Extent.Text))
'''
        secret='FIXTURE_SECRET_MUST_NOT_APPEAR'
        result=subprocess.run(['pwsh','-NoProfile','-NonInteractive','-Command',harness],
                              env={**os.environ,'CCF_TEST_DEPLOY':str(ROOT/'scripts/Deploy-Lab.ps1'),
                                   'CCF_CLIENT_SECRET':secret},capture_output=True,text=True,check=False)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertNotIn(secret,result.stdout+result.stderr)
        self.assertIn('$env:CCF_CLIENT_SECRET',result.stdout)

    def run_fixture(self, mode, broken_artifacts=False):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Path(temp)
            shutil.copytree(ROOT/'scripts', fixture/'scripts')
            shutil.copytree(ROOT/'connector', fixture/'connector')
            if broken_artifacts:
                (fixture/'connector/table.json').write_text('{broken', encoding='utf-8')
            state = dict(schemaVersion=1, projectName='audit-test', subscriptionId='sub', tenantId='tenant',
                         resourceGroup='audit-test-rg', workspaceName='audit-test-law',
                         ownerToken='00000000-0000-0000-0000-000000000001')
            (fixture/'.ccf-push-lab-state-audit-test.json').write_text(json.dumps(state), encoding='utf-8')
            harness = r'''
$ErrorActionPreference = 'Stop'
function global:az {
    $global:LASTEXITCODE = 0
    if ($args[0] -eq 'account') { return '{"id":"sub","tenantId":"tenant","name":"Fixture"}' }
    if ($args[0] -eq 'group' -and $args[1] -eq 'exists') { return 'true' }
    if ($args[0] -eq 'group' -and $args[1] -eq 'show') {
        return '{"name":"audit-test-rg","tags":{"nlzt-owner":"00000000-0000-0000-0000-000000000001"}}'
    }
    if ($args[0] -eq 'rest' -and $args[2] -eq 'GET') { return '{"value":[]}' }
    throw 'MUTATION OR UNEXPECTED CALL REFUSED BY TEST'
}
$params=@{ ProjectName='audit-test'; WhatIf=$true }
if ($env:CCF_TEST_MODE -eq 'destroy') { $params.Destroy=$true }
if ($env:CCF_TEST_MODE -eq 'enable') { $params.EnableSentinelRules=$true }
& $env:CCF_TEST_DEPLOY @params
'''
            return subprocess.run(['pwsh','-NoProfile','-NonInteractive','-Command',harness],
                                  env={**os.environ,'CCF_TEST_DEPLOY':str(fixture/'scripts/Deploy-Lab.ps1'),
                                       'CCF_TEST_MODE':mode},capture_output=True,text=True,check=False)

    def test_owned_destroy_preview_ignores_broken_local_packaging_files(self):
        result=self.run_fixture('destroy', True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('Cleanup preview complete',result.stdout)

    def test_deploy_rejects_broken_packaging_before_mutation(self):
        result=self.run_fixture('deploy', True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('invalid JSON',result.stdout+result.stderr)
        self.assertNotIn('MUTATION OR UNEXPECTED',result.stdout+result.stderr)

    def test_enable_is_refused_without_the_provisioned_table(self):
        result=self.run_fixture('enable')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('FeodoTracker_CL is absent',result.stdout+result.stderr)
        self.assertNotIn('MUTATION OR UNEXPECTED',result.stdout+result.stderr)

if __name__ == '__main__': unittest.main()
