import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "Send-ThreatIntel.py"
SPEC = importlib.util.spec_from_file_location("send_threat_intel", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class _Response:
    def __init__(self, status_code=204, headers=None):
        self.status_code = status_code
        self.headers = headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise MODULE.requests.exceptions.HTTPError(
                f"HTTP {self.status_code}", response=self
            )


class SenderTests(unittest.TestCase):
    def test_transform_normalizes_and_filters_records(self):
        records = MODULE.transform([
            {
                "ip_address": "192.0.2.10",
                "port": "443",
                "status": "online",
                "malware": "Example",
                "first_seen": "2026-07-10T10:00:00Z",
                "last_online": "2026-07-10T11:00:00Z",
                "country": "US",
            },
            {"ip_address": "not-an-ip", "port": 443},
            {"ip_address": "192.0.2.11", "port": 70000},
            "not-an-object",
        ])

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["port"], 443)
        self.assertEqual(records[0]["ip_address"], "192.0.2.10")

    @patch.object(MODULE.requests, "post", return_value=_Response())
    def test_send_batch_normalizes_endpoint(self, post):
        status = MODULE.send_batch(
            [{"ip_address": "192.0.2.10"}],
            "https://example.ingest.monitor.azure.com/",
            "dcr-example",
            "Custom-FeodoTrackerStream",
            "token",
        )

        self.assertEqual(status, 204)
        self.assertNotIn(".com//dataCollectionRules", post.call_args.args[0])
        self.assertFalse(post.call_args.kwargs["allow_redirects"])

    def test_ingestion_url_rejects_non_azure_hosts_and_unsafe_path_segments(self):
        invalid_inputs = (
            ("http://example.ingest.monitor.azure.com", "dcr-example", "Custom-Feed"),
            ("https://attacker.example", "dcr-example", "Custom-Feed"),
            ("https://example.ingest.monitor.azure.com@attacker.example", "dcr-example", "Custom-Feed"),
            ("https://example.ingest.monitor.azure.com/extra", "dcr-example", "Custom-Feed"),
            ("https://example.ingest.monitor.azure.com", "../other", "Custom-Feed"),
            ("https://example.ingest.monitor.azure.com", "dcr-example", "Custom-../other"),
        )
        for dce_uri, dcr_id, stream_name in invalid_inputs:
            with self.subTest(dce_uri=dce_uri, dcr_id=dcr_id, stream_name=stream_name):
                with self.assertRaises(ValueError):
                    MODULE.build_ingestion_url(dce_uri, dcr_id, stream_name)

    @patch.object(MODULE.time, "sleep")
    @patch.object(
        MODULE.requests,
        "post",
        return_value=_Response(302, {"Location": "https://attacker.example/steal"}),
    )
    def test_ingestion_redirect_is_never_followed(self, post, sleep):
        with self.assertRaises(MODULE.requests.exceptions.HTTPError):
            MODULE.send_batch(
                [{"ip_address": "192.0.2.10"}],
                "https://example.ingest.monitor.azure.com",
                "dcr-example",
                "Custom-FeodoTrackerStream",
                "token",
            )

        self.assertEqual(post.call_count, MODULE.MAX_RETRIES)
        self.assertTrue(all(call.kwargs["allow_redirects"] is False for call in post.call_args_list))
        self.assertTrue(
            all(call.args[0].startswith("https://example.ingest.monitor.azure.com/") for call in post.call_args_list)
        )

    @patch.object(MODULE.time, "sleep")
    @patch.object(MODULE.requests, "post", return_value=_Response(429))
    def test_terminal_rate_limit_raises_instead_of_reporting_success(self, post, sleep):
        with self.assertRaises(MODULE.requests.exceptions.HTTPError):
            MODULE.send_batch(
                [{"ip_address": "192.0.2.10"}],
                "https://example.ingest.monitor.azure.com",
                "dcr-example",
                "Custom-FeodoTrackerStream",
                "token",
            )

        self.assertEqual(post.call_count, MODULE.MAX_RETRIES)
        self.assertEqual(sleep.call_count, MODULE.MAX_RETRIES - 1)

    def test_get_env_rejects_blank_values(self):
        with patch.dict(MODULE.os.environ, {"EXAMPLE": "  "}):
            with self.assertRaises(SystemExit):
                MODULE.get_env("EXAMPLE")

    def test_workflow_runs_unit_tests_before_ingestion(self):
        workflow = (
            MODULE_PATH.parents[1] / ".github" / "workflows" / "ingest.yml"
        ).read_text(encoding="utf-8")

        test_step = workflow.index("python -m unittest discover -s tests -v")
        ingest_step = workflow.index("python scripts/Send-ThreatIntel.py")
        self.assertLess(test_step, ingest_step)
        self.assertIn("--require-hashes -r scripts/requirements.lock", workflow)

    def test_workflow_pr_and_default_manual_runs_do_not_ingest(self):
        workflow = (
            MODULE_PATH.parents[1] / ".github" / "workflows" / "ingest.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("pull_request:", workflow)
        self.assertIn("perform_ingest:", workflow)
        self.assertIn(
            "if: ${{ github.event_name == 'schedule' || inputs.perform_ingest }}",
            workflow,
        )

    def test_destroy_whatif_has_preview_specific_summary(self):
        deploy = (MODULE_PATH.parent / "Deploy-Lab.ps1").read_text(encoding="utf-8")

        self.assertIn("Cleanup preview complete; no resources were deleted.", deploy)
        self.assertNotIn('Write-Host "`nCleanup complete."', deploy)

    def test_deployment_uses_manifest_bound_resource_group_ownership(self):
        deploy = (MODULE_PATH.parent / "Deploy-Lab.ps1").read_text(encoding="utf-8")

        self.assertIn('.ccf-push-lab-state-$ProjectName.json', deploy)
        self.assertIn("'nlzt-owner'", deploy)
        self.assertIn("Refusing to adopt, overwrite, or delete it.", deploy)
        self.assertIn("az group wait --name $ResourceGroup --deleted", deploy)
        self.assertNotIn("--no-wait", deploy)

    def test_sentinel_content_is_deterministic_owned_and_disabled_by_default(self):
        deploy = (MODULE_PATH.parent / "Deploy-Lab.ps1").read_text(encoding="utf-8")

        self.assertIn("function Get-LabResourceGuid", deploy)
        self.assertIn('[switch]$EnableSentinelRules', deploy)
        self.assertIn('enabled               = [bool]$EnableSentinelRules', deploy)
        self.assertIn('Ownership: $ownerMarker', deploy)
        self.assertIn("'nlzt-owner'   = $state.ownerToken", deploy)
        self.assertIn("A non-lab analytics rule already uses display name", deploy)
        self.assertIn("A non-lab workbook already uses title", deploy)
        self.assertIn("function Get-PagedAzRestValues", deploy)
        self.assertIn("Azure returned an untrusted pagination URL", deploy)
        self.assertNotIn("$existingRuleIdsByName", deploy)

    def test_ccf_artifacts_align_with_current_packaging_contract(self):
        connector_root = MODULE_PATH.parents[1] / "connector"
        definition = json.loads(
            (connector_root / "connectorDefinition.json").read_text(encoding="utf-8")
        )["resources"][0]
        table = json.loads(
            (connector_root / "table.json").read_text(encoding="utf-8")
        )["resources"][0]
        dcr = json.loads(
            (connector_root / "dcr.json").read_text(encoding="utf-8")
        )["resources"][0]
        data_connector = json.loads(
            (connector_root / "dataConnector.json").read_text(encoding="utf-8")
        )["resources"][0]

        self.assertEqual(table["apiVersion"], "2025-07-01")
        self.assertEqual(table["properties"]["schema"]["name"], "FeodoTracker_CL")
        self.assertIn(
            "Custom-FeodoTrackerStream",
            dcr["properties"]["streamDeclarations"],
        )
        self.assertEqual(
            dcr["properties"]["dataFlows"][0]["outputStream"],
            "Custom-FeodoTracker_CL",
        )
        self.assertEqual(
            data_connector["properties"]["connectorDefinitionName"],
            definition["properties"]["connectorUiConfig"]["id"],
        )
        self.assertEqual(
            definition["properties"]["connectorUiConfig"]["connectivityCriteria"][0]["type"],
            "IsConnectedQuery",
        )

    def test_azure_script_does_not_claim_raw_definition_is_a_packaged_solution(self):
        deploy = (MODULE_PATH.parent / "Deploy-Lab.ps1").read_text(encoding="utf-8")

        self.assertIn("function Assert-ConnectorArtifacts", deploy)
        self.assertIn("does not package or install the connector solution", deploy)
        self.assertNotIn("--template-file $connectorDefPath", deploy)

    def test_rule_examples_do_not_overstate_feed_metadata(self):
        deploy = (MODULE_PATH.parent / "Deploy-Lab.ps1").read_text(encoding="utf-8")
        hunting = (
            MODULE_PATH.parents[1] / "detection" / "hunting-queries.kql"
        ).read_text(encoding="utf-8")
        workbook = json.loads(
            (
                MODULE_PATH.parents[1]
                / "workbook"
                / "ccf-push-threat-intel-workbook.json"
            ).read_text(encoding="utf-8")
        )

        self.assertIn("LAB - Network Traffic Match to Feed Indicator", deploy)
        self.assertIn("$deprecatedRuleNames", deploy)
        self.assertNotIn('tactics        = @("', deploy)
        self.assertNotIn('techniques     = @("', deploy)
        self.assertNotIn("Prioritize these IPs for immediate blocking", hunting)
        self.assertNotIn("either in bulletproof hosting", hunting)
        serialized = json.dumps(workbook)
        self.assertIn("Triage Only", serialized)
        self.assertNotIn("Network Traffic to Known C2", serialized)

    def test_surge_compares_adjacent_equal_24_hour_windows(self):
        deploy = (MODULE_PATH.parent / "Deploy-Lab.ps1").read_text(encoding="utf-8")

        current = deploy.index("let Current = FeodoTracker_CL")
        previous = deploy.index("let Previous = FeodoTracker_CL", current)
        query = deploy[current:previous]
        self.assertIn("TimeGenerated > ago(1d)", query)
        self.assertNotIn("TimeGenerated > ago(1h)", query)

    def test_validation_uses_manifest_and_exact_ids_not_titles(self):
        validator = (MODULE_PATH.parent / "Test-CCFPush.ps1").read_text(
            encoding="utf-8"
        )

        self.assertIn('.ccf-push-lab-state-$ProjectName.json', validator)
        self.assertIn('Get-LabResourceGuid -ResourceKey "rule:$ruleName"', validator)
        self.assertIn('workbooks/$($state.workbookId)', validator)
        self.assertIn('dataConnectorDefinitions/$($state.connectorDefinitionName)', validator)
        self.assertNotIn('-like "*Feodotracker*"', validator)

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is not available")
    def test_whatif_and_foreign_group_collision_never_mutate(self):
        repo_root = MODULE_PATH.parents[1]
        with tempfile.TemporaryDirectory() as temp_dir:
            copied_root = Path(temp_dir) / "lab"
            shutil.copytree(repo_root, copied_root)
            deploy_path = copied_root / "scripts" / "Deploy-Lab.ps1"
            state_path = copied_root / ".ccf-push-lab-state-ccf-push-lab.json"
            harness = textwrap.dedent(
                r"""
                $ErrorActionPreference = 'Stop'
                $global:mode = 'absent'
                $global:mutations = @()
                function global:az {
                    $request = $args -join ' '
                    if ($request -match 'account show') {
                        $global:LASTEXITCODE = 0
                        '{"id":"sub-1","tenantId":"tenant-1","name":"Test"}'
                        return
                    }
                    if ($request -match '^group show') {
                        if ($global:mode -eq 'foreign') {
                            $global:LASTEXITCODE = 0
                            '{"name":"ccf-push-lab-rg","tags":{"nlzt-owner":"foreign"}}'
                        } else {
                            $global:LASTEXITCODE = 3
                        }
                        return
                    }
                    if ($request -match 'group create|group delete|deployment group create|--method PUT|--method DELETE') {
                        $global:mutations += $request
                        throw "Mutation attempted: $request"
                    }
                    throw "Unexpected mocked az call: $request"
                }

                $preview = & $env:CCF_DEPLOY_SCRIPT -WhatIf 6>&1 | Out-String
                if ($preview -notmatch 'no Azure resources or local state were changed') {
                    throw "Preview summary missing: $preview"
                }
                if (Test-Path -LiteralPath $env:CCF_STATE_PATH) {
                    throw 'WhatIf created an ownership state file'
                }
                if ($global:mutations.Count -ne 0) {
                    throw 'WhatIf attempted an Azure mutation'
                }

                $global:mode = 'foreign'
                $collision = ''
                try {
                    $null = & $env:CCF_DEPLOY_SCRIPT 6>&1
                } catch {
                    $collision = $_.Exception.Message
                }
                if ($collision -notmatch 'Refusing to adopt, overwrite, or delete it') {
                    throw "Foreign resource group was not rejected: $collision"
                }
                if ($global:mutations.Count -ne 0) {
                    throw 'Foreign resource group collision caused a mutation'
                }
                'OK'
                """
            )
            env = os.environ.copy()
            env["CCF_DEPLOY_SCRIPT"] = str(deploy_path)
            env["CCF_STATE_PATH"] = str(state_path)
            result = subprocess.run(
                ["pwsh", "-NoLogo", "-NoProfile", "-Command", harness],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
