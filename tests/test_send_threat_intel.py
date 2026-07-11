import importlib.util
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


if __name__ == "__main__":
    unittest.main()
