# Sentinel CCF Push Connector Lab

Build a custom Microsoft Sentinel connector using the Codeless Connector Framework (CCF) Push mode. Ingests real botnet C2 threat intelligence from [abuse.ch Feodotracker](https://feodotracker.abuse.ch/).

## Verification status

- **Last reviewed:** 2026-07-10
- **Scope:** Python unit tests/compilation, PowerShell parser checks, JSON parsing, Bicep build, workflow/dependency review, secret scanning, and documentation/link comparison.
- **Status:** Locally verified; sender transformations and failure exits are covered by tests.
- **Limitation:** This review did not deploy CCF preview resources or ingest into a live Sentinel workspace. Portal-generated schemas and permissions must be confirmed in your tenant/region.

## Prerequisites and permissions

- Azure CLI authenticated to the intended subscription and tenant
- PowerShell 7.3+, Python 3.10+, and `pip`
- Contributor and Microsoft Sentinel Contributor on the target resource group
- Tenant permission to create the CCF-generated Entra application and assign Monitoring Metrics Publisher on the DCR

Use a disposable lab subscription. Log Analytics ingestion/retention and Sentinel usage can incur charges; the Feodotracker feed itself is free. CCF Push is a preview surface, so validate supported regions and current platform behavior before production use.

## What's Included

| Component | Description |
|-----------|-------------|
| **Bicep templates** | Log Analytics workspace + Sentinel onboarding |
| **CCF Push connector** | Table, DCR, and connector definition (data connector auto-provisioned via portal) |
| **Python sender** | Fetches abuse.ch → transforms → POSTs to DCE via OAuth |
| **Analytics rules** | 5 KQL detection rules (4 feed analysis + 1 network TI correlation) |
| **Hunting queries** | 5 proactive threat hunting queries |
| **GitHub Actions** | Scheduled ingestion workflow (every 6 hours) |
| **Workbook** | Threat Intelligence Dashboard (5 panels) |

## Quick Start

```powershell
# Deploy everything
./scripts/Deploy-Lab.ps1 -Location "eastus"

# After clicking "Deploy Push Connector Resources" in the Sentinel portal:
$env:CCF_TENANT_ID = "<tenant-id>"
$env:CCF_CLIENT_ID = "<client-id>"
$env:CCF_CLIENT_SECRET = "<client-secret>"
$env:CCF_DCE_URI = "<dce-uri>"
$env:CCF_DCR_ID = "<dcr-immutable-id>"

# Push threat intelligence
pip install -r ./scripts/requirements.txt
python3 ./scripts/Send-ThreatIntel.py

# Validate
./scripts/Test-CCFPush.ps1 -ResourceGroup "ccf-push-lab-rg" -WorkspaceName "ccf-push-lab-law"
```

The test script now exits nonzero when any end-to-end check fails, making it suitable for automation. A passing local unit test is not a substitute for this live validation.

## Scheduled ingestion safety

The workflow runs every six hours with read-only repository permissions and pinned action/dependency versions. Store the five `CCF_*` values as GitHub Actions secrets, restrict repository administration, rotate the client secret, and never commit connector credentials. Prefer workload identity federation if the CCF workflow in your tenant supports it.

## Analytics Rules

| Rule | Severity | MITRE |
|------|----------|-------|
| New Botnet Family Detected | High | T1071 |
| C2 Infrastructure Surge | Medium | T1583 |
| High-Confidence Active C2 | High | T1071, T1573 |
| Geographic C2 Concentration | Medium | T1583 |
| Network Traffic to Known Botnet C2 | High | T1071, T1102 |

## Cleanup

```powershell
./scripts/Deploy-Lab.ps1 -Destroy
```

Resource-group deletion does not necessarily remove the tenant-level Entra application/service principal created by the portal button. After confirming no other connector uses it, remove that app registration separately and delete the five GitHub Actions secrets. `-Destroy -WhatIf` previews resource-group deletion without applying it.

## Troubleshooting

- **No rows:** run the sender, wait 5–10 minutes, then query `FeodoTracker_CL | take 10`.
- **401/403 ingestion response:** confirm tenant/client IDs, secret validity, DCR immutable ID, DCE URI, and Monitoring Metrics Publisher assignment.
- **Sender reports no valid indicators:** verify the abuse.ch JSON schema and network access; malformed IP/port records are deliberately skipped.
- **Connector absent:** confirm the connector definition deployment succeeded and that CCF Push is available in the selected Sentinel experience/region.

## Blog Post

[Building Custom Sentinel Connectors in One Click with CCF Push](https://nineliveszerotrust.com/blog/sentinel-ccf-push-connector/)

## License

[MIT](LICENSE)
