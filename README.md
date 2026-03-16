# Sentinel CCF Push Connector Lab

Build a custom Microsoft Sentinel connector using the Codeless Connector Framework (CCF) Push mode. Ingests real botnet C2 threat intelligence from [abuse.ch Feodotracker](https://feodotracker.abuse.ch/).

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
pip install requests
python3 ./scripts/Send-ThreatIntel.py

# Validate
./scripts/Test-CCFPush.ps1 -ResourceGroup "ccf-push-lab-rg" -WorkspaceName "ccf-push-lab-law"
```

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

## Blog Post

[Building Custom Sentinel Connectors in One Click with CCF Push](https://nineliveszerotrust.com/blog/sentinel-ccf-push-connector/)

## License

MIT
