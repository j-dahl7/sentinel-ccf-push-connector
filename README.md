# Sentinel CCF Push Connector Lab

Build a custom Microsoft Sentinel connector using the Codeless Connector Framework (CCF) Push mode. Ingests real botnet C2 threat intelligence from [abuse.ch Feodotracker](https://feodotracker.abuse.ch/).

## Validation Boundary

The hardened July 25, 2026 revision passed offline Python unit/compilation
checks, PowerShell parser checks, JSON parsing, Bicep compilation, workflow and
dependency review, and credential-pattern scanning. It was not deployed to a
live CCF preview environment and no indicator was ingested into Sentinel for
this revision. Portal-generated resources, schemas, permissions, supported
regions, and ingestion behavior must be confirmed in the target tenant.
`Deploy-Lab.ps1` deliberately does not pretend that deploying a raw connector
definition is equivalent to a packaged Microsoft Sentinel solution. It validates
the four local CCF artifacts and deploys the owned sandbox, rules, and workbook;
the connector must then be packaged with Microsoft's current tooling.

## Prerequisites and Permissions

- Azure CLI authenticated to the intended subscription and tenant
- PowerShell 7.3+, Python 3.10+, and `pip`
- Access to the official Azure-Sentinel repository and its current
  `Create-Azure-Sentinel-Solution` packaging tooling
- Permission to create the resource group plus Contributor and Microsoft
  Sentinel Contributor on the target scope
- Entra permission to create an application and client secret (typically
  Application Developer or higher)
- Owner or User Access Administrator on the target scope, or equivalent exact
  permission to assign Monitoring Metrics Publisher on the generated DCR

The provided sender is intentionally scoped to **Azure public cloud**. Its token
audience, Microsoft identity endpoint, and allowed DCE hostname suffix are not
parameterized for Azure Government, Azure operated by 21Vianet, or other cloud
environments. Adapt and revalidate those endpoints before using it elsewhere.

Use a disposable lab subscription. Log Analytics ingestion/retention and
Sentinel usage can incur charges; the Feodotracker feed itself is free. CCF
Push is a preview surface, so validate current platform behavior before any
production use.

## What's Included

| Component | Description |
|-----------|-------------|
| **Bicep templates** | Log Analytics workspace + Sentinel onboarding |
| **CCF Push artifacts** | Table, DCR, connector definition, and push-connector configuration for official solution packaging |
| **Python sender** | Fetches abuse.ch → transforms → POSTs to DCE via OAuth |
| **Analytics rules** | 5 KQL detection rules (4 feed analysis + 1 network TI correlation) |
| **Hunting queries** | 5 proactive threat hunting queries |
| **GitHub Actions** | Scheduled ingestion workflow (every 6 hours) |
| **Workbook** | Threat Intelligence Dashboard (5 panels) |

## Quick Start

```powershell
# Preview the Azure resource-group deployment. This still performs read-only
# local/account checks but does not write Azure resources.
./scripts/Deploy-Lab.ps1 -Location "eastus" -ProjectName "ccf-push-lab" -WhatIf

# Live owned sandbox deployment. This does not package or install the connector.
# The five analytics rules are created disabled for review.
./scripts/Deploy-Lab.ps1 -Location "eastus" -ProjectName "ccf-push-lab"

# Explicitly opt in only after review if you want the rules enabled.
./scripts/Deploy-Lab.ps1 -Location "eastus" -ProjectName "ccf-push-lab" -EnableSentinelRules

# Follow Microsoft's current CCF Push guide to place the four connector/*.json
# files into an Azure-Sentinel solution, build it with the official tooling,
# deploy the generated package to this workspace, and click its portal button.
# Then configure the one-time credentials without committing them:
$env:CCF_TENANT_ID = "<tenant-id>"
$env:CCF_CLIENT_ID = "<client-id>"
$env:CCF_CLIENT_SECRET = "<client-secret>"
$env:CCF_DCE_URI = "<dce-uri>"
$env:CCF_DCR_ID = "<dcr-immutable-id>"

# Push threat intelligence
python3 -m pip install --require-hashes -r ./scripts/requirements.lock
python3 ./scripts/Send-ThreatIntel.py

# Validate
./scripts/Test-CCFPush.ps1 -ProjectName "ccf-push-lab"
```

The `-WhatIf` switch performs read-only account and collision checks but does
not create Azure resources, temporary request bodies, or the local ownership
manifest. It does not preview the portal button, tenant-level Entra
application/service-principal creation, role assignment, sender network calls,
data ingestion, GitHub secret creation, or scheduled runs. The test script
exits nonzero when an end-to-end check fails; passing local unit tests is not a
substitute for live validation.

## Connector Packaging Boundary

The `connector/` directory contains the four mutually validated CCF Push
artifacts. A raw resource-group deployment of `connectorDefinition.json` lacks
the packaged table, DCR, and push-connector context required by the portal
workflow, so `Deploy-Lab.ps1` does not perform that misleading partial install.
Use Microsoft's current [CCF Push connector guide](https://learn.microsoft.com/azure/sentinel/isv/create-push-codeless-connector),
copy these artifacts into the prescribed Azure-Sentinel solution structure,
run the official packaging checks, inspect the generated template, and deploy
that package to the exact owned workspace. Do not run packaging code from an
unreviewed fork or assume a locally valid JSON file proves live preview support.

Deployment parameters are `-Location`, `-ProjectName`, `-SkipSentinel`,
`-EnableSentinelRules`, `-Destroy`, and PowerShell's common `-WhatIf` switch.
The script stores an ignored `.ccf-push-lab-state-<project>.json` ownership
manifest before its first Azure write. Keep that file private and intact: rerun,
validation, and cleanup refuse ambiguous or foreign resources without it.

## Scheduled Ingestion Safety

The workflow validates pull requests and default manual runs without ingesting.
Scheduled runs execute every six hours; a manual run pushes only when
`perform_ingest` is explicitly enabled. Tests run before the sender, repository
permissions are read-only, and terminal authentication, validation, ingestion,
or rate-limit failure exits the job nonzero. Store all five `CCF_*` values as
GitHub Actions secrets, restrict repository administration, rotate the client
secret, and never commit connector credentials. Prefer workload-identity
federation when the CCF flow in your tenant supports it.

## Analytics Rules

All five rules are deployed **disabled by default**. Inspect the KQL, confirm
the custom table schema and source tables in your workspace, and tune the
thresholds before using `-EnableSentinelRules`. These are lab examples, not
production-ready detections or proof that a host is compromised.

| Rule | Example severity | Evidence boundary |
|------|----------|-------|
| New Feed Malware Label Observed | High | No ATT&CK technique asserted from feed metadata alone |
| Feed Indicator Count Increase | Medium | No ATT&CK technique asserted from feed-volume change alone |
| Recent Feed Indicators on 443 or 8443 | High | Port alone does not establish T1071 or T1573 |
| Feed Country Concentration | Medium | Geography alone does not establish T1583 |
| Network Traffic Match to Feed Indicator | High | IP matching alone does not establish T1071 or T1102 |

The first rule compares the latest hour with the preceding **14-day** workspace
lookback, matching the query period deployed by `Deploy-Lab.ps1`.

## Cleanup

```powershell
./scripts/Deploy-Lab.ps1 -ProjectName "ccf-push-lab" -Destroy -WhatIf
./scripts/Deploy-Lab.ps1 -ProjectName "ccf-push-lab" -Destroy
```

`-Destroy -WhatIf` makes read-only checks and deletes nothing. The live command
requires the local manifest plus an exact subscription, tenant, group name, and
`nlzt-owner` tag match. It refuses resource-group adoption, waits for Azure to
finish deletion, verifies absence, and only then removes the manifest. It does
not remove the tenant-level Entra application and service principal created by
the portal button. After proving no other connector uses them, remove those
exact tenant objects separately and delete the five GitHub Actions secrets.
Rotating or removing a secret does not erase it from prior logs or repository
history.

## Troubleshooting

- **No rows:** run the sender, allow for ingestion delay, then query
  `FeodoTracker_CL | take 10`.
- **401/403 response:** confirm tenant/client IDs, secret validity, DCR
  immutable ID, DCE URI, and Monitoring Metrics Publisher assignment.
- **Sender reports no valid indicators:** verify the abuse.ch JSON schema and
  network access; malformed IP/port records are deliberately skipped.
- **Connector absent:** confirm the complete generated solution package—not the
  raw definition alone—was deployed, then check CCF Push availability in the
  selected Sentinel experience and region.

## Blog Post

[Building Custom Sentinel Connectors with CCF Push](https://nineliveszerotrust.com/blog/sentinel-ccf-push-connector/)

## License

MIT
