# Sentinel CCF Push Connector Lab

## September 25, 2026 source repair

The four `connector/*.json` files are **bare CCF resources**, not independently deployable ARM wrappers. The Push resource carries escaped runtime expressions for the DCE/DCR and Entra identities. The reviewed Microsoft packager is pinned in `packaging/tooling.lock.json`.

Use PowerShell 7.6 and Python 3.12 or later. Python direct inputs are in `scripts/requirements.in`; the conventional hash-locked `scripts/requirements.txt` is the installed transitive dependency set. Regenerate it with pip-compile and review changes together.

### Build the package without Azure

Use an isolated tooling checkout. The helper refuses a different commit, modified tools, or an existing output directory:

```powershell
git clone --filter=blob:none --sparse https://github.com/Azure/Azure-Sentinel.git ../azure-sentinel-tooling
git -C ../azure-sentinel-tooling sparse-checkout set Tools/Create-Azure-Sentinel-Solution Solutions/Templates
git -C ../azure-sentinel-tooling checkout f6cc4352c34b84d781735967808cfc953376e7f2
./scripts/Build-CCFPackage.ps1 -AzureSentinelRoot ../azure-sentinel-tooling
```

The output is under the tooling checkout's `Solutions/NineLivesFeodoTrackerLab/Package`. The helper uses the provider's offline/local version mode, includes Metadata after Data Connectors to preserve its resource-array contract, and checks the generated JSON for the required nested resources. Microsoft's tooling may download its checksum-pinned ARM-TTK archive. It currently emits ARM-TTK errors for old API versions in provider-generated templates; Microsoft's CCF guide documents that this validation stage can fail. **JSON generation and structural checks are not a successful ARM-TTK certification or an Azure deployment.** Review the entire generated package and the current [CCF Push guide](https://learn.microsoft.com/en-us/azure/sentinel/isv/create-push-codeless-connector) before deployment. Do not ignore unrelated generation failures.

### Deploy and enable in separate phases

1. Deploy the owner-bound sandbox with rules disabled (the default).
2. Build, inspect and deploy the generated package to that exact sandbox. Current CCF provisioning requires the Azure-portal Sentinel experience; use the current provider guide before the March 2027 portal transition.
3. Activate the connector, retain exact tenant-object IDs and protect the one-time client secret. `-Destroy` removes only the exact owner-tagged resource group; it does not delete tenant applications or repository secrets.
4. Install the read-only query prerequisite explicitly: `az extension add --name log-analytics`. Run `Test-CCFPush.ps1` and validate the intended queries/data source.
5. Only then rerun `Deploy-Lab.ps1 -EnableSentinelRules`. Missing `FeodoTracker_CL` now blocks this path before any Azure mutation.

The workspace disables local/shared-key authentication and uses modern Sentinel onboarding. Cleanup does not depend on local packaging validity. Native CLI stderr remains visible for failed reads/writes. Workbook title checks hydrate each exact inventoried resource instead of assuming generic inventory includes display names.

### Detection and source freshness

Feodo currently reports empty datasets and may retain old indicator rows. A legitimate empty list exits successfully **without authentication or ingestion**; a nonempty feed with no valid rows still fails. No fixed arrival latency is promised. Verify `last_seen` and the upstream source before treating a match as current threat evidence.

Rule 5 correlates `CommonSecurityLog` only and restricts fresh source ingestion to its one-hour schedule before the join. The seven-day indicator lookback remains. The default query and workbook no longer assume retired `DnsEvents` collection; map modern DNS/ASIM data into the documented canonical columns and test it separately. Statistical/baseline rules intentionally retain their full windows; they can repeat observations. An IP match is a triage lead, not proof of compromise.

Scheduled ingestion runs at minute 17 every six hours and a dispatch can ingest only from the repository's default branch with its explicit boolean enabled. GitHub scheduling is best-effort. Repository writers remain a credential trust boundary; use protected environments and reviewed federation where appropriate before production use. No account settings, secrets, live feeds, or cloud resources were changed by this source repair.


Build a custom Microsoft Sentinel connector using the Codeless Connector Framework (CCF) Push mode. Ingests real botnet C2 threat intelligence from [abuse.ch Feodotracker](https://feodotracker.abuse.ch/).

## Validation Boundary

The July 25 hardened baseline passed offline Python/PowerShell checks, JSON
parsing, Bicep compilation, workflow/dependency review, and credential-pattern
scanning. After the August 13, 2026 lookback and cloud-scope corrections, all 19
Python contract tests passed again. The current revision was not deployed to a
live CCF preview environment and no indicator was ingested into Sentinel.
Portal-generated resources, schemas, permissions, supported regions, and
ingestion behavior must be confirmed in the target tenant.
`Deploy-Lab.ps1` deliberately does not pretend that deploying a raw connector
definition is equivalent to a packaged Microsoft Sentinel solution. It validates
the four local CCF artifacts and deploys the owned sandbox, rules, and workbook;
the connector must then be packaged with Microsoft's current tooling.

For the current offline suite, run `python -m unittest discover -s tests -v`.
It reports the actual run/pass/skip totals for your environment: sender tests
mock HTTP traffic, and the deployment/API-contract cases use PowerShell Azure
mocks. Those PowerShell cases are skipped if `pwsh` is unavailable. The dated
test totals above are historical observations, not a claim about today's suite
size or a substitute for the current run output.
The separate `validate.yml` pull-request workflow compiles Bicep and runs the
offline suite without cloud credentials or an ingestion step. It does not
enable or change the independently controlled ingestion workflow.

## Prerequisites and Permissions

- Azure CLI authenticated to the intended subscription and tenant
- PowerShell 7.6+ (stable native-command failure propagation), Python 3.12+, and `pip`
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

The fixed Feodotracker download is streamed with a **4 MiB body cap** and a
**20,000-indicator cap**. Redirects and compressed responses are refused (the
request asks for identity encoding). Connect and individual reads time out at
10 seconds; after headers arrive the body has a 60-second budget, checked around
non-filling reads so keepalive trickles cannot indefinitely fill a large chunk.
A read already in progress can last up to its 10-second timeout.

Consumed fields have UTF-8 byte limits: IP/date fields 64, port 5, status 32,
malware 128 and country 8. An overflow or unsupported nested field aborts the
whole feed before token acquisition or ingestion; the valid-looking prefix is
not sent. Ordinary malformed IP/port rows retain their documented skip behavior.
Batches are also limited to 100 records and 512 KiB. These are conservative lab
limits; investigate a rejected feed/schema change before deliberately changing
them. Tests use synthetic responses and a loopback trickle server, without live
Sentinel ingestion. Partial delivery on an unrelated later ingestion failure
still requires review; this is not transactional ingestion.

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

# Follow Microsoft's current CCF Push guide to place the four connector/*.json
# files into an Azure-Sentinel solution, build it with the official tooling,
# deploy the generated package to this workspace, and click its portal button.
# Then configure the one-time credentials without committing them:
$env:CCF_TENANT_ID = "<tenant-id>"
$env:CCF_CLIENT_ID = "<client-id>"
$env:CCF_CLIENT_SECRET = Read-Host "CCF client secret" -MaskInput
$env:CCF_DCE_URI = "<dce-uri>"
$env:CCF_DCR_ID = "<dcr-immutable-id>"

# Push threat intelligence
python3 -m pip install --require-hashes -r ./scripts/requirements.txt
python3 ./scripts/Send-ThreatIntel.py

# Validate
az extension add --name log-analytics
./scripts/Test-CCFPush.ps1 -ProjectName "ccf-push-lab"

# Only after the connector/table and intended queries have been validated:
./scripts/Deploy-Lab.ps1 -Location "eastus" -ProjectName "ccf-push-lab" -EnableSentinelRules
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

The first rule compares the latest hour with every malware label observed in
the preceding **14-day** workspace lookback, matching the query period deployed
by `Deploy-Lab.ps1`. It retains all prior labels even when one IP changes labels
over time; `tests/fixtures/new-malware-family-baseline.kql` captures the
`A -> B -> A` regression and should return zero rows.

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
