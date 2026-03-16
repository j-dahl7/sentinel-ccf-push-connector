#!/usr/bin/env python3
"""Fetch abuse.ch Feodotracker C2 indicators and push to Sentinel via CCF Push.

Environment variables:
    CCF_TENANT_ID      - Entra tenant ID
    CCF_CLIENT_ID      - App registration client ID (from CCF Push deploy)
    CCF_CLIENT_SECRET  - Client secret (from CCF Push deploy)
    CCF_DCE_URI        - Data Collection Endpoint URI
    CCF_DCR_ID         - Data Collection Rule immutable ID
    CCF_STREAM_NAME    - Stream name (default: Custom-FeodoTrackerStream)
"""

import json
import os
import sys
import time

import requests

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
BATCH_SIZE = 100
MAX_RETRIES = 3
RETRY_DELAY = 5


def get_env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None:
        print(f"Error: environment variable {name} is required", file=sys.stderr)
        sys.exit(1)
    return value


def get_oauth_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Acquire OAuth 2.0 token via client credentials flow."""
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    resp = requests.post(url, data={
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://monitor.azure.com//.default",
    }, timeout=30)
    resp.raise_for_status()
    return resp.json()["access_token"]


def fetch_indicators() -> list[dict]:
    """Fetch C2 indicators from abuse.ch Feodotracker."""
    print(f"Fetching indicators from {FEODO_URL}")
    resp = requests.get(FEODO_URL, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    indicators = data if isinstance(data, list) else data.get("data", [])
    print(f"  Fetched {len(indicators)} indicators")
    return indicators


def transform(indicators: list[dict]) -> list[dict]:
    """Transform Feodotracker JSON to table schema."""
    records = []
    for ind in indicators:
        records.append({
            "ip_address": ind.get("ip_address", ""),
            "port": ind.get("port", 0),
            "status": ind.get("status", ""),
            "malware": ind.get("malware", ""),
            "first_seen": ind.get("first_seen", ""),
            "last_seen": ind.get("last_online", ""),
            "country": ind.get("country", ""),
        })
    return records


def send_batch(
    records: list[dict],
    dce_uri: str,
    dcr_id: str,
    stream_name: str,
    token: str,
) -> int:
    """Send a batch of records to the DCE ingestion endpoint."""
    url = (
        f"{dce_uri}/dataCollectionRules/{dcr_id}"
        f"/streams/{stream_name}?api-version=2023-01-01"
    )
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.post(
                url,
                json=records,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                timeout=60,
            )
            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", RETRY_DELAY))
                print(f"  Rate limited, retrying in {retry_after}s (attempt {attempt}/{MAX_RETRIES})")
                time.sleep(retry_after)
                continue
            resp.raise_for_status()
            return resp.status_code
        except requests.exceptions.RequestException as e:
            if attempt < MAX_RETRIES:
                print(f"  Error: {e}, retrying in {RETRY_DELAY}s (attempt {attempt}/{MAX_RETRIES})")
                time.sleep(RETRY_DELAY)
            else:
                raise
    return 0


def main():
    tenant_id = get_env("CCF_TENANT_ID")
    client_id = get_env("CCF_CLIENT_ID")
    client_secret = get_env("CCF_CLIENT_SECRET")
    dce_uri = get_env("CCF_DCE_URI")
    dcr_id = get_env("CCF_DCR_ID")
    stream_name = get_env("CCF_STREAM_NAME", "Custom-FeodoTrackerStream")

    # Authenticate
    print("Authenticating via OAuth 2.0 client credentials...")
    token = get_oauth_token(tenant_id, client_id, client_secret)
    print("  Token acquired")

    # Fetch and transform
    indicators = fetch_indicators()
    records = transform(indicators)
    print(f"  Transformed {len(records)} records")

    # Send in batches
    total_sent = 0
    for i in range(0, len(records), BATCH_SIZE):
        batch = records[i : i + BATCH_SIZE]
        batch_num = (i // BATCH_SIZE) + 1
        total_batches = (len(records) + BATCH_SIZE - 1) // BATCH_SIZE
        print(f"Sending batch {batch_num}/{total_batches} ({len(batch)} records)...")
        status = send_batch(batch, dce_uri, dcr_id, stream_name, token)
        total_sent += len(batch)
        print(f"  Status: {status}")

    print(f"\nDone. Sent {total_sent} records in {total_batches} batches.")
    print("Data will appear in FeodoTracker_CL within 5-10 minutes.")


if __name__ == "__main__":
    main()
