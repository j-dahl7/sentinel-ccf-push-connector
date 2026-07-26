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
import ipaddress
import os
import re
import sys
import time
from datetime import datetime
from urllib.parse import urlsplit

import requests

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
BATCH_SIZE = 100
MAX_RETRIES = 3
RETRY_DELAY = 5
AZURE_INGEST_HOST_SUFFIX = ".ingest.monitor.azure.com"
DCR_ID_PATTERN = re.compile(r"dcr-[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
STREAM_NAME_PATTERN = re.compile(r"Custom-[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def get_env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None or not value.strip():
        print(f"Error: environment variable {name} is required", file=sys.stderr)
        sys.exit(1)
    return value.strip()


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
    resp = requests.get(
        FEODO_URL,
        headers={"User-Agent": "nine-lives-zero-trust-ccf-lab/1.0"},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    indicators = data if isinstance(data, list) else data.get("data", []) if isinstance(data, dict) else None
    if not isinstance(indicators, list):
        raise ValueError("Feodotracker response did not contain an indicator list")
    print(f"  Fetched {len(indicators)} indicators")
    return indicators


def transform(indicators: list[dict]) -> list[dict]:
    """Transform Feodotracker JSON to table schema."""
    records = []
    skipped = 0
    for ind in indicators:
        if not isinstance(ind, dict):
            skipped += 1
            continue

        try:
            address = str(ipaddress.ip_address(str(ind.get("ip_address", "")).strip()))
            port = int(ind.get("port", 0))
            if not 1 <= port <= 65535:
                raise ValueError("port outside valid range")
        except (TypeError, ValueError):
            skipped += 1
            continue

        def normalize_datetime(value):
            if not value:
                return None
            text = str(value).strip()
            try:
                datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                return None
            return text

        records.append({
            "ip_address": address,
            "port": port,
            "status": str(ind.get("status", "") or ""),
            "malware": str(ind.get("malware", "") or ""),
            "first_seen": normalize_datetime(ind.get("first_seen")),
            "last_seen": normalize_datetime(ind.get("last_online")),
            "country": str(ind.get("country", "") or ""),
        })
    if skipped:
        print(f"  Skipped {skipped} malformed indicator(s)")
    return records


def build_ingestion_url(dce_uri: str, dcr_id: str, stream_name: str) -> str:
    """Build a public-Azure ingestion URL without exposing a token to arbitrary hosts."""
    parsed = urlsplit(dce_uri.strip())
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("CCF_DCE_URI contains an invalid port") from exc

    hostname = (parsed.hostname or "").lower()
    if (
        parsed.scheme.lower() != "https"
        or not hostname.endswith(AZURE_INGEST_HOST_SUFFIX)
        or hostname == AZURE_INGEST_HOST_SUFFIX.lstrip(".")
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "CCF_DCE_URI must be an HTTPS base URL on *.ingest.monitor.azure.com"
        )
    if not DCR_ID_PATTERN.fullmatch(dcr_id):
        raise ValueError("CCF_DCR_ID must be a valid dcr-* immutable ID")
    if not STREAM_NAME_PATTERN.fullmatch(stream_name):
        raise ValueError("CCF_STREAM_NAME must be a valid Custom-* stream name")

    authority = hostname if port is None else f"{hostname}:{port}"
    return (
        f"https://{authority}/dataCollectionRules/{dcr_id}"
        f"/streams/{stream_name}?api-version=2023-01-01"
    )


def send_batch(
    records: list[dict],
    dce_uri: str,
    dcr_id: str,
    stream_name: str,
    token: str,
) -> int:
    """Send a batch of records to the DCE ingestion endpoint."""
    url = build_ingestion_url(dce_uri, dcr_id, stream_name)
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
                allow_redirects=False,
            )
            if resp.status_code == 429:
                retry_value = resp.headers.get("Retry-After", str(RETRY_DELAY))
                retry_after = int(retry_value) if retry_value.isdigit() else RETRY_DELAY
                if attempt == MAX_RETRIES:
                    resp.raise_for_status()
                print(f"  Rate limited, retrying in {retry_after}s (attempt {attempt}/{MAX_RETRIES})")
                time.sleep(retry_after)
                continue
            if not 200 <= resp.status_code < 300:
                if 300 <= resp.status_code < 400:
                    raise requests.exceptions.HTTPError(
                        f"Refusing ingestion redirect (HTTP {resp.status_code})",
                        response=resp,
                    )
                resp.raise_for_status()
            return resp.status_code
        except requests.exceptions.RequestException as e:
            if attempt < MAX_RETRIES:
                print(f"  Error: {e}, retrying in {RETRY_DELAY}s (attempt {attempt}/{MAX_RETRIES})")
                time.sleep(RETRY_DELAY)
            else:
                raise
    raise RuntimeError("Batch ingestion exhausted all retry attempts")


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
    if not records:
        raise RuntimeError("No valid Feodotracker indicators were available to ingest")

    # Send in batches. total_batches is computed up front so an empty feed still
    # reports cleanly instead of failing on an unbound name after all the work.
    total_sent = 0
    total_batches = (len(records) + BATCH_SIZE - 1) // BATCH_SIZE
    for i in range(0, len(records), BATCH_SIZE):
        batch = records[i : i + BATCH_SIZE]
        batch_num = (i // BATCH_SIZE) + 1
        print(f"Sending batch {batch_num}/{total_batches} ({len(batch)} records)...")
        status = send_batch(batch, dce_uri, dcr_id, stream_name, token)
        total_sent += len(batch)
        print(f"  Status: {status}")

    print(f"\nDone. Sent {total_sent} records in {total_batches} batches.")
    print("Data will appear in FeodoTracker_CL within 5-10 minutes.")


if __name__ == "__main__":
    main()
