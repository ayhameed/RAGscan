"""
Seed the dev/staging environment with DefectDojo sample Nessus scan data.

Usage:
    python scripts/load_demo_data.py --url http://localhost:8000 --email admin@ragscan.dev --password changeme

This script:
1. Registers a demo admin user (or logs in if already exists)
2. Downloads the DefectDojo sample Nessus file
3. POSTs it to /ingest
4. Prints a summary of ingested findings
"""
import argparse
import sys
import httpx

NESSUS_SAMPLE_URL = (
    "https://raw.githubusercontent.com/DefectDojo/sample-scan-files"
    "/master/nessus/nessus_v_unknown.nessus"
)


def get_token(base_url: str, email: str, password: str) -> str:
    # Try register first, fall back to login
    resp = httpx.post(
        f"{base_url}/auth/register",
        json={"email": email, "password": password, "role": "admin"},
        timeout=15,
    )
    if resp.status_code in (200, 201):
        return resp.json()["access_token"]
    if resp.status_code == 409:
        resp = httpx.post(
            f"{base_url}/auth/login",
            json={"email": email, "password": password},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]
    resp.raise_for_status()


def download_sample(url: str) -> bytes:
    print(f"Downloading sample scan from {url} ...")
    resp = httpx.get(url, follow_redirects=True, timeout=60)
    resp.raise_for_status()
    print(f"Downloaded {len(resp.content):,} bytes")
    return resp.content


def ingest(base_url: str, token: str, data: bytes, filename: str) -> dict:
    print("Ingesting scan file ...")
    resp = httpx.post(
        f"{base_url}/ingest",
        files={"file": (filename, data, "application/xml")},
        headers={"Authorization": f"Bearer {token}"},
        timeout=300,
    )
    resp.raise_for_status()
    return resp.json()


def get_scores(base_url: str, token: str) -> dict:
    resp = httpx.get(
        f"{base_url}/score",
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def main():
    parser = argparse.ArgumentParser(description="Load RAGScan demo data")
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--email", default="admin@ragscan.dev")
    parser.add_argument("--password", default="changeme123!")
    args = parser.parse_args()

    print(f"RAGScan Demo Data Loader -> {args.url}")

    token = get_token(args.url, args.email, args.password)
    print("Authenticated.")

    sample = download_sample(NESSUS_SAMPLE_URL)
    result = ingest(args.url, token, sample, "demo_scan.nessus")

    print(f"\nIngest complete:")
    print(f"  Ingested : {result['ingested']}")
    print(f"  Enriched : {result['enriched']}")
    print(f"  Skipped  : {result['skipped']}")

    scores = get_scores(args.url, token)
    print(f"\nRisk summary:")
    print(f"  Total    : {scores['total']}")
    print(f"  Critical : {scores['critical']}")
    print(f"  High     : {scores['high']}")
    print(f"  CISA KEV : {scores['kev_count']}")
    print(f"  Avg Risk : {scores['avg_risk_score']}/100")

    print("\nDemo data loaded. Visit http://localhost:8000/docs to explore the API.")


if __name__ == "__main__":
    main()
