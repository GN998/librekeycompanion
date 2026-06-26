#!/usr/bin/env python3
"""
Generate the bundled MDS JSON (res/raw/mds_bundled.json) for Libre Key Companion.

Downloads the FIDO Alliance MDS3 BLOB (a JWT), decodes its payload, and writes a
compact {aaguid: {name, certification, icon}} map that the app reads offline.

Usage:
    python generate_mds_bundle.py                # all authenticators, with icons
    python generate_mds_bundle.py --no-icons     # names + certification only (small)
    python generate_mds_bundle.py --filter yubi token2 cryptnox   # only matching names
    python generate_mds_bundle.py --out app/src/main/res/raw/mds_bundled.json

Notes:
  * The BLOB is public and needs no token.
  * This script does NOT verify the JWT signature — it only reads the payload for
    display data. That's fine for names/icons; do not use it for attestation trust.
  * Icons roughly double the file size per entry. The full set with icons is a few
    hundred KB to ~1-2 MB depending on how many entries you keep.
"""
import argparse
import base64
import json
import sys
import urllib.request

MDS_URL = "https://mds3.fidoalliance.org/"


def b64url_decode(segment: str) -> bytes:
    # JWT uses base64url without padding; restore padding before decoding.
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def fetch_blob(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "lkc-mds-bundler"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8")


def decode_jwt_payload(jwt: str) -> dict:
    parts = jwt.strip().split(".")
    if len(parts) < 2:
        raise ValueError("Not a JWT (expected header.payload.signature)")
    return json.loads(b64url_decode(parts[1]))


def best_certification(entry: dict):
    """Pick the most recent FIDO_CERTIFIED* status from statusReports, if any."""
    cert = None
    for report in entry.get("statusReports", []):
        status = report.get("status", "")
        if status.startswith("FIDO_CERTIFIED"):
            cert = status  # later reports override earlier ones
    return cert


def build(blob: dict, keep_icons: bool, name_filters):
    """Emit a flat array of {aaguid, description, icon, status} objects."""
    out = []
    for entry in blob.get("entries", []):
        ms = entry.get("metadataStatement") or {}
        aaguid = entry.get("aaguid") or ms.get("aaguid")
        if not aaguid:
            continue  # skip U2F-only / AAID entries (no AAGUID)
        name = ms.get("description", "Unknown authenticator")
        if name_filters and not any(f.lower() in name.lower() for f in name_filters):
            continue
        rec = {"aaguid": aaguid, "description": name}
        icon = ms.get("icon")
        if keep_icons and icon:
            rec["icon"] = icon  # already a data:image/...;base64,... URI
        cert = best_certification(entry)
        if cert:
            rec["status"] = cert
        out.append(rec)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="mds_bundled.json")
    ap.add_argument("--no-icons", action="store_true", help="omit icon data URIs")
    ap.add_argument("--filter", nargs="*", default=None,
                    help="only keep authenticators whose name contains any of these")
    ap.add_argument("--from-file", default=None,
                    help="read a previously-downloaded BLOB (JWT) from a file instead of the network")
    args = ap.parse_args()

    print("Fetching MDS BLOB…", file=sys.stderr)
    jwt = open(args.from_file).read() if args.from_file else fetch_blob(MDS_URL)
    blob = decode_jwt_payload(jwt)
    print(f"  BLOB no={blob.get('no')} nextUpdate={blob.get('nextUpdate')} "
          f"entries={len(blob.get('entries', []))}", file=sys.stderr)

    entries = build(blob, keep_icons=not args.no_icons, name_filters=args.filter)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(entries, f, ensure_ascii=False, separators=(",", ":"))
    import os
    kb = os.path.getsize(args.out) / 1024
    print(f"Wrote {len(entries)} authenticators to {args.out} ({kb:.0f} KB)",
          file=sys.stderr)


if __name__ == "__main__":
    main()
