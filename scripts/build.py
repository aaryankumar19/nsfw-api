#!/usr/bin/env python3
"""
==============================================================================
FILE: scripts/build.py
DESCRIPTION: Automated build pipeline for the static NSFW blocklist API.

WHAT THIS FILE DOES:
1. Parses 'data/domains.txt' (the editable source of truth).
2. Cleans, normalizes, and validates domain entries:
   - Strips protocols (http/https), port numbers, paths, queries, and fragments.
   - Lowers case and strips trailing dots.
   - Converts international domain names (IDN) to Punycode.
   - Validates RFC 1035 / RFC 1123 hostname syntax.
   - Deduplicates and alphabetically sorts domains.
3. Implements immutable releases:
   - Writes 'public/api/v1/releases/<version>.json' (never silently overwrites).
   - Generates 'public/api/v1/domains.json' as a convenience alias for the active release.
4. Computes the exact SHA-256 checksum over the raw release bytes.
5. Generates 'public/api/v1/version.json' with version metadata, checksum, and ISO timestamp.
6. Provides CLI controls for version bumping, explicit targeting, and instant rollbacks.

USAGE:
    python3 scripts/build.py                  # Build/rebuild current active version
    python3 scripts/build.py --bump           # Bump version by 1 and publish new release
    python3 scripts/build.py --version <N>    # Build specific version N
    python3 scripts/build.py --rollback <N>   # Point version.json back to older release N
    python3 scripts/build.py --dry-run        # Validate and print statistics without writing
==============================================================================
"""

import argparse
import datetime
import gzip
import hashlib
import json
import os
import re
import sys
import urllib.parse
from pathlib import Path

# RFC 1035 / RFC 1123 compliant domain regex
# Labels: 1-63 chars, alphanumeric with hyphens, not starting or ending with hyphen
# TLD: at least 2 alpha characters or valid Punycode
DOMAIN_REGEX = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9]+)$"
)

# IPv4 regex to reject plain IP addresses
IPV4_REGEX = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def normalize_domain(raw_line: str) -> tuple[str | None, str | None]:
    """
    Sanitizes, normalizes, and validates a raw input line into a clean domain.
    Returns: (cleaned_domain, error_reason)
    """
    line = raw_line.strip()

    # Ignore empty lines and comment lines
    if not line or line.startswith("#"):
        return None, None

    # Handle protocol prefixes (e.g. https://domain.com/path)
    if "://" in line:
        try:
            parsed = urllib.parse.urlparse(line)
            line = parsed.netloc or parsed.path
        except Exception:
            pass

    # Check for and preserve leading wildcard (e.g. *.domain.com)
    has_wildcard = False
    if line.startswith("*."):
        has_wildcard = True
        line = line[2:]

    # Strip port numbers (e.g. domain.com:8080)
    if ":" in line:
        line = line.split(":", 1)[0]

    # Strip trailing URL components (paths, query params, fragments)
    for sep in ["/", "?", "#"]:
        if sep in line:
            line = line.split(sep, 1)[0]

    # Lowercase and remove trailing dots/whitespace
    domain = line.strip().rstrip(".").lower()

    if not domain:
        return None, "Empty domain after sanitization"

    # Convert international domain names (IDN) to Punycode
    try:
        domain = domain.encode("idna").decode("ascii")
    except Exception as exc:
        return None, f"IDNA encoding failed: {exc}"

    # Overall length check (RFC max 253 characters)
    if len(domain) > 253:
        return None, f"Domain exceeds 253 characters ({len(domain)} chars)"

    # Reject plain IPv4 addresses
    if IPV4_REGEX.match(domain):
        return None, "Domain is an IPv4 address; only hostnames are allowed"

    # Reject IPv6 brackets
    if "[" in domain or "]" in domain:
        return None, "Domain appears to be an IPv6 address; only hostnames are allowed"

    # RFC format validation
    if not DOMAIN_REGEX.match(domain):
        return None, "Does not match standard hostname syntax"

    return f"*.{domain}" if has_wildcard else domain, None


def load_metadata(meta_path: Path) -> dict:
    """Reads or initializes version metadata tracking."""
    if meta_path.is_file():
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Warning: Failed to parse {meta_path}: {e}. Initializing defaults.")
    return {"schema_version": 1, "domains_version": 1}


def save_metadata(meta_path: Path, data: dict) -> None:
    """Persists updated metadata to disk."""
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def compute_sha256_bytes(data_bytes: bytes) -> str:
    """Calculates SHA-256 hexadecimal hash over exact file bytes."""
    return hashlib.sha256(data_bytes).hexdigest()


def process_domains_file(domains_path: Path) -> tuple[list[str], int, int, list[str]]:
    """
    Reads domains.txt (or domains.txt.gz), sanitizes, deduplicates, and validates.
    Returns: (sorted_domains, total_raw_lines, duplicates_count, warnings)
    """
    raw_domains_txt = domains_path.with_name("domains.txt")
    gz_path = domains_path.with_name("domains.txt.gz")

    if raw_domains_txt.is_file():
        # If uncompressed exists and is newer than .gz, keep .gz in sync
        if not gz_path.is_file() or raw_domains_txt.stat().st_mtime > gz_path.stat().st_mtime:
            print("[*] Updating data/domains.txt.gz (Cloudflare Pages 25MB compliance)...")
            with open(raw_domains_txt, "rb") as f_in, gzip.open(gz_path, "wb", compresslevel=9) as f_out:
                f_out.write(f_in.read())
        domains_source = raw_domains_txt
    elif gz_path.is_file():
        domains_source = gz_path
    else:
        raise FileNotFoundError(f"Source file not found at: {domains_path} or {gz_path}")

    raw_count = 0
    valid_domains: set[str] = set()
    duplicates_count = 0
    warnings: list[str] = []

    is_gz = domains_source.name.endswith(".gz")
    open_ctx = gzip.open(domains_source, "rt", encoding="utf-8") if is_gz else open(domains_source, "r", encoding="utf-8")

    with open_ctx as f:
        for line_num, line in enumerate(f, start=1):
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue

            raw_count += 1
            domain, err = normalize_domain(raw)

            if err:
                warnings.append(f"Line {line_num}: Skipped '{raw}' -> {err}")
                continue

            if domain in valid_domains:
                duplicates_count += 1
            else:
                valid_domains.add(domain)

    sorted_domains = sorted(valid_domains)
    return sorted_domains, raw_count, duplicates_count, warnings


def build_release_payload(schema_version: int, version: int, domains: list[str]) -> bytes:
    """Creates the deterministic JSON byte payload for a release."""
    payload = {
        "schema_version": schema_version,
        "version": version,
        "domains": domains,
    }
    # Deterministic compact formatting: avoids whitespace overhead and keeps payloads under Git's 100MB limit
    formatted = json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n"
    return formatted.encode("utf-8")


def build_version_payload(
    schema_version: int,
    domains_version: int,
    domains_url: str,
    sha256_hash: str,
    updated_at: str,
    uncompressed_sha256: str | None = None,
    total_domains: int | None = None,
    size_bytes: int | None = None,
) -> bytes:
    """Creates the JSON byte payload for version.json."""
    payload = {
        "schema_version": schema_version,
        "domains_version": domains_version,
        "domains_url": domains_url,
        "sha256": sha256_hash,
        "updated_at": updated_at,
    }
    if uncompressed_sha256:
        payload["uncompressed_sha256"] = uncompressed_sha256
    if total_domains is not None:
        payload["total_domains"] = total_domains
    if size_bytes is not None:
        payload["size_bytes"] = size_bytes
    formatted = json.dumps(payload, indent=2) + "\n"
    return formatted.encode("utf-8")


def perform_rollback(
    target_version: int,
    releases_dir: Path,
    public_api_dir: Path,
    meta_path: Path,
    dry_run: bool,
) -> None:
    """Rolls back version.json to point to an existing immutable release."""
    release_file = releases_dir / f"{target_version}.json.gz"
    is_gz = True
    if not release_file.is_file():
        release_file = releases_dir / f"{target_version}.json"
        is_gz = False

    if not release_file.is_file():
        print(f"[ERROR] Cannot rollback to version {target_version}: file not found at {releases_dir / f'{target_version}.json[.gz]'}")
        sys.exit(1)

    with open(release_file, "rb") as f:
        release_bytes = f.read()

    sha256_hash = compute_sha256_bytes(release_bytes)
    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    metadata = load_metadata(meta_path)
    schema_version = metadata.get("schema_version", 1)

    domains_url = f"/api/v1/releases/{target_version}.json.gz" if is_gz else f"/api/v1/releases/{target_version}.json"
    version_bytes = build_version_payload(
        schema_version=schema_version,
        domains_version=target_version,
        domains_url=domains_url,
        sha256_hash=sha256_hash,
        updated_at=now_utc,
        size_bytes=len(release_bytes),
    )

    print("=" * 60)
    print(f" NSFW Blocklist Rollback -> Version {target_version}")
    print("=" * 60)
    print(f"Target Release File: {release_file}")
    print(f"Release SHA-256:     {sha256_hash}")
    print(f"Timestamp:           {now_utc}")

    if dry_run:
        print("\n[DRY-RUN] No files were modified.")
        return

    # 1. Update version.json
    version_json_path = public_api_dir / "version.json"
    with open(version_json_path, "wb") as f:
        f.write(version_bytes)
    print(f"[✓] Updated: {version_json_path}")

    # 2. Update domains.json convenience copy
    domains_copy_filename = "domains.json.gz" if is_gz else "domains.json"
    domains_json_path = public_api_dir / domains_copy_filename
    with open(domains_json_path, "wb") as f:
        f.write(release_bytes)
    print(f"[✓] Updated convenience copy: {domains_json_path}")

    # 3. Update metadata
    metadata["domains_version"] = target_version
    save_metadata(meta_path, metadata)
    print(f"[✓] Updated metadata tracker: {meta_path}")

    print("=" * 60)
    print(f" Successfully rolled back to release {target_version}!")
    print(" Note: The newer release files remain intact in releases/ (immutable).")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Build and publish static NSFW blocklist JSON releases for Cloudflare Pages."
    )
    parser.add_argument(
        "--bump",
        action="store_true",
        help="Increment domains_version by 1 and generate a new immutable release.",
    )
    parser.add_argument(
        "--version",
        type=int,
        metavar="N",
        help="Specify an explicit version number for the release.",
    )
    parser.add_argument(
        "--rollback",
        type=int,
        metavar="N",
        help="Point version.json back to release N without modifying old releases.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Allow overwriting an existing release file if content differs.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate domains and calculate checksums without writing files.",
    )

    args = parser.parse_args()

    # Paths resolution
    base_dir = Path(__file__).resolve().parent.parent
    data_dir = base_dir / "data"
    domains_path = data_dir / "domains.txt"
    meta_path = data_dir / "metadata.json"

    public_api_dir = base_dir / "public" / "api" / "v1"
    releases_dir = public_api_dir / "releases"

    # Handle Rollback command
    if args.rollback is not None:
        perform_rollback(
            target_version=args.rollback,
            releases_dir=releases_dir,
            public_api_dir=public_api_dir,
            meta_path=meta_path,
            dry_run=args.dry_run,
        )
        return

    # Load version tracking metadata
    metadata = load_metadata(meta_path)
    schema_version = metadata.get("schema_version", 1)
    current_version = metadata.get("domains_version", 1)

    # Determine target version
    if args.version is not None:
        target_version = args.version
    elif args.bump:
        target_version = current_version + 1
    else:
        target_version = current_version

    print("=" * 60)
    print(f" NSFW Blocklist Builder (Target Version: {target_version})")
    print("=" * 60)

    # Process and validate domains.txt
    domains, raw_count, dup_count, warnings = process_domains_file(domains_path)

    print(f"[*] Read source file: {domains_path}")
    print(f"[*] Parsed entries:   {raw_count} domain lines")
    print(f"[*] Valid domains:    {len(domains)} unique hostnames")
    if dup_count > 0:
        print(f"[*] Deduplicated:     {dup_count} duplicate entries removed")

    if warnings:
        print(f"\n[!] Warnings encountered ({len(warnings)}):")
        for w in warnings[:10]:
            print(f"    - {w}")
        if len(warnings) > 10:
            print(f"    ... and {len(warnings) - 10} more warnings.")

    # Generate release JSON bytes
    release_bytes = build_release_payload(schema_version, target_version, domains)
    uncompressed_sha256 = compute_sha256_bytes(release_bytes)
    uncompressed_len = len(release_bytes)

    # Cloudflare Pages 25 MiB single-file limit compliance
    # If the uncompressed JSON exceeds 20 MiB, store and serve pre-compressed .json.gz release
    use_gzip_release = uncompressed_len > 20 * 1024 * 1024

    if use_gzip_release:
        release_payload = gzip.compress(release_bytes, compresslevel=6)
        release_sha256 = compute_sha256_bytes(release_payload)
        domains_url = f"/api/v1/releases/{target_version}.json.gz"
        release_filename = f"{target_version}.json.gz"
        domains_copy_filename = "domains.json.gz"
    else:
        release_payload = release_bytes
        release_sha256 = uncompressed_sha256
        domains_url = f"/api/v1/releases/{target_version}.json"
        release_filename = f"{target_version}.json"
        domains_copy_filename = "domains.json"

    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Generate version metadata JSON bytes
    version_bytes = build_version_payload(
        schema_version=schema_version,
        domains_version=target_version,
        domains_url=domains_url,
        sha256_hash=release_sha256,
        updated_at=now_utc,
        uncompressed_sha256=uncompressed_sha256 if use_gzip_release else None,
        total_domains=len(domains),
        size_bytes=len(release_payload),
    )

    print("\n[*] Release Checksum:")
    print(f"    SHA-256: {release_sha256}")
    print(f"    URL:     {domains_url}")
    print(f"    Payload: {len(release_payload)} bytes ({'compressed .gz' if use_gzip_release else 'uncompressed'})")
    if use_gzip_release:
        print(f"    Uncompressed: {uncompressed_len} bytes (SHA-256: {uncompressed_sha256})")

    if args.dry_run:
        print("\n[DRY-RUN] Execution completed. No files were written to disk.")
        return

    # Ensure output directories exist
    releases_dir.mkdir(parents=True, exist_ok=True)

    # Check for release immutability
    target_release_path = releases_dir / release_filename
    if target_release_path.is_file():
        with open(target_release_path, "rb") as f:
            existing_bytes = f.read()
        if existing_bytes == release_payload:
            print(f"[*] Note: {target_release_path.name} already exists with identical content.")
        elif not args.force:
            print(f"\n[ERROR] Immutable Release Protection:")
            print(f"        '{target_release_path}' already exists with different content!")
            print(f"        To publish changes, please increment version with: python3 scripts/build.py --bump")
            print(f"        Or if you explicitly intend to overwrite, pass: --force")
            sys.exit(1)
        else:
            print(f"[!] Warning: Overwriting existing release {target_release_path.name} (--force enabled).")

    # 1. Write the immutable release file
    with open(target_release_path, "wb") as f:
        f.write(release_payload)
    print(f"[✓] Written release snapshot: {target_release_path}")

    # Remove any obsolete uncompressed file if switching to gzip
    if use_gzip_release:
        obsolete_uncompressed = releases_dir / f"{target_version}.json"
        if obsolete_uncompressed.is_file():
            obsolete_uncompressed.unlink()
            print(f"[✓] Cleaned up oversized file: {obsolete_uncompressed.name} (exceeded 25MB Pages limit)")

    # 2. Write the latest convenience copy
    domains_copy_path = public_api_dir / domains_copy_filename
    with open(domains_copy_path, "wb") as f:
        f.write(release_payload)
    print(f"[✓] Written latest copy:      {domains_copy_path}")

    if use_gzip_release:
        obsolete_domains_copy = public_api_dir / "domains.json"
        if obsolete_domains_copy.is_file():
            obsolete_domains_copy.unlink()
            print(f"[✓] Cleaned up oversized file: {obsolete_domains_copy.name} (exceeded 25MB Pages limit)")

    # 3. Write version.json
    version_json_path = public_api_dir / "version.json"
    with open(version_json_path, "wb") as f:
        f.write(version_bytes)
    print(f"[✓] Written version metadata: {version_json_path}")

    # 4. Update metadata tracking
    metadata["domains_version"] = target_version
    metadata["schema_version"] = schema_version
    save_metadata(meta_path, metadata)
    print(f"[✓] Updated state tracker:    {meta_path}")

    print("=" * 60)
    print(f" Release {target_version} successfully built and ready for deployment!")
    print("=" * 60)


if __name__ == "__main__":
    main()
