#!/usr/bin/env python3
"""Prepare a reviewed Aether Android version bump without bypassing artifact pins.

Fetches *all* advertised Android ABIs and derives archive + per-executable
SHA-256 from the exact release. It never alters an existing installation,
APK, certificate, WARP identity or another core. Without --write, prints
a prospective lock only. Every change is reviewable as a normal git diff.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "internal/aether/android-cores.json"
REPO = "https://github.com/patterniha/Aether"
ASSET_TO_ABI = {
    "arm64-v8a": "aether-android-arm64.tar.gz",
    "armeabi-v7a": "aether-android-armv7.tar.gz",
    "x86_64": "aether-android-x86_64.tar.gz",
}
MAX_ARCHIVE = 200 << 20
MAX_FILE = 100 << 20


def request(url):
    req = urllib.request.Request(url, headers={
        "User-Agent": "ktest-aether-pin-updater",
        "Accept": "application/vnd.github+json",
    })
    return urllib.request.urlopen(req, timeout=90)


def fetch_release(version):
    with request("https://api.github.com/repos/patterniha/Aether/releases/tags/" + version) as r:
        release = json.load(r)
    if release.get("tag_name") != version or release.get("draft") or release.get("prerelease"):
        raise ValueError("requested release tag missing or not a stable publication")
    assets = {item["name"]: item for item in release["assets"]}
    return assets


def get_archive(asset):
    # GitHub asset digests independently pin the staged release payload.
    digest = asset.get("digest", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("GitHub release asset lacks a validated SHA-256")
    with request(asset["browser_download_url"]) as r:
        with tempfile.SpooledTemporaryFile(max_size=MAX_ARCHIVE) as staging:
            total = 0
            while chunk := r.read(1 << 20):
                total += len(chunk)
                if total > MAX_ARCHIVE:
                    raise ValueError("archive exceeds size limit")
                staging.write(chunk)
            staging.seek(0)
            data = staging.read()
    archive_sha = hashlib.sha256(data).hexdigest()
    if archive_sha != digest.split(":", 1)[1]:
        raise ValueError("release asset SHA-256 differs from downloaded archive")
    return data, archive_sha


def check_binary_headers(data, abi):
    # Reuse exactly the same Android ELF validation as the APK packager.
    spec = importlib.util.spec_from_file_location(
        "ktest_native_prepare", ROOT / "android/scripts/prepare-native-cores.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.check_elf(data, abi)


def update_manifest(version):
    current = json.loads(LOCK.read_text(encoding="utf-8"))
    if current.get("repository") != REPO:
        raise ValueError("unexpected existing native source")
    assets = fetch_release(version)
    updated = json.loads(json.dumps(current))
    updated["version"] = version
    for abi_name, asset_name in ASSET_TO_ABI.items():
        if abi_name not in updated["abis"] or asset_name not in assets:
            raise ValueError(f"missing stable ABI/asset: {abi_name} ({asset_name})")
        entry = updated["abis"][abi_name]
        if entry["archive"] != asset_name:
            raise ValueError(f"archive filename mismatch for {abi_name}")
        payload, sha = get_archive(assets[asset_name])
        entry["sha256"] = sha
        expected = {item["source"]: item for item in entry["files"]}
        seen = set()
        with tempfile.TemporaryFile() as temp:
            temp.write(payload)
            temp.seek(0)
            with tarfile.open(fileobj=temp, mode="r:gz") as package:
                for member in package:
                    name = member.name.removeprefix("./")
                    if name not in expected:
                        continue
                    if name in seen or not member.isfile() or member.size > MAX_FILE:
                        raise ValueError("duplicate/non-regular/oversized Aether native member")
                    stream = package.extractfile(member)
                    if stream is None:
                        raise ValueError("unreadable Aether native member")
                    data = stream.read()
                    check_binary_headers(data, entry)
                    expected[name]["sha256"] = hashlib.sha256(data).hexdigest()
                    seen.add(name)
        if seen != set(expected):
            raise ValueError("incomplete Aether archive for " + abi_name)
        print(f"{abi_name}: verified archive {sha}; {len(seen)} executable hashes")
    return updated


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--write", action="store_true", help="atomically publish the complete reviewed lock")
    args = parser.parse_args()
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", args.version):
        raise ValueError("expected an explicit stable semver tag")
    updated = update_manifest(args.version)
    result = json.dumps(updated, indent=2) + "\n"
    if not args.write:
        print(result)
        print("Dry run: no files changed; pass --write only after reviewing provenance.")
        return
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=LOCK.parent, delete=False) as tmp:
        tmp.write(result)
        tmp_name = tmp.name
    os.replace(tmp_name, LOCK)
    print("Wrote reviewed native lock:", LOCK)


if __name__ == "__main__":
    main()
