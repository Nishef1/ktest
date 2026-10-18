#!/usr/bin/env python3
"""Verify/package unmodified official native executables; never build APK/AAR.

The APK extracts these files to nativeLibraryDir. They must be executed from
that read-only package directory, never copied into the writable app home.
Use --verify-only to inspect archives and ELF contracts without packaging.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
MANIFESTS = [ROOT / "internal/aether/android-cores.json",
             ROOT / "internal/byedpi/android-cores.json",
             ROOT / "internal/xraycfg/android-cores.json"]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def check_elf(data, abi):
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[5] != 1:
        raise ValueError("native payload must be little-endian ELF")
    bits = {1: 32, 2: 64}.get(data[4])
    kind, machine = struct.unpack_from("<HH", data, 16)
    if bits != abi["bits"] or machine != abi["machine"] or kind not in (2, 3):
        raise ValueError("native ELF ABI/type mismatch")
    if bits == 64:
        offset = struct.unpack_from("<Q", data, 32)[0]
        size, count = struct.unpack_from("<HH", data, 54)
        fmt, align_at, offset_at, size_at = "<Q", 48, 8, 32
        minimum_header = 56
    else:
        offset = struct.unpack_from("<I", data, 28)[0]
        size, count = struct.unpack_from("<HH", data, 42)
        fmt, align_at, offset_at, size_at = "<I", 28, 4, 16
        minimum_header = 32
    if size < minimum_header or count == 0 or offset + size * count > len(data):
        raise ValueError("invalid native ELF program headers")
    loads = 0
    for index in range(count):
        pos = offset + index * size
        segment = struct.unpack_from("<I", data, pos)[0]
        if segment == 1:
            alignment = struct.unpack_from(fmt, data, pos + align_at)[0]
            if alignment < abi["min_load_alignment"]:
                raise ValueError("native ELF does not meet the ABI page-alignment contract")
            loads += 1
        if segment == 3:
            start = struct.unpack_from(fmt, data, pos + offset_at)[0]
            length = struct.unpack_from(fmt, data, pos + size_at)[0]
            if start + length > len(data):
                raise ValueError("invalid ELF interpreter bounds")
            expected = b"/system/bin/linker64" if bits == 64 else b"/system/bin/linker"
            if data[start:start + length].rstrip(b"\0") != expected:
                raise ValueError("native executable requires a non-Android dynamic linker")
    if loads == 0:
        raise ValueError("native ELF has no loadable segments")


def archive_payloads(archive, abi):
    payloads = {}
    expected = {item["source"]: item for item in abi["files"]}
    if archive.suffix == ".zip":
        # Xray publishes unchanged Android ELF inside a ZIP (unlike Aether
        # and ByeDPI tarballs). Validate each payload in addition to the
        # already pinned whole-archive digest.
        with zipfile.ZipFile(archive) as source:
            entries = [item for item in source.infolist() if item.filename in expected]
            if len(entries) != len(expected) or len({item.filename for item in entries}) != len(expected):
                raise ValueError("Xray ZIP missing or duplicating official executable")
            for item in entries:
                if item.is_dir() or item.file_size > 100 << 20:
                    raise ValueError("bad Xray executable ZIP entry")
                data = source.read(item)
                if digest(data) != expected[item.filename]["sha256"]:
                    raise ValueError("Xray executable checksum mismatch")
                check_elf(data, abi)
                payloads[item.filename] = data
        return payloads
    with tarfile.open(archive, "r:gz") as source:
        for member in source:
            name = member.name.removeprefix("./")
            if name not in expected:
                continue
            if name in payloads or not member.isfile() or member.size > 100 << 20:
                raise ValueError("duplicate, nonregular or oversized native archive entry")
            stream = source.extractfile(member)
            if stream is None:
                raise ValueError("native archive entry cannot be read")
            data = stream.read()
            if digest(data) != expected[name]["sha256"]:
                raise ValueError("native executable checksum mismatch")
            check_elf(data, abi)
            payloads[name] = data
    if payloads.keys() != expected.keys():
        raise ValueError("native archive is missing a required core/helper")
    return payloads


def prepare(manifest, cache, destination, abis, verify_only):
    cache.mkdir(parents=True, exist_ok=True)
    for name in abis:
        if name not in manifest["abis"]:
            if manifest.get("optional_abis"):
                continue  # e.g. official Android Xray is pinned only for ARM64
            raise ValueError(f"unsupported Android ABI: {name}")
        abi = manifest["abis"][name]
        archive_name = abi["archive"]
        if Path(archive_name).name != archive_name:
            raise ValueError("native archive must be a single filename")
        archive = cache / archive_name
        if not archive.exists():
            url = f'{manifest["repository"]}/releases/download/{manifest["version"]}/{archive_name}'
            # A task-owned temporary file prevents interrupted downloads being adopted.
            with tempfile.TemporaryFile() as staged:
                with urllib.request.urlopen(url, timeout=90) as response:
                    while block := response.read(1 << 20):
                        staged.write(block)
                        if staged.tell() > 200 << 20:
                            raise ValueError("native archive exceeds its download budget")
                staged.seek(0)
                data = staged.read()
            if digest(data) != abi["sha256"]:
                raise ValueError("downloaded native archive checksum mismatch")
            archive.write_bytes(data)
        if digest(archive.read_bytes()) != abi["sha256"]:
            raise ValueError("cached native archive checksum mismatch; file preserved")
        payloads = archive_payloads(archive, abi)
        if not verify_only:
            target = destination / name
            target.mkdir(parents=True, exist_ok=True)
            for item in abi["files"]:
                if Path(item["name"]).name != item["name"] or not item["name"].endswith(".so"):
                    raise ValueError("packaged executable must have a native-library filename")
                output = target / item["name"]
                data = payloads[item["source"]]
                if output.exists() and digest(output.read_bytes()) == item["sha256"]:
                    continue
                with tempfile.NamedTemporaryFile(dir=target, delete=False) as staged:
                    staged.write(data)
                    staged_path = Path(staged.name)
                try:
                    staged_path.chmod(0o755)
                    staged_path.replace(output)
                finally:
                    staged_path.unlink(missing_ok=True)
        if not verify_only and manifest["repository"] == "https://github.com/XTLS/Xray-core":
            # The exact pinned official archive supplies the license verbatim.
            with zipfile.ZipFile(archive) as xray_archive:
                license_text = xray_archive.read("LICENSE")
            if len(license_text) == 0 or len(license_text) > 1 << 20:
                raise ValueError("invalid official Xray license payload")
            license_path = ROOT / "android/app/src/main/assets/third_party/Xray-MPL-2.0.txt"
            license_path.parent.mkdir(parents=True, exist_ok=True)
            license_path.write_bytes(license_text)
        print(f'{name}: verified {len(payloads)} official {manifest["version"]} executables; '
              f'{"not packaged" if verify_only else "packaged into jniLibs"}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--abis", nargs="+", default=["arm64-v8a", "armeabi-v7a"])
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "dist/android-native-cache")
    parser.add_argument("--output", type=Path, default=ROOT / "android/app/src/main/jniLibs")
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--verify-apk", type=Path, help="check an existing APK; never build one")
    args = parser.parse_args()
    if args.verify_apk:
        with zipfile.ZipFile(args.verify_apk) as apk:
            for path in MANIFESTS:
                manifest = json.loads(path.read_text())
                for abi in args.abis:
                    if abi not in manifest["abis"] and manifest.get("optional_abis"):
                        continue
                    for item in manifest["abis"][abi]["files"]:
                        name = f'lib/{abi}/{item["name"]}'
                        if digest(apk.read(name)) != item["sha256"]:
                            raise ValueError(f"APK changed or stripped pinned executable: {name}")
                    print(f"{abi}: {manifest['repository']} APK native executable hashes verified")
        return
    for path in MANIFESTS:
        manifest = json.loads(path.read_text())
        prepare(manifest, args.cache_dir, args.output, args.abis, args.verify_only)


if __name__ == "__main__":
    main()
