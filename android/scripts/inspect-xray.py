#!/usr/bin/env python3
"""Inspect the pinned PattNG Xray fork Android archive before KTest pins its ELF."""
import hashlib
import io
import struct
import urllib.request
import zipfile

URL = "https://github.com/patterniha/Xray-core/releases/download/v26.11.1/Xray-android-arm64-v8a.zip"
EXPECTED = "e35403384aeafc5857cc7ed0a5c5c01dd10bc97992599840b6d77ef29031c3a6"
with urllib.request.urlopen(URL, timeout=120) as src:
    raw = src.read(48 << 20)
if hashlib.sha256(raw).hexdigest() != EXPECTED:
    raise SystemExit("official Xray archive SHA-256 mismatch")
with zipfile.ZipFile(io.BytesIO(raw)) as archive:
    for item in archive.infolist():
        if item.is_dir():
            continue
        print(f"XRAY_ARCHIVE_ENTRY={item.filename} size={item.file_size}", flush=True)
        if item.filename.rsplit("/", 1)[-1] != "xray":
            continue
        payload = archive.read(item)
        if len(payload) < 64 or payload[:4] != b"\x7fELF":
            raise SystemExit("Xray Android binary is not an ELF")
        machine = struct.unpack_from("<H", payload, 18)[0]
        print("XRAY_ELF_MACHINE=", machine, "class=", payload[4], flush=True)
        phoff = struct.unpack_from("<Q", payload, 32)[0]
        entsize, count = struct.unpack_from("<HH", payload, 54)
        alignments = [struct.unpack_from("<Q", payload, phoff+i*entsize+48)[0]
                      for i in range(count) if struct.unpack_from("<I", payload, phoff+i*entsize)[0] == 1]
        print("XRAY_ELF_PT_LOAD_ALIGNMENTS=", alignments, flush=True)
        print("XRAY_OFFICIAL_BINARY_SHA256=", hashlib.sha256(payload).hexdigest(), flush=True)
