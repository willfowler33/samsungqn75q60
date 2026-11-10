#!/usr/bin/env python3
"""Verify decrypted section CRCs and GPT tables; carve VDFS partitions for analysis."""

import argparse
import hashlib
import json
import re
import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--decrypted", type=Path, default=ROOT / "firmware/decrypted")
    parser.add_argument("--metadata", type=Path, default=ROOT / "firmware/metadata")
    parser.add_argument("--partitions", type=Path, default=ROOT / "firmware/partitions")
    parser.add_argument(
        "--carve",
        action="store_true",
        help="Also write partitions into a fresh directory",
    )
    parser.add_argument(
        "--report", type=Path, default=ROOT / ".local/reports/decrypted-inventory.json"
    )
    args = parser.parse_args()
    if not args.decrypted.is_dir():
        parser.error(f"Missing decrypted input: {args.decrypted}")
    if args.carve and args.partitions.exists():
        parser.error(f"Refusing existing partition directory: {args.partitions}")
    families = sorted(path for path in args.decrypted.iterdir() if path.is_dir())
    if not families:
        parser.error("No decrypted firmware families found")
    report = []
    for directory in families:
        log = (args.metadata / (directory.name + "-extraction.log")).read_text()
        expected = re.findall(
            r"Original size: (\d+).*?Name: ([\w.]+).*?CRC32: ([0-9a-f]+)", log, re.S
        )
        if len(expected) != 9:
            raise ValueError("Expected nine decrypted sections")
        image = {"family": directory.name, "sections": [], "partitions": []}
        for size, name, crc in expected:
            path = directory / name
            digest, computed = hashlib.sha256(), 0
            with path.open("rb") as f:
                while block := f.read(4 * 1024 * 1024):
                    digest.update(block)
                    computed = zlib.crc32(block, computed)
            ok = computed == int(crc, 16) and path.stat().st_size == int(size)
            image["sections"].append(
                {
                    "name": name,
                    "size": path.stat().st_size,
                    "sha256": digest.hexdigest(),
                    "crc32": f"{computed:08x}",
                    "expected_crc32": crc,
                    "verified": ok,
                }
            )
            if not ok:
                raise ValueError("Decrypted image verification failed: " + str(path))
        with (directory / "platform.img").open("rb") as f:
            total_size = (directory / "platform.img").stat().st_size
            f.seek(512)
            header = bytearray(f.read(512))
            if header[:8] != b"EFI PART":
                raise ValueError("Missing GPT signature")
            header_size, header_crc = struct.unpack_from("<II", header, 12)
            if not 92 <= header_size <= 512:
                raise ValueError("Bad GPT header size")
            struct.pack_into("<I", header, 16, 0)
            image["gpt_header_crc_valid"] = (
                zlib.crc32(header[:header_size]) == header_crc
            )
            lba, count, entry_size, entry_crc = struct.unpack_from("<QIII", header, 72)
            if count > 1024 or entry_size < 128 or count * entry_size > 1048576:
                raise ValueError("Bad GPT table size")
            f.seek(lba * 512)
            entries = f.read(count * entry_size)
            image["gpt_entries_crc_valid"] = zlib.crc32(entries) == entry_crc
            if not image["gpt_header_crc_valid"] or not image["gpt_entries_crc_valid"]:
                raise ValueError("GPT checksum failure")
            for i in range(count):
                entry = entries[i * entry_size : (i + 1) * entry_size]
                if entry[:16] == bytes(16):
                    continue
                start, end = struct.unpack_from("<QQ", entry, 32)
                name = entry[56:128].decode("utf-16le").split("\0")[0]
                if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
                    raise ValueError("Unsafe partition name")
                offset, length = start * 512, (end - start + 1) * 512
                if start > end or offset + length > total_size:
                    raise ValueError("Partition outside image")
                out = args.partitions / directory.name / name
                if args.carve:
                    out.parent.mkdir(parents=True, exist_ok=True)
                digest = hashlib.sha256()
                f.seek(offset)
                magic = f.read(8)
                f.seek(offset)
                remaining = length
                # Verify the bytes even when no partition output was requested.
                output = out.open("xb") if args.carve else None
                try:
                    while remaining:
                        block = f.read(min(4 * 1024 * 1024, remaining))
                        if not block:
                            raise ValueError("Truncated partition")
                        if output is not None:
                            output.write(block)
                        digest.update(block)
                        remaining -= len(block)
                finally:
                    if output is not None:
                        output.close()
                image["partitions"].append(
                    {
                        "name": name,
                        "offset": offset,
                        "size": length,
                        "magic": magic.hex(),
                        "sha256": digest.hexdigest(),
                        "path": str(out) if args.carve else None,
                    }
                )
        report.append(image)
        print(
            directory.name,
            "all 9 section CRCs and primary GPT checksums verified",
            flush=True,
        )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
