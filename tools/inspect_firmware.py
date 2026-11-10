#!/usr/bin/env python3
"""Inventory and extract the official ZIP; inspect MSDU11 headers without TV access."""

import argparse
import hashlib
import json
import re
import struct
import subprocess
import zipfile
import zlib
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "firmware/T-RSMFAKUC-0090_TB-RSWF4AKUC-0090.zip"
OUT = ROOT / "firmware/extracted"
ANALYSIS = ROOT / "firmware/metadata"
KEYS = ROOT / ".local/toolchain/unixtract/src/keys.ukf"


def digest_file(path, algorithm="sha256"):
    with path.open("rb") as f:
        return hashlib.file_digest(f, algorithm).hexdigest()


def inspect_msd(path, *, keys_path=KEYS, metadata=ANALYSIS):
    size = path.stat().st_size
    with path.open("rb") as f:
        b = f.read(65536)
        magic, crc, header_size, count = struct.unpack_from("<6sIQI", b)
        if magic != b"MSDU11" or count > 1000 or header_size > len(b) - 18:
            raise ValueError("Unexpected MSD header")
        pos = 22
        sections = []
        for _ in range(count):
            index, offset, length = struct.unpack_from("<IQQ", b, pos)
            pos += 20
            if offset + length > size:
                raise ValueError("MSD section outside file")
            f.seek(offset)
            sample = f.read(min(length, 1048576))
            sections.append(
                {
                    "index": index,
                    "offset": offset,
                    "size": length,
                    "prefix_hex": sample[:32].hex(),
                }
            )
        (header_count,) = struct.unpack_from("<I", b, pos)
        pos += 4
        if header_count > 1000:
            raise ValueError("Unexpected header count")
        headers = []
        keys_text = keys_path.read_text()
        key_collection = keys_text.split('collection "MSD11": {', 1)[1].split("\n}", 1)[
            0
        ]
        keys = re.findall(r'"([^"\n]+)"\s*:\s*\{x"([0-9a-fA-F]+)"\}', key_collection)
        for _ in range(header_count):
            offset, length, name_length = struct.unpack_from("<QIB", b, pos)
            pos += 13
            name = b[pos : pos + name_length].decode("ascii")
            pos += name_length
            if offset + length > size or length < 24 or length > 1048576:
                raise ValueError("Invalid MSD TOC bounds")
            f.seek(offset)
            raw = f.read(length)
            toc = raw[8:]
            entry = {
                "name": name,
                "offset": offset,
                "size": length,
                "prefix_hex": raw[:32].hex(),
                "public_keys_tested": [],
            }
            if toc[:8] == b"Salted__":
                salt, encrypted = toc[8:16], toc[16:]
                for key_name, key_hex in keys:
                    key = bytes.fromhex(key_hex)
                    iv = (
                        hashlib.md5(salt).digest()
                        if len(key) == 16
                        else hashlib.sha256(salt).digest()[:16]
                    )
                    result = subprocess.run(
                        [
                            "openssl",
                            "enc",
                            "-d",
                            f"-aes-{len(key) * 8}-cbc",
                            "-K",
                            key_hex,
                            "-iv",
                            iv.hex(),
                        ],
                        input=encrypted,
                        capture_output=True,
                        check=False,
                    )
                    plain = result.stdout
                    valid = result.returncode == 0 and any(
                        plain[o : o + 50] == marker
                        for o, marker in [
                            (
                                256,
                                b"Tizen Software Upgrade Tree Binary Format ver. 1.8",
                            ),
                            (
                                262,
                                b"Tizen Software Upgrade Tree Binary Format ver. 1.9",
                            ),
                            (
                                518,
                                b"Tizen Software Upgrade Tree Binary Format ver. 1.9",
                            ),
                        ]
                    )
                    entry["public_keys_tested"].append(
                        {"name": key_name, "valid_toc": valid}
                    )
                    if valid:
                        (metadata / f"{path.parents[1].name}-toc.bin").write_bytes(
                            plain
                        )
                        entry["matching_key_name"] = key_name
            headers.append(entry)
    return {
        "magic": magic.decode(),
        "header_size": header_size,
        "header_crc32": f"{crc:08x}",
        "header_crc32_valid": zlib.crc32(b[18 : 18 + header_size]) == crc,
        "sections": sections,
        "headers": headers,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=ARCHIVE)
    parser.add_argument(
        "--output",
        type=Path,
        default=OUT,
        help="Fresh extraction directory; existing directories are refused",
    )
    parser.add_argument("--metadata", type=Path, default=ANALYSIS)
    parser.add_argument(
        "--keys", type=Path, default=KEYS, help="Pinned unixtract keys.ukf"
    )
    args = parser.parse_args()
    archive, out, metadata, keys = (
        path.resolve() for path in (args.archive, args.output, args.metadata, args.keys)
    )
    for path in (archive, keys):
        if not path.is_file():
            parser.error(f"Missing input: {path}")
    if out.exists():
        parser.error(f"Refusing existing extraction directory: {out}")
    metadata.mkdir(parents=True, exist_ok=True)
    out.mkdir(parents=True, exist_ok=False)
    report = {
        "archive": str(archive),
        "archive_bytes": archive.stat().st_size,
        "archive_sha256": digest_file(archive),
        "members": [],
    }
    with zipfile.ZipFile(archive) as z:
        if sum(i.file_size for i in z.infolist()) > 6 * 1024**3:
            raise ValueError("Archive exceeds extraction budget")
        for info in z.infolist():
            rel = PurePosixPath(info.filename)
            if (
                rel.is_absolute()
                or ".." in rel.parts
                or (info.external_attr >> 16) & 0o170000 == 0o120000
            ):
                raise ValueError("Unsafe archive member")
            dest = out.joinpath(*rel.parts)
            if info.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            sha, md5 = hashlib.sha256(), hashlib.md5()
            with z.open(info) as source, dest.open("xb") as output:
                while block := source.read(4 * 1024 * 1024):
                    output.write(block)
                    sha.update(block)
                    md5.update(block)
            item = {
                "path": str(dest),
                "bytes": info.file_size,
                "zip_crc32": f"{info.CRC:08x}",
                "zip_crc32_valid": True,
                "sha256": sha.hexdigest(),
                "md5": md5.hexdigest(),
            }
            if dest.suffix == ".txt":
                item["text"] = dest.read_text()
            if dest.suffix == ".msd":
                item["msd"] = inspect_msd(dest, keys_path=keys, metadata=metadata)
                vendor_metadata = dest.with_name("info.txt").read_text()
                expected = re.search(
                    r"^md5sum:\s*([a-f0-9]+)", vendor_metadata, re.M
                ).group(1)
                item["vendor_md5_valid"] = expected == item["md5"]
            report["members"].append(item)
            print(json.dumps(item), flush=True)
    (metadata / "firmware-inventory.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    (metadata / "SHA256SUMS").write_text(
        report["archive_sha256"]
        + "  "
        + report["archive"]
        + "\n"
        + "".join(i["sha256"] + "  " + i["path"] + "\n" for i in report["members"])
    )
    print("Archive SHA256:", report["archive_sha256"])


if __name__ == "__main__":
    main()
