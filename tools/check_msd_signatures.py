#!/usr/bin/env python3
"""Verify stock MSD section signatures with the extracted updater public key.

Read-only with respect to firmware. This verifies section signatures, not the
complete update policy, boot chain, or acceptance of any modified image.
"""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHA512_DIGEST_INFO = bytes.fromhex("3051300d060960864801650304020305000440")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, default=ROOT / "firmware/metadata")
    parser.add_argument(
        "--key",
        type=Path,
        default=ROOT
        / "firmware/filesystems/T-RSMFAKUC-0090/pltf_t/root/usr/share/org.tizen.tv.swu/itemsPublicRSAKey.txt",
    )
    args = parser.parse_args()
    key = args.key
    output = subprocess.check_output(
        [
            "openssl",
            "rsa",
            "-RSAPublicKey_in",
            "-in",
            str(key),
            "-text",
            "-modulus",
            "-noout",
        ],
        stderr=subprocess.DEVNULL,
    ).decode()
    modulus = bytes.fromhex(re.search(r"^Modulus=([0-9A-Fa-f]+)$", output, re.M)[1])
    exponent = int(re.search(r"Exponent: (\d+)", output)[1])
    n, width = int.from_bytes(modulus, "big"), len(modulus)
    report = {
        "scope": "stock encrypted MSD sections only; no modified-image acceptance test",
        "key_path": str(key.resolve()),
        "modulus_sha256": hashlib.sha256(modulus).hexdigest(),
        "exponent": exponent,
        "signature_scheme": "RSASSA-PKCS1-v1_5 with SHA-512",
        "sections": [],
    }
    for family in ("T-RSMFAKUC-0090", "TB-RSWF4AKUC-0090"):
        log = (args.metadata / f"{family}-extraction.log").read_text()
        sections = re.findall(r"Section (\d+): offset: (\d+), size: (\d+)", log)
        signatures = re.findall(r"^\s+Signature: ([0-9a-f]+)$", log, re.M)
        key_ids = re.findall(r"Public key ID: (\d+)", log)
        if len(sections) != 9 or len(signatures) != 9 or len(key_ids) != 9:
            raise ValueError(f"Unexpected section/signature count for {family}")
        with (ROOT / f"firmware/extracted/{family}/image/upgrade.msd").open(
            "rb"
        ) as image:
            for (identifier, offset, size), signature_hex, key_id in zip(
                sections, signatures, key_ids, strict=True
            ):
                signature = bytes.fromhex(signature_hex)
                if len(signature) != width or int.from_bytes(signature, "big") >= n:
                    raise ValueError("Invalid signature representation")
                image.seek(int(offset))
                remaining, digest = int(size), hashlib.sha512()
                while remaining:
                    chunk = image.read(min(8 * 1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("Truncated encrypted section")
                    digest.update(chunk)
                    remaining -= len(chunk)
                payload = SHA512_DIGEST_INFO + digest.digest()
                expected = (
                    b"\0\1" + b"\xff" * (width - len(payload) - 3) + b"\0" + payload
                )
                recovered = pow(int.from_bytes(signature, "big"), exponent, n).to_bytes(
                    width, "big"
                )
                if recovered != expected:
                    raise ValueError(f"Signature mismatch: {family}/{identifier}")
                changed = bytearray(expected)
                changed[-1] ^= 1
                if recovered == changed:
                    raise ValueError("Changed-digest negative check failed")
                report["sections"].append(
                    {
                        "family": family,
                        "item_id": int(identifier),
                        "public_key_id": int(key_id),
                        "offset": int(offset),
                        "encrypted_size": int(size),
                        "encrypted_sha512": digest.hexdigest(),
                        "signature_valid": True,
                        "changed_digest_rejected": True,
                    }
                )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
