#!/usr/bin/env python3
"""Prepare certificate-file replacements and deletion records, not firmware.

Reads the inert extraction; never edits baseline images or contacts the TV.
Exact certificate fingerprints prevent deleting similarly named unrelated CAs.
Filesystem metadata, image reconstruction and firmware signing are not supplied.
"""

import argparse
import base64
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "firmware/filesystems"
TARGETS = {
    "40f6af0346a99aa1cd1d555a4e9cce62c7f9634603ee406615833dc8c8d00367": "emSign Root CA - G1",
    "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b": "emSign ECC Root CA - G3",
    "125609aa301da0a249b97a8239cb6a34216f44dcac9f3954b14292f2e8c8608f": "emSign Root CA - C1",
    "bc4d809b15189d78db3e1d8cf4f9726a795da1643ca5f1358e1ddb0edc0d7eb3": "emSign ECC Root CA - C3",
}
PEM = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\r\n\t ]+)-----END CERTIFICATE-----"
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def certificates(data):
    return [
        (m, base64.b64decode(re.sub(rb"\s", b"", m[1]), validate=True))
        for m in PEM.finditer(data)
    ]


def filter_bundle(data):
    before = certificates(data)
    remove = [(m, der) for m, der in before if sha(der) in TARGETS]
    after = data
    for m, _der in reversed(remove):
        after = after[: m.start()] + after[m.end() :]
    expected = [der for _, der in before if sha(der) not in TARGETS]
    actual = [der for _, der in certificates(after)]
    if actual != expected:
        raise ValueError("Unrelated certificate changed")
    return after, [sha(der) for _, der in remove], len(expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "run_name", help="Fresh directory name under .local/candidates/"
    )
    args = parser.parse_args()
    if not re.fullmatch(r"[a-zA-Z0-9_-]+", args.run_name):
        parser.error("Use a simple run name")
    out = ROOT / ".local/candidates" / args.run_name
    out.mkdir(parents=True, exist_ok=False)
    manifest = {
        "status": "NON_INSTALLABLE_CERTIFICATE_FILE_CANDIDATE",
        "model": "QN65LS03FWFXZA",
        "baseline_firmware": {
            "T-RSMFAKUC-0090": "1301.0",
            "TB-RSWF4AKUC-0090": "1301.8",
        },
        "targets_sha256": TARGETS,
        "changes": [],
        "deferred_embedded_stores": [],
        "limitations": [
            "No metadata-preserving filesystem rebuild",
            "No MSD repack/signing or USB acceptance",
            "No live TV validation",
            "Embedded binary/database/compressed stores not exhaustively audited",
            "Nested factory images must be rebuilt from their staged changes",
            "Existing live trust stores and update regeneration behavior require validation",
        ],
    }
    # Search PEM content regardless of filename, including app-specific stores.
    result = subprocess.run(
        ["rg", "-l", "--text", "-e", "-----BEGIN CERTIFICATE-----", str(BASE)],
        check=True,
        stdout=subprocess.PIPE,
    )
    files = sorted(Path(p) for p in result.stdout.decode().splitlines())
    deleted_targets = set()
    for path in files:
        if path.is_symlink() or path.name.endswith(".symlink-target"):
            continue
        data = path.read_bytes()
        changed, removed, kept = filter_bundle(data)
        if not removed:
            continue
        rel = path.relative_to(BASE)
        # PEM blocks inside ELF/SQLite must never be spliced as text.
        if b"\x00" in data or path.suffix not in (".pem", ".crt", ".cer", ".0"):
            manifest["deferred_embedded_stores"].append(
                {
                    "path": str(rel),
                    "before_sha256": sha(data),
                    "target_fingerprints": removed,
                    "reason": "Requires format-aware modification and validation; not staged",
                }
            )
            continue
        row = {
            "path": str(rel),
            "before_sha256": sha(data),
            "removed_sha256": removed,
            "retained_certificate_count": kept,
        }
        if kept == 0:
            if changed.strip():
                raise ValueError(
                    f"Non-certificate content remains in {path}; inspect before deleting"
                )
            row["action"] = "delete"
            parts = rel.parts
            root_index = parts.index("root")
            virtual = "/" + "/".join(parts[root_index + 1 :])
            deleted_targets.add((parts[0], virtual))
        else:
            row.update(action="replace", after_sha256=sha(changed))
            target = out / "staging" / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(changed)
            # OpenSSL must parse the complete retained certificate bundle.
            subprocess.run(
                [
                    "openssl",
                    "crl2pkcs7",
                    "-nocrl",
                    "-certfile",
                    str(target),
                    "-outform",
                    "DER",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        manifest["changes"].append(row)
    # The extractor represents symlinks as text; record exact links to removed files.
    for path in sorted(BASE.rglob("*.symlink-target")):
        rel = path.relative_to(BASE)
        data = path.read_bytes()
        if (rel.parts[0], data.decode().strip()) in deleted_targets:
            manifest["changes"].append(
                {
                    "path": str(rel),
                    "action": "delete_symlink_record",
                    "before_sha256": sha(data),
                    "target": data.decode().strip(),
                }
            )
    observed = {fp for r in manifest["changes"] for fp in r.get("removed_sha256", [])}
    if observed != set(TARGETS):
        raise ValueError("Not all four requested roots were found")
    for family in manifest["baseline_firmware"]:
        factory = f"{family}/data_backup/root/var/lib/ca-certificates/ca-bundle.pem"
        match = next((r for r in manifest["changes"] if r["path"] == factory), None)
        if match is None or set(match["removed_sha256"]) != set(TARGETS):
            raise ValueError(f"Factory CA bundle coverage missing: {family}")
    # Read back outputs and baseline to ensure no write drift.
    for row in manifest["changes"]:
        if sha((BASE / row["path"]).read_bytes()) != row["before_sha256"]:
            raise ValueError("Baseline changed during preparation")
        if row["action"] == "replace":
            data = (out / "staging" / row["path"]).read_bytes()
            if sha(data) != row["after_sha256"] or any(
                sha(d) in TARGETS for _, d in certificates(data)
            ):
                raise ValueError("Staged verification failed")
    manifest["validation"] = {
        "all_four_roots_found": True,
        "original_files_unchanged": True,
        "unrelated_certificates_preserved_in_order": True,
        "staged_bundles_parse_with_openssl": True,
        "target_roots_absent_from_staged_bundles": True,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (out / "README.md").write_text(
        "# Certificate-removal candidate — NOT a USB firmware update\n\n"
        "This directory contains replacement certificate bundles and a deletion manifest. "
        "It cannot be installed through Samsung Software Update. It contains no rebuilt "
        "VDFS/MSD images or accepted firmware signatures.\n\n"
        "The manifest records exact input/output hashes and removal fingerprints. "
        "Only `replace` entries have staged files; `delete` and `delete_symlink_record` "
        "entries describe future removals. Inert link records must never be copied to a TV. "
        "Canonical extraction and original firmware remain unchanged.\n\n"
        "The roots also occur in Chromium ELF binaries and certificate SQLite databases. Those are listed as deferred, left unchanged, and require format-aware work. Validation covers staged PEM stores only. "
        "Changing an image also needs a validated update migration for existing writable stores. "
        "No installer is provided.\n"
    )
    print(
        json.dumps(
            {
                "output": str(out),
                "changes": len(manifest["changes"]),
                "deferred_embedded_stores": manifest["deferred_embedded_stores"],
                "certificate_occurrences_removed": sum(
                    len(r.get("removed_sha256", [])) for r in manifest["changes"]
                ),
                "replacements": sum(
                    r["action"] == "replace" for r in manifest["changes"]
                ),
                "deletions": sum(r["action"] == "delete" for r in manifest["changes"]),
                "link_deletions": sum(
                    r["action"] == "delete_symlink_record" for r in manifest["changes"]
                ),
                "validation": manifest["validation"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
