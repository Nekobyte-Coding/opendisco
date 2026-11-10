#!/usr/bin/env python3
"""Sign a release: write SHA256SUMS over every file in a folder, and SHA256SUMS.sig, the Ed25519
signature of SHA256SUMS's exact bytes with OpenDisco's release key (docs/UPDATES.md).

    OPENDISCO_RELEASE_SIGNING_KEY=... python3 packaging/sign_release.py FOLDER
    python3 packaging/sign_release.py --verify FOLDER      # check a signed folder, no key needed

- SHA256SUMS: one "<sha256 hex>  <file name>" line per file (sha256sum's format), sorted by name,
  over every file in FOLDER except SHA256SUMS and SHA256SUMS.sig. update-key must be among them.
- SHA256SUMS.sig: the raw 64-byte signature, base64 on one line.
- The private key (OPENDISCO_RELEASE_SIGNING_KEY) is a PKCS#8 PEM Ed25519 key (openssl genpkey
  -algorithm ed25519); a 32-byte seed in base64 on one line works too. It must belong to the public key committed in
  src/opendisco/resources/release-signing.pub, and the signature is checked with that key (and
  OpenDisco's own verifier) before the script ends. Signing needs the cryptography package.

Nothing secret is printed: only file names, the public key's fingerprint and the update key's
last 4 characters.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from opendisco import signing, updatekey  # noqa: E402

SUMS, SIGNATURE = "SHA256SUMS", "SHA256SUMS.sig"


def files(folder: Path) -> list:
    found = sorted(p for p in folder.iterdir() if p.is_file() and p.name not in (SUMS, SIGNATURE))
    for p in found:
        if p.name.startswith(".") or any(c in p.name for c in "\n\r\\") or " " in p.name:
            sys.exit(f"error: {p.name!r} can't go in SHA256SUMS: no hidden files, spaces or line breaks")
    names = [p.name for p in found]
    if updatekey.NAME not in names:
        sys.exit(f"error: {folder} has no {updatekey.NAME}")
    if not updatekey.valid((folder / updatekey.NAME).read_text(encoding="ascii").strip()):
        sys.exit(f"error: {updatekey.NAME} isn't an update key")
    return found


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def private_key(text: str):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    text = text.strip()
    if text.startswith("-----BEGIN"):
        key = serialization.load_pem_private_key(text.encode("ascii"), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            sys.exit("error: the signing key isn't an Ed25519 key")
        return key
    try:
        seed = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        seed = b""
    if len(seed) != 32:
        sys.exit("error: the signing key isn't a base64 32-byte Ed25519 seed or a PEM")
    return Ed25519PrivateKey.from_private_bytes(seed)


def verify(folder: Path) -> None:
    public = signing.public_key()
    sums = (folder / SUMS).read_bytes()
    signature = base64.b64decode((folder / SIGNATURE).read_text(encoding="ascii").strip(), validate=True)
    if not (signing.verify_pure(public, sums, signature) and signing.verify(public, sums, signature)):
        sys.exit(f"error: {SIGNATURE} doesn't verify with release-signing.pub ({signing.fingerprint(public)})")
    listed = {}
    for line in sums.decode("utf-8").splitlines():
        digest, name = line.split("  ", 1)
        listed[name] = digest
    present = {p.name for p in files(folder)}
    if set(listed) != present:
        sys.exit(f"error: SHA256SUMS lists {sorted(set(listed) ^ present)} differently from the folder")
    for name, digest in listed.items():
        if sha256(folder / name) != digest:
            sys.exit(f"error: {name} doesn't match SHA256SUMS")
    print(f"{SUMS} verifies with the release key {signing.fingerprint(public)}: {len(listed)} files")


def main() -> int:
    parser = argparse.ArgumentParser(description="Write and sign a release's SHA256SUMS.")
    parser.add_argument("folder", type=Path)
    parser.add_argument("--verify", action="store_true", help="only check a folder that's signed already")
    args = parser.parse_args()
    folder = args.folder.resolve()
    if args.verify:
        verify(folder)
        return 0
    secret = os.environ.get("OPENDISCO_RELEASE_SIGNING_KEY", "")
    if not secret.strip():
        sys.exit("error: OPENDISCO_RELEASE_SIGNING_KEY is empty")
    from cryptography.hazmat.primitives import serialization
    key = private_key(secret)
    del secret
    public = signing.public_key()
    mine = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if mine != public:
        sys.exit(f"error: the signing key belongs to {signing.fingerprint(mine)}, not to the committed "
                 f"release-signing.pub ({signing.fingerprint(public)})")
    listed = files(folder)
    sums = "".join(f"{sha256(p)}  {p.name}\n" for p in listed).encode("utf-8")
    (folder / SUMS).write_bytes(sums)
    (folder / SIGNATURE).write_text(base64.b64encode(key.sign(sums)).decode("ascii") + "\n", encoding="ascii")
    hint = (folder / updatekey.NAME).read_text(encoding="ascii").strip()[-4:]
    print(f"Signed {SUMS} over {len(listed)} files (update key …{hint}):")
    for p in listed:
        print(f"  {p.name}")
    verify(folder)
    return 0


if __name__ == "__main__":
    sys.exit(main())
