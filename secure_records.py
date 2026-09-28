#!/usr/bin/env python3
"""secure_records.py - Encrypt, decrypt and integrity-check student record files.

Encryption : AES-256-GCM (authenticated encryption) from the 'cryptography' package.
Integrity  : SHA-256 of the plaintext, stored in a manifest, re-checked on demand.
Key        : 32 random bytes kept OUTSIDE the repository (default ~/.secure_records/master.key).

Sub-commands: keygen | encrypt | decrypt | decrypt-verify | hash | verify
"""
import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover
    sys.exit("Missing dependency. Run: pip install -r requirements.txt")

NONCE_LEN = 12
MAGIC = b"SRv1"                                   # file-format marker (also authenticated)
DEFAULT_KEY = Path(os.environ.get("SECURE_RECORDS_KEY",
                                  Path.home() / ".secure_records" / "master.key"))
DEFAULT_MANIFEST = Path("data/manifest.json")


class SecureRecordsError(Exception):
    """Expected, user-facing error (bad path, bad key, tampering...)."""


# ---------- helpers ----------
def _require_file(path: Path, label: str = "File") -> Path:
    if not path.exists():
        raise SecureRecordsError(f"{label} not found: {path}")
    if not path.is_file():
        raise SecureRecordsError(f"{label} is not a regular file: {path}")
    return path


def sha256_file(path: Path) -> str:
    _require_file(path)
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def generate_key(key_path: Path = DEFAULT_KEY, overwrite: bool = False) -> Path:
    if key_path.exists() and not overwrite:
        raise SecureRecordsError(f"Key already exists at {key_path} (use --force to replace; old data becomes unreadable).")
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(AESGCM.generate_key(bit_length=256))
    try:
        key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)   # chmod 600
    except OSError:
        pass
    return key_path


def load_key(key_path: Path = DEFAULT_KEY) -> bytes:
    _require_file(key_path, "Key file")
    key = key_path.read_bytes()
    if len(key) != 32:
        raise SecureRecordsError("Invalid key: expected exactly 32 bytes. Run 'keygen'.")
    return key


def _load_manifest(manifest: Path) -> dict:
    if not manifest.exists():
        return {}
    try:
        return json.loads(manifest.read_text())
    except json.JSONDecodeError:
        raise SecureRecordsError(f"Manifest is corrupt: {manifest}")


def _save_manifest(manifest: Path, data: dict) -> None:
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps(data, indent=2, sort_keys=True))


# ---------- core operations ----------
def encrypt_file(src: Path, dst: Path, key_path: Path = DEFAULT_KEY,
                 manifest: Path = DEFAULT_MANIFEST) -> str:
    _require_file(src, "Input file")
    key = load_key(key_path)
    plaintext = src.read_bytes()
    if not plaintext:
        raise SecureRecordsError("Input file is empty; nothing to encrypt.")
    nonce = os.urandom(NONCE_LEN)                 # unique per encryption
    ct = AESGCM(key).encrypt(nonce, plaintext, MAGIC)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(MAGIC + nonce + ct)
    digest = hashlib.sha256(plaintext).hexdigest()
    m = _load_manifest(manifest)
    m[str(src)] = digest                          # baseline hash of the original
    _save_manifest(manifest, m)
    return digest


def decrypt_file(src: Path, dst: Path, key_path: Path = DEFAULT_KEY) -> str:
    _require_file(src, "Encrypted file")
    key = load_key(key_path)
    blob = src.read_bytes()
    if len(blob) < len(MAGIC) + NONCE_LEN + 16 or not blob.startswith(MAGIC):
        raise SecureRecordsError("Not a valid encrypted file (bad header or too short).")
    nonce = blob[len(MAGIC):len(MAGIC) + NONCE_LEN]
    try:
        pt = AESGCM(key).decrypt(nonce, blob[len(MAGIC) + NONCE_LEN:], MAGIC)
    except InvalidTag:
        raise SecureRecordsError("Decryption failed: wrong key or the file was modified.")
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(pt)
    return hashlib.sha256(pt).hexdigest()


def record_hash(path: Path, manifest: Path = DEFAULT_MANIFEST) -> str:
    digest = sha256_file(path)
    m = _load_manifest(manifest)
    m[str(path)] = digest
    _save_manifest(manifest, m)
    return digest


def verify_hash(path: Path, manifest: Path = DEFAULT_MANIFEST) -> bool:
    current = sha256_file(path)
    m = _load_manifest(manifest)
    if str(path) not in m:
        raise SecureRecordsError(f"No stored hash for {path}. Run 'hash' or 'encrypt' first.")
    return current == m[str(path)]


def verify_roundtrip(original: Path, decrypted: Path) -> bool:
    return sha256_file(original) == sha256_file(decrypted)


# ---------- CLI ----------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--key", type=Path, default=DEFAULT_KEY, help="key file (default: %(default)s)")
    p.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST, help="hash manifest (default: %(default)s)")
    sub = p.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen", help="create a new 256-bit key outside the repo")
    k.add_argument("--force", action="store_true")
    for name in ("encrypt", "decrypt"):
        s = sub.add_parser(name)
        s.add_argument("input", type=Path)
        s.add_argument("output", type=Path)
    d = sub.add_parser("decrypt-verify", help="decrypt, then compare with the original")
    d.add_argument("encrypted", type=Path)
    d.add_argument("output", type=Path)
    d.add_argument("original", type=Path)
    for name in ("hash", "verify"):
        s = sub.add_parser(name)
        s.add_argument("file", type=Path)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "keygen":
            print(f"Key written to {generate_key(args.key, args.force)} (keep it out of Git)")
        elif args.cmd == "encrypt":
            h = encrypt_file(args.input, args.output, args.key, args.manifest)
            print(f"Encrypted {args.input} -> {args.output}\nSHA-256 of original: {h}")
        elif args.cmd == "decrypt":
            h = decrypt_file(args.input, args.output, args.key)
            print(f"Decrypted {args.input} -> {args.output}\nSHA-256 of result:   {h}")
        elif args.cmd == "decrypt-verify":
            decrypt_file(args.encrypted, args.output, args.key)
            ok = verify_roundtrip(args.original, args.output)
            print("MATCH: decrypted content is identical to the original" if ok
                  else "MISMATCH: decrypted content differs from the original")
            return 0 if ok else 2
        elif args.cmd == "hash":
            print(f"{record_hash(args.file, args.manifest)}  {args.file}")
        elif args.cmd == "verify":
            ok = verify_hash(args.file, args.manifest)
            print(f"UNCHANGED: {args.file}" if ok else f"MODIFIED: {args.file} no longer matches its stored hash")
            return 0 if ok else 2
    except SecureRecordsError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except PermissionError as e:
        print(f"Error: permission denied: {e.filename}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
