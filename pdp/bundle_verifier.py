import base64
import json
import tarfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.exceptions import InvalidSignature


class BundleSignatureError(Exception):
    pass


def _b64url_pad(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def verify_bundle(bundle_path: Path, public_key_path: Path) -> bool:
    """Verify OPA bundle's .signatures.json JWS against the RSA public key.

    OPA's bundle signing uses JWS with RS256 by default. Each entry in
    `.signatures.json.signatures[*].signed` is a JWS compact serialization.
    """
    if not bundle_path.exists():
        raise BundleSignatureError(f"Bundle missing: {bundle_path}")

    try:
        with tarfile.open(bundle_path, "r:gz") as tf:
            # OPA writes bundle entries with a leading slash (e.g. "/.signatures.json"),
            # but normal tar tools would name them ".signatures.json". Accept either.
            sig_member = None
            for candidate in (".signatures.json", "/.signatures.json"):
                try:
                    sig_member = tf.getmember(candidate)
                    break
                except KeyError:
                    continue
            if sig_member is None:
                raise BundleSignatureError("Bundle is not signed (no .signatures.json)")
            with tf.extractfile(sig_member) as fh:  # type: ignore[union-attr]
                sigfile = json.load(fh)
    except tarfile.TarError as e:
        # A corrupt/truncated archive can't be a validly signed bundle.
        raise BundleSignatureError(f"Bundle is not a readable tar.gz: {e}") from e

    if not sigfile.get("signatures"):
        raise BundleSignatureError("No signatures in bundle")

    pubkey = serialization.load_pem_public_key(public_key_path.read_bytes())
    if not isinstance(pubkey, RSAPublicKey):
        raise BundleSignatureError("Public key is not RSA")

    for entry in sigfile["signatures"]:
        # OPA 0.x stored each entry as an object with `signed`/`signature` fields;
        # OPA 1.x stores each entry as a single compact JWS string. Handle both.
        if isinstance(entry, str):
            compact = entry
        elif "signature" in entry:
            compact = entry["signed"] + "." + entry["signature"]
        else:
            compact = entry["signed"]
        # Compact JWS form: header.payload.signature
        parts = compact.split(".")
        if len(parts) != 3:
            raise BundleSignatureError(f"Malformed JWS: {compact[:40]}...")
        header_b64, payload_b64, signature_b64 = parts
        signed_bytes = (header_b64 + "." + payload_b64).encode("ascii")
        signature = _b64url_pad(signature_b64)
        try:
            pubkey.verify(signature, signed_bytes, PKCS1v15(), hashes.SHA256())
        except InvalidSignature as e:
            raise BundleSignatureError(f"Signature verification failed for {entry.get('keyid') if isinstance(entry, dict) else 'jws-string'}") from e
    return True
