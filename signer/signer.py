import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

KEYS_DIR = Path(__file__).parent.parent / "keys"
PRIVATE_KEY_PATH = KEYS_DIR / "verdict-signing.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "verdict-signing.pub"


def canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def load_private_key() -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(PRIVATE_KEY_PATH.read_bytes(), password=None)  # type: ignore[return-value]


def load_public_key() -> Ed25519PublicKey:
    return serialization.load_pem_public_key(PUBLIC_KEY_PATH.read_bytes())  # type: ignore[return-value]


def sign(verdict: dict) -> str:
    # Exclude the signature field from the signed payload.
    payload = {k: v for k, v in verdict.items() if k != "signature"}
    key = load_private_key()
    sig = key.sign(canonical_json(payload))
    return "beacon-signature:v1:" + base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")


def verify(verdict: dict, signature: str) -> bool:
    if not signature.startswith("beacon-signature:v1:"):
        return False
    raw = signature[len("beacon-signature:v1:"):]
    raw += "=" * (-len(raw) % 4)  # pad b64
    sig_bytes = base64.urlsafe_b64decode(raw)
    payload = {k: v for k, v in verdict.items() if k != "signature"}
    try:
        load_public_key().verify(sig_bytes, canonical_json(payload))
        return True
    except InvalidSignature:
        return False
