import json


def canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(verdict: dict) -> str:
    """Stub for Phase 1. Phase 3 replaces with real Ed25519 signing."""
    return "beacon-signature:stub:v0"
