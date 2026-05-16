import uuid
from datetime import datetime, timedelta, timezone

from enricher.enricher import enrich
from pdp.opa_runner import evaluate

BUNDLE_REVISION = "beacon-policy:v2026.05.03"
DEFAULT_TTL_DAYS = 30


def run_pipeline(derived_intent: dict, implementation_context: dict) -> dict:
    """Resolve, enrich, evaluate. Returns the unsigned verdict envelope; signing
    happens in the API layer (server.py) so the bytes signed match the bytes
    serialized on the wire after Pydantic normalization."""
    enriched, snapshot, snapshot_hash = enrich(derived_intent)

    opa_result = evaluate(enriched)
    allow = opa_result["allow"]
    deny_reasons = opa_result["deny"]

    requested_ttl = derived_intent["spec"].get("lifecycle", {}).get("requestedTtlDays", DEFAULT_TTL_DAYS)
    evaluated_at = datetime.now(timezone.utc)
    expires_at = evaluated_at + timedelta(days=requested_ttl) if allow else None

    return {
        "decisionId": f"dec-{uuid.uuid4().hex[:8]}",
        "allow": allow,
        "policyBundle": BUNDLE_REVISION,
        "evaluatedAt": evaluated_at.isoformat(),
        "expiresAt": expires_at.isoformat() if expires_at else None,
        "implementationHash": implementation_context["hash"],
        "metadataSnapshotHash": snapshot_hash,
        "denyReasons": deny_reasons,
        "matchedRules": opa_result["matchedRules"],
        "controls": opa_result.get("controls", {}),
        "canonicalRequest": enriched,
        "enrichmentSnapshot": snapshot,
    }
