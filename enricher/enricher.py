import hashlib
import json
from pathlib import Path

from resolver.resolver import resolve

SOURCES_DIR = Path(__file__).parent.parent / "fixtures" / "sources"


def _canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_source_fixture(workload_id: str) -> dict:
    # workload_id -> fixture filename, simple mapping for the POC
    name_map = {"orders-api": "orders.json"}
    path = SOURCES_DIR / name_map.get(workload_id, f"{workload_id}.json")
    if not path.exists():
        raise FileNotFoundError(f"No source fixture for workload_id={workload_id!r}")
    with path.open() as fh:
        return json.load(fh)


def enrich(derived_intent: dict) -> tuple[dict, dict, str]:
    """Returns (enriched_intent, enrichment_snapshot, snapshot_hash)."""
    src = derived_intent["spec"]["source"]
    dst_fqdn = derived_intent["spec"]["destination"]["fqdn"]

    source_meta = _load_source_fixture(src["workloadId"])
    destination_meta = resolve(dst_fqdn)

    # Build the canonical enriched NetworkIntent (intent-model.md shape).
    enriched = {
        "apiVersion": derived_intent["apiVersion"],
        "kind": derived_intent["kind"],
        "metadata": derived_intent["metadata"],
        "spec": {
            "source": {**src, **source_meta},
            "destination": {
                **destination_meta,
                "requestedFqdn": destination_meta["requestedFqdn"],
            },
            "traffic": derived_intent["spec"]["traffic"],
            "purpose": derived_intent["spec"].get("purpose", {}),
            "lifecycle": derived_intent["spec"].get("lifecycle", {}),
            "path": _expected_path(source_meta, destination_meta),
        }
    }

    snapshot = {
        "source": source_meta,
        "destination": destination_meta,
    }
    snapshot_hash = "sha256:" + hashlib.sha256(_canonical_json(snapshot)).hexdigest()

    return enriched, snapshot, snapshot_hash


def _expected_path(source: dict, destination: dict) -> dict:
    """Derive the expected primary + transitive control set."""
    return {
        "preferredPrimaryControl": "istio-service-entry",
        "expectedPrimaryControls": ["istio-service-entry"],
        "requiredTransitiveControls": ["equinix-pa", "onprem-fabric-pa", "illumio"],
        "inspectionRequired": destination.get("complianceDomain") == "pci",
        "expectedRoute": {
            "sourceZone": source.get("trustZone"),
            "destinationZone": destination.get("trustZone"),
        }
    }
