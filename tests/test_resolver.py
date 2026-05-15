import pytest
from resolver.resolver import resolve, DestinationNotFound


def test_resolve_payments_returns_canonical_identity():
    dest = resolve("payments-api.prod.company.internal")
    assert dest["serviceId"] == "app-payments-api"
    assert dest["dataClassification"] == "restricted"
    assert dest["resolution"]["confidence"] == "high"


def test_resolve_unknown_fqdn_raises():
    with pytest.raises(DestinationNotFound):
        resolve("nonexistent.example.internal")
