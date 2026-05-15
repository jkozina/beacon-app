from enricher.enricher import enrich


def test_enrich_orders_to_payments_builds_canonical_intent():
    derived = {
        "apiVersion": "network.company.com/v1",
        "kind": "NetworkIntent",
        "metadata": {"name": "orders-to-payments"},
        "spec": {
            "source": {
                "workloadId": "orders-api",
                "namespace": "orders",
                "serviceAccount": "orders-api"
            },
            "destination": {"fqdn": "payments-api.prod.company.internal"},
            "traffic": {"protocol": "TCP", "port": 443, "applicationProtocol": "HTTPS"},
            "purpose": {"businessJustification": "test", "ticket": "CHG1"},
            "lifecycle": {"requestedTtlDays": 30}
        }
    }
    enriched, snapshot, snapshot_hash = enrich(derived)
    assert enriched["spec"]["source"]["centralId"] == "app-orders"
    assert enriched["spec"]["destination"]["serviceId"] == "app-payments-api"
    assert enriched["spec"]["destination"]["resolution"]["confidence"] == "high"
    assert snapshot_hash.startswith("sha256:")
    assert len(snapshot_hash) == 71   # "sha256:" + 64 hex chars
    assert snapshot["source"]["centralId"] == "app-orders"
