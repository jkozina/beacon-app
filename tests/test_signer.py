from signer.signer import sign, canonical_json, load_private_key, verify


def test_sign_and_verify_round_trip():
    verdict = {"decisionId": "dec-1", "allow": True, "z": 1, "a": 2}
    sig = sign(verdict)
    assert sig.startswith("beacon-signature:v1:")
    assert verify(verdict, sig) is True


def test_verify_rejects_tampered_verdict():
    verdict = {"decisionId": "dec-1", "allow": True}
    sig = sign(verdict)
    tampered = dict(verdict, allow=False)
    assert verify(tampered, sig) is False


def test_canonical_json_is_sorted():
    a = canonical_json({"b": 1, "a": 2})
    b = canonical_json({"a": 2, "b": 1})
    assert a == b


def test_e2e_wire_signature_verifies_against_returned_body():
    # Regression for the bug where pipeline.py signed the raw orchestrator dict
    # but FastAPI's response_model expanded Pydantic defaults (e.g. Controls
    # default_factory), making the on-the-wire bytes differ from the signed
    # bytes. The action's consumer-side verify (Task 3.3) would fail 100%.
    from fastapi.testclient import TestClient
    from api.server import app

    client = TestClient(app)
    response = client.post("/v1/verdict", json={
        "derivedIntent": {
            "apiVersion": "network.company.com/v1", "kind": "NetworkIntent",
            "metadata": {"name": "orders-to-payments"},
            "spec": {
                "source": {"workloadId": "orders-api", "namespace": "orders", "serviceAccount": "orders-api"},
                "destination": {"fqdn": "payments-api.prod.company.internal"},
                "traffic": {"protocol": "TCP", "port": 443, "applicationProtocol": "HTTPS"},
                "purpose": {"businessJustification": "test", "ticket": "CHG1"},
                "lifecycle": {"requestedTtlDays": 30},
            },
        },
        "implementationContext": {
            "hash": "sha256:stub", "repository": "x/y", "pullRequest": 1,
            "commit": "abc", "actor": "u", "workflowRunId": "1", "implementationFiles": ["a"],
        },
    })
    assert response.status_code == 200
    body = response.json()
    sig = body["signature"]
    assert sig.startswith("beacon-signature:v1:")
    assert verify(body, sig) is True, (
        "Wire signature must verify against the wire body. If this fails, the "
        "signing layer is signing a different shape than what gets serialized."
    )
