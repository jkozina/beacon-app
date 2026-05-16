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
