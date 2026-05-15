import copy

from pdp.opa_runner import evaluate


SAMPLE_INPUT = {
    "spec": {
        "source": {"environment": "prod"},
        "destination": {"dataClassification": "restricted"},
        "lifecycle": {"requestedTtlDays": 120}
    }
}


def test_evaluate_returns_deny_for_long_ttl():
    result = evaluate(copy.deepcopy(SAMPLE_INPUT))
    assert result["allow"] is False
    deny_ids = [d["id"] for d in result["deny"]]
    assert "TTL_EXCEEDS_MAX" in deny_ids


def test_evaluate_returns_allow_for_short_ttl():
    short = copy.deepcopy(SAMPLE_INPUT)
    short["spec"]["lifecycle"]["requestedTtlDays"] = 30
    result = evaluate(short)
    assert result["allow"] is True
