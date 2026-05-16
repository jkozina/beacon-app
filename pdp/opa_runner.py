import json
import subprocess
from pathlib import Path

BUNDLE_PATH = Path(__file__).parent.parent / "bundle" / "bundle.tar.gz"


class OpaError(RuntimeError):
    pass


def evaluate(canonical_input: dict) -> dict:
    """Invoke `opa eval` against the bundled policy. Returns {allow, deny, controls?, ...}."""
    if not BUNDLE_PATH.exists():
        raise OpaError(f"Bundle missing at {BUNDLE_PATH}")

    cmd = [
        "opa", "eval",
        "--bundle", str(BUNDLE_PATH),
        "--stdin-input",
        "--format", "json",
        "data.beacon.verdict",
    ]
    try:
        proc = subprocess.run(
            cmd,
            input=json.dumps(canonical_input).encode("utf-8"),
            capture_output=True,
            check=False,
            timeout=5,
        )
    except subprocess.TimeoutExpired as e:
        raise OpaError("opa eval timed out after 5s") from e
    if proc.returncode != 0:
        raise OpaError(f"opa eval failed: {proc.stderr.decode()}")

    raw = json.loads(proc.stdout)
    # opa eval output: {"result": [{"expressions": [{"value": {...}, ...}]}]}
    try:
        value = raw["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError) as e:
        raise OpaError(f"Unexpected OPA output: {raw}") from e

    return {
        "allow": bool(value.get("allow", False)),
        "deny": list(value.get("deny", [])),
        "matchedRules": _matched_rules(value),
        "controls": value.get("controls", {}),
    }


def _matched_rules(value: dict) -> list[str]:
    """Combine deny IDs and OPA-emitted matchedRules into a deduped list."""
    out = set()
    out.update(d.get("id") for d in value.get("deny", []) if d.get("id"))
    out.update(value.get("matchedRules", []) or [])
    return sorted(out)
