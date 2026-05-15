import json
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "destinations"


class DestinationNotFound(Exception):
    pass


def resolve(fqdn: str) -> dict:
    """Resolve an FQDN to a canonical destination identity via fixture lookup."""
    fixture_path = FIXTURES_DIR / f"{fqdn}.json"
    if not fixture_path.exists():
        raise DestinationNotFound(f"No fixture for fqdn={fqdn!r}; tried {fixture_path}")
    with fixture_path.open() as fh:
        return json.load(fh)
