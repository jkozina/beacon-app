import shutil
import tarfile
from pathlib import Path

import pytest
from pdp.bundle_verifier import verify_bundle, BundleSignatureError


def test_verify_signed_bundle_passes(tmp_path: Path):
    # Use the real bundle from beacon-policy build output.
    bundle = Path(__file__).parent.parent / "bundle" / "bundle.tar.gz"
    pubkey = Path(__file__).parent.parent / "keys" / "bundle-signing.pub"
    assert verify_bundle(bundle, pubkey) is True


def test_verify_tampered_bundle_fails(tmp_path: Path):
    src = Path(__file__).parent.parent / "bundle" / "bundle.tar.gz"
    pubkey = Path(__file__).parent.parent / "keys" / "bundle-signing.pub"
    tampered = tmp_path / "tampered.tar.gz"
    # Flip one byte in the data portion
    raw = src.read_bytes()
    tampered.write_bytes(raw[:100] + bytes([raw[100] ^ 0xFF]) + raw[101:])
    with pytest.raises(BundleSignatureError):
        verify_bundle(tampered, pubkey)
