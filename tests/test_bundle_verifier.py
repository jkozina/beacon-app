import gzip
import io
import tarfile
from pathlib import Path

import pytest
from pdp.bundle_verifier import verify_bundle, BundleSignatureError

BUNDLE = Path(__file__).parent.parent / "bundle" / "bundle.tar.gz"
PUBKEY = Path(__file__).parent.parent / "keys" / "bundle-signing.pub"


def test_verify_signed_bundle_passes():
    assert verify_bundle(BUNDLE, PUBKEY) is True


def test_verify_tampered_gzip_stream_fails(tmp_path: Path):
    # Flip a byte in the gzip stream; tarfile.open should reject it.
    tampered = tmp_path / "tampered-gz.tar.gz"
    raw = BUNDLE.read_bytes()
    tampered.write_bytes(raw[:100] + bytes([raw[100] ^ 0xFF]) + raw[101:])
    with pytest.raises(BundleSignatureError):
        verify_bundle(tampered, PUBKEY)


def test_verify_tampered_policy_content_fails(tmp_path: Path):
    # Mid-content tamper: extract, rewrite a policy file, repack. The tar+JWS
    # remain internally consistent but the file's actual sha256 no longer
    # matches the digest in the JWS payload. Without files[] verification this
    # would silently pass.
    tampered_tar = tmp_path / "tampered-content.tar"
    with tarfile.open(BUNDLE, "r:gz") as src, tarfile.open(tampered_tar, "w") as dst:
        for member in src.getmembers():
            if member.name.lstrip("/") == "policy/enterprise/ttl.rego":
                buf = src.extractfile(member).read()
                buf = buf.replace(b"TTL_EXCEEDS_MAX", b"TTL_EXCEEDS_HAH")  # same length
                member.size = len(buf)
                dst.addfile(member, io.BytesIO(buf))
            else:
                dst.addfile(member, src.extractfile(member) if member.isfile() else None)
    tampered_gz = tmp_path / "tampered-content.tar.gz"
    tampered_gz.write_bytes(gzip.compress(tampered_tar.read_bytes()))
    with pytest.raises(BundleSignatureError, match="hash mismatch"):
        verify_bundle(tampered_gz, PUBKEY)


def test_verify_wrong_public_key_fails(tmp_path: Path):
    # Generate a fresh RSA key with no relation to the signing key.
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    wrong_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_pub = wrong_priv.public_key()
    wrong_path = tmp_path / "wrong.pub"
    wrong_path.write_bytes(wrong_pub.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    with pytest.raises(BundleSignatureError, match="Signature verification failed"):
        verify_bundle(BUNDLE, wrong_path)


def test_verify_smuggled_extra_file_fails(tmp_path: Path):
    # Add a new policy file the JWS payload doesn't list. Even though the JWS
    # still verifies (its payload is unchanged), the bundle now carries a rule
    # not covered by the signed manifest — the verifier should reject it.
    extra_tar = tmp_path / "extra.tar"
    with tarfile.open(BUNDLE, "r:gz") as src, tarfile.open(extra_tar, "w") as dst:
        for member in src.getmembers():
            dst.addfile(member, src.extractfile(member) if member.isfile() else None)
        evil = b'package beacon.verdict\n\nallow := true\n'
        info = tarfile.TarInfo(name="/policy/sneaky.rego")
        info.size = len(evil)
        dst.addfile(info, io.BytesIO(evil))
    extra_gz = tmp_path / "extra.tar.gz"
    extra_gz.write_bytes(gzip.compress(extra_tar.read_bytes()))
    with pytest.raises(BundleSignatureError, match="not in signed manifest"):
        verify_bundle(extra_gz, PUBKEY)
