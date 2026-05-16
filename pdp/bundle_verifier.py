import base64
import hashlib
import json
import tarfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.exceptions import InvalidSignature


class BundleSignatureError(Exception):
    pass


def _b64url_pad(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _hash_bytes(algorithm: str, data: bytes) -> str:
    algo = algorithm.lower().replace("-", "")
    try:
        h = hashlib.new(algo)
    except ValueError as e:
        raise BundleSignatureError(f"Unsupported file-hash algorithm in JWS payload: {algorithm!r}") from e
    h.update(data)
    return h.hexdigest()


def _normalize_member(name: str) -> str:
    """OPA writes tar members as '/foo/bar' and JWS payload lists them as 'foo/bar'.
    Strip the leading slash to compare apples to apples."""
    return name.lstrip("/")


def _file_hash(name: str, raw: bytes, algorithm: str) -> str:
    """OPA canonicalizes JSON files before hashing (sort_keys, no whitespace);
    non-JSON files (.rego) are hashed by raw bytes. Mirroring OPA's behavior
    is the only way for the verifier's digests to match the JWS payload."""
    if name.endswith(".json") or name == ".manifest":
        try:
            obj = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise BundleSignatureError(f"Cannot parse {name!r} as JSON for canonicalization: {e}") from e
        canonical = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return _hash_bytes(algorithm, canonical)
    return _hash_bytes(algorithm, raw)


def verify_bundle(bundle_path: Path, public_key_path: Path) -> bool:
    """Verify OPA bundle's RS256 signature AND file-content integrity.

    Two-stage check (refuses to serve on any failure):
      1. The JWS in `.signatures.json` verifies against the RSA public key.
      2. Every file the JWS payload claims (`files[]`) is present in the tar with
         a matching content hash. (Without #2, an attacker who can rewrite policy
         bytes — without forging the JWS — would still pass verification, since
         the JWS only signs the digest manifest, not the files themselves.)
    """
    if not bundle_path.exists():
        raise BundleSignatureError(f"Bundle missing: {bundle_path}")

    try:
        with tarfile.open(bundle_path, "r:gz") as tf:
            # OPA writes bundle entries with a leading slash (e.g. "/.signatures.json"),
            # but normal tar tools would name them ".signatures.json". Accept either.
            sig_member = None
            for candidate in (".signatures.json", "/.signatures.json"):
                try:
                    sig_member = tf.getmember(candidate)
                    break
                except KeyError:
                    continue
            if sig_member is None:
                raise BundleSignatureError("Bundle is not signed (no .signatures.json)")
            with tf.extractfile(sig_member) as fh:  # type: ignore[union-attr]
                sigfile = json.load(fh)

            # Snapshot every non-signature member's bytes for the digest check below.
            # OPA bundles are small (few KB); this fully fits in memory.
            member_bytes: dict[str, bytes] = {}
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                norm = _normalize_member(member.name)
                if norm == ".signatures.json":
                    continue
                with tf.extractfile(member) as mh:  # type: ignore[union-attr]
                    member_bytes[norm] = mh.read()
    except (tarfile.TarError, json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
        # A corrupt/truncated archive or malformed signatures file can't be a
        # validly signed bundle; surface it as a clean signature error.
        raise BundleSignatureError(f"Bundle is not a readable signed tar.gz: {e}") from e

    if not sigfile.get("signatures"):
        raise BundleSignatureError("No signatures in bundle")

    pubkey = serialization.load_pem_public_key(public_key_path.read_bytes())
    if not isinstance(pubkey, RSAPublicKey):
        raise BundleSignatureError("Public key is not RSA")

    # Stage 1: verify every JWS signature and accumulate the claimed file digests.
    declared_files: dict[str, dict] = {}  # name -> {hash, algorithm}
    for entry in sigfile["signatures"]:
        # OPA 0.x stored each entry as an object with `signed`/`signature` fields;
        # OPA 1.x stores each entry as a single compact JWS string. Handle both.
        if isinstance(entry, str):
            compact = entry
        elif "signature" in entry:
            compact = entry["signed"] + "." + entry["signature"]
        else:
            compact = entry["signed"]
        # Compact JWS form: header.payload.signature
        parts = compact.split(".")
        if len(parts) != 3:
            raise BundleSignatureError(f"Malformed JWS: {compact[:40]}...")
        header_b64, payload_b64, signature_b64 = parts
        signed_bytes = (header_b64 + "." + payload_b64).encode("ascii")
        signature = _b64url_pad(signature_b64)
        try:
            pubkey.verify(signature, signed_bytes, PKCS1v15(), hashes.SHA256())
        except InvalidSignature as e:
            keyid = entry.get("keyid") if isinstance(entry, dict) else "jws-string"
            raise BundleSignatureError(f"Signature verification failed for {keyid}") from e
        # JWS verified; pull the file-digest manifest out of the payload.
        try:
            payload = json.loads(_b64url_pad(payload_b64))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise BundleSignatureError(f"JWS payload is not valid JSON: {e}") from e
        for f in payload.get("files", []):
            name = _normalize_member(f.get("name", ""))
            if not name:
                continue
            declared_files[name] = {"hash": f.get("hash"), "algorithm": f.get("algorithm", "SHA-256")}

    # Stage 2: verify the bundle's actual file contents match the JWS-signed digests.
    # No declared files = nothing to check beyond the JWS itself (unusual but not
    # something this layer should police; OPA's signing always emits files[]).
    for name, claim in declared_files.items():
        if name not in member_bytes:
            raise BundleSignatureError(f"Signed manifest lists {name!r} but tar does not contain it")
        actual = _file_hash(name, member_bytes[name], claim["algorithm"])
        if actual != claim["hash"]:
            raise BundleSignatureError(
                f"Content hash mismatch for {name!r}: manifest claims {claim['hash']}, "
                f"actual {actual} (algorithm={claim['algorithm']})"
            )
    # Also reject any file in the tar that is not in the signed manifest — prevents
    # an attacker from smuggling extra rules past the verifier.
    extras = set(member_bytes) - set(declared_files)
    if extras:
        raise BundleSignatureError(f"Bundle contains files not in signed manifest: {sorted(extras)}")
    return True
