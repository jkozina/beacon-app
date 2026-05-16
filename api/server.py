from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException

from api.models import VerdictRequest, VerdictResponse
from orchestrator.pipeline import run_pipeline
from pdp.bundle_verifier import verify_bundle, BundleSignatureError
from resolver.resolver import DestinationNotFound
from signer.signer import sign


@asynccontextmanager
async def lifespan(app):
    bundle = Path(__file__).parent.parent / "bundle" / "bundle.tar.gz"
    pubkey = Path(__file__).parent.parent / "keys" / "bundle-signing.pub"
    try:
        verify_bundle(bundle, pubkey)
        print(f"[beacon-app] bundle verified: {bundle}", flush=True)
    except BundleSignatureError as e:
        print(f"[beacon-app] FATAL: bundle signature verification failed: {e}", flush=True)
        raise SystemExit(2)
    yield


app = FastAPI(title="beacon-app", version="0.1.0", lifespan=lifespan)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/verdict", response_model=VerdictResponse)
def verdict(req: VerdictRequest) -> VerdictResponse:
    try:
        envelope = run_pipeline(
            req.derivedIntent.model_dump(),
            req.implementationContext.model_dump(),
        )
    except DestinationNotFound as e:
        raise HTTPException(status_code=400, detail=f"unresolvable_destination: {e}") from e
    # Sign the wire-shaped payload (after Pydantic normalization) so the bytes
    # we sign equal the bytes we ship. Without the round-trip, Pydantic's
    # default factories (e.g. Controls) expand {} into {"primary":null,...}
    # and the consumer-side verify always fails.
    response = VerdictResponse(**envelope)
    response.signature = sign(response.model_dump())
    return response
