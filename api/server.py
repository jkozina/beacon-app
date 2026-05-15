from datetime import datetime, timezone
from fastapi import FastAPI

from api.models import VerdictRequest, VerdictResponse, Controls

app = FastAPI(title="beacon-app", version="0.1.0")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/verdict", response_model=VerdictResponse)
def verdict(req: VerdictRequest) -> VerdictResponse:
    # Phase 1: hardcoded allow. Phase 1 Task 1.5 replaces this with the real pipeline.
    return VerdictResponse(
        decisionId="dec-stub-0001",
        allow=True,
        policyBundle="beacon-policy:stub",
        evaluatedAt=datetime.now(timezone.utc).isoformat(),
        implementationHash=req.implementationContext.hash,
        metadataSnapshotHash="sha256:stub",
        controls=Controls(),
        canonicalRequest={"stub": True},
        enrichmentSnapshot={"stub": True},
    )
