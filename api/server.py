from fastapi import FastAPI, HTTPException

from api.models import VerdictRequest, VerdictResponse
from orchestrator.pipeline import run_pipeline
from resolver.resolver import DestinationNotFound

app = FastAPI(title="beacon-app", version="0.1.0")


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
    return VerdictResponse(**envelope)
