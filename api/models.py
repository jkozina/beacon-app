from typing import Any, Optional
from pydantic import BaseModel, Field


class ImplementationContext(BaseModel):
    hash: str
    repository: str
    pullRequest: int
    commit: str
    actor: str
    workflowRunId: str
    implementationFiles: list[str]


class DerivedIntent(BaseModel):
    apiVersion: str
    kind: str
    metadata: dict[str, Any]
    spec: dict[str, Any]


class VerdictRequest(BaseModel):
    derivedIntent: DerivedIntent
    implementationContext: ImplementationContext
    policyMode: str = "enforce"


class Control(BaseModel):
    type: str
    owner: str
    target: str
    reason: Optional[str] = None


class Controls(BaseModel):
    primary: Optional[Control] = None
    transitive: list[Control] = Field(default_factory=list)


class DenyReason(BaseModel):
    id: str
    message: str


class VerdictResponse(BaseModel):
    decisionId: str
    allow: bool
    policyBundle: str
    evaluatedAt: str
    expiresAt: Optional[str] = None
    implementationHash: str
    metadataSnapshotHash: str
    denyReasons: list[DenyReason] = Field(default_factory=list)
    matchedRules: list[str] = Field(default_factory=list)
    controls: Controls = Field(default_factory=Controls)
    canonicalRequest: dict[str, Any]
    enrichmentSnapshot: dict[str, Any]
    signature: str = ""   # filled in Phase 3
