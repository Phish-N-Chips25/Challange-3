"""
Pydantic request / response models for the FastAPI service.
"""
from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class SysmonEvent(BaseModel):
    """A single Sysmon event row (all fields optional — missing values filled downstream)."""
    EventID: Optional[int] = None
    EventType: Optional[str] = None
    Computer: Optional[str] = None
    User: Optional[str] = None
    Image: Optional[str] = None
    CommandLine: Optional[str] = None
    ParentImage: Optional[str] = None
    ParentCommandLine: Optional[str] = None
    TargetFilename: Optional[str] = None
    TargetObject: Optional[str] = None
    DestinationIp: Optional[str] = None
    DestinationPort: Optional[int] = None
    SourceIp: Optional[str] = None
    SourcePort: Optional[int] = None
    ProcessGuid: Optional[str] = None
    ProcessId: Optional[int] = None
    Hashes: Optional[str] = None
    Signed: Optional[bool] = None
    Signature: Optional[str] = None
    IntegrityLevel: Optional[str] = None
    CurrentDirectory: Optional[str] = None
    Details: Optional[str] = None

    class Config:
        extra = "allow"  # Pass through any additional fields not listed above


class BatchInferRequest(BaseModel):
    """Batch of raw Sysmon events for inference."""
    events: list[SysmonEvent] = Field(..., min_length=1, max_length=1024,
                                       description="List of Sysmon events (max 1024)")
    use_judge: bool = Field(False, description="Enable LLM-as-judge scoring (LLM endpoint only)")


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class TechniqueHit(BaseModel):
    technique_id: str
    technique_name: str
    count: int


class ClassicAlertResponse(BaseModel):
    pipeline: str = "classic"
    window_size: int
    anomaly_score: float = Field(..., ge=0.0, le=1.0,
                                  description="Normalised anomaly score [0, 1]")
    is_anomaly: bool
    techniques: list[TechniqueHit] = []
    latency_ms: float


class JudgeScore(BaseModel):
    detection_accuracy: int = Field(..., ge=1, le=10)
    technique_mapping: int = Field(..., ge=1, le=10)
    explanation_quality: int = Field(..., ge=1, le=10)
    false_positive_risk: int = Field(..., ge=1, le=10)
    action_appropriateness: int = Field(..., ge=1, le=10)
    overall_score: float
    commentary: str


class LLMAlertResponse(BaseModel):
    pipeline: str = "llm"
    window_size: int
    anomaly_detected: bool
    anomaly_score: Optional[float] = None
    techniques: list[str] = []
    severity: Optional[str] = None
    explanation: Optional[str] = None
    recommended_action: Optional[str] = None
    judge_scores: Optional[JudgeScore] = None
    latency_ms: float


class HealthResponse(BaseModel):
    status: str
    classic_ready: bool
    llm_ready: bool
    kafka_ready: bool
