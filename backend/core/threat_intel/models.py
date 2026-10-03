from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    CVE = "cve"


class ReputationLevel(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class ProviderStatus(str, Enum):
    ONLINE = "online"
    NO_KEY = "no_key"
    DEGRADED = "degraded"
    OFFLINE = "offline"


class ProviderResult(BaseModel):
    provider_name: str
    indicator: str
    indicator_type: IndicatorType
    reputation: ReputationLevel = ReputationLevel.UNKNOWN
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    details: dict[str, Any] = Field(default_factory=dict)
    raw_data: dict[str, Any] | None = None
    source_url: str | None = None
    queried_at: str
    latency_ms: float = 0.0
    error: str | None = None


class EnrichedIndicator(BaseModel):
    indicator: str
    indicator_type: IndicatorType
    overall_reputation: ReputationLevel = ReputationLevel.UNKNOWN
    overall_risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    max_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    provider_results: list[ProviderResult] = Field(default_factory=list)
    primary_provider: str | None = None
    cached: bool = False
    tags: list[str] = Field(default_factory=list)
    summary: str = ""
    extracted_from: str | None = None


class ProviderHealth(BaseModel):
    provider_name: str
    display_name: str
    status: ProviderStatus
    has_api_key: bool
    total_queries: int = 0
    successful_queries: int = 0
    failed_queries: int = 0
    avg_latency_ms: float = 0.0
    last_queried_at: str | None = None
    last_error: str | None = None
    supported_types: list[IndicatorType] = Field(default_factory=list)
    is_free_tier: bool = True
    rate_limit_info: str | None = None
