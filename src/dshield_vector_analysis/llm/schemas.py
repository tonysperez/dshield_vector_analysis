"""Pydantic models for LLM-structured output."""
from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, Field, field_validator

INTENTS = {
    "reconnaissance", "initial_access", "execution", "persistence",
    "privilege_escalation", "defense_evasion", "credential_access",
    "discovery", "lateral_movement", "collection", "command_and_control",
    "exfiltration", "impact", "cryptomining", "benign", "unknown",
}


class IOCs(BaseModel):
    urls: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    files: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)


class CommandEnrichment(BaseModel):
    description: str
    intent: str
    tactics: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    iocs: IOCs = Field(default_factory=IOCs)
    confidence: int = 1  # 1-10 scale, see prompt for anchors

    @field_validator("intent")
    @classmethod
    def _intent_in_set(cls, v: str) -> str:
        v2 = v.strip().lower()
        return v2 if v2 in INTENTS else "unknown"

    @field_validator("confidence", mode="before")
    @classmethod
    def _coerce_confidence(cls, v) -> int:
        # Accept ints, floats, and stringified numbers. Clamp 1..10.
        try:
            n = float(v)
        except (TypeError, ValueError):
            return 1
        # If a model returns 0..1 (legacy float), rescale to 1..10
        if 0.0 <= n <= 1.0 and not isinstance(v, int):
            n = n * 10
        return max(1, min(10, int(round(n))))

    @field_validator("tactics", "techniques")
    @classmethod
    def _strip_upper(cls, v: list[str]) -> list[str]:
        return [s.strip().upper() for s in v if s and s.strip()]


class CloudCommandEnrichment(CommandEnrichment):
    """Cloud (Claude) variant adds optional analyst notes (actor/campaign hypotheses)."""
    notes: str = ""
