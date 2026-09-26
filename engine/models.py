"""
Data models for AegisAI Defense Gateway
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid

@dataclass
class SecurityEvent:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = field(default_factory=lambda: datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
    risk_level: str = "INFO"  # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    owasp_category: str = "N/A"  # e.g., LLM01: Prompt Injection, LLM02: Sensitive Info, LLM06: Excessive Agency
    layer: str = "Gateway"       # Layer 1: Input Guard, Layer 2: RAG Sanitizer, Layer 3: Tool Firewall, Layer 4: Output Guard
    action: str = "ALLOW"        # ALLOW, BLOCKED, SANITIZED, REDACTED, FLAGGED
    trigger: str = ""
    target_payload: str = ""
    mitigation_notes: str = ""
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class GuardrailResult:
    allowed: bool
    risk_level: str
    action: str
    modified_content: str
    reasons: List[str] = field(default_factory=list)
    owasp_categories: List[str] = field(default_factory=list)
    events: List[SecurityEvent] = field(default_factory=list)
    inspection_latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "risk_level": self.risk_level,
            "action": self.action,
            "modified_content": self.modified_content,
            "reasons": self.reasons,
            "owasp_categories": self.owasp_categories,
            "events": [e.to_dict() for e in self.events],
            "inspection_latency_ms": round(self.inspection_latency_ms, 2)
        }

@dataclass
class AttackScenario:
    id: str
    title: str
    category: str
    owasp_id: str
    description: str
    attacker_persona: str
    user_prompt: str
    retrieved_context: Optional[str] = None
    target_tool_call: Optional[Dict[str, Any]] = None
    expected_vulnerable_outcome: str = ""
    expected_defended_outcome: str = ""
    is_adversarial: bool = True  # False for benign test controls
