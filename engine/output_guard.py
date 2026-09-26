"""
Layer 4: Output Guard & Canary Tripwire
Inspects model output before transmission to the client:
- Cryptographic Canary Token tripwire detection
- System Prompt extraction / leakage prevention
- Sensitive PII & API Secret Scanner (Regex & High-Entropy masking)
- Covert Exfiltration Channel (Markdown/HTML image URL stripping)
"""

import re
import time
from typing import List, Tuple
import config
from engine.models import SecurityEvent, GuardrailResult
from engine.canary_manager import CanaryManager

class OutputGuard:
    def __init__(self, canary_manager: CanaryManager):
        self.canary_manager = canary_manager
        self.secret_patterns = {k: re.compile(v) for k, v in config.SECRET_PATTERNS.items()}
        self.markdown_image_regex = re.compile(r"!\[([^\]]*)\]\((https?:\/\/[^\s\)]+)\)")

    def inspect(self, raw_output: str) -> GuardrailResult:
        start_time = time.perf_counter()
        reasons = []
        owasp = []
        events = []
        risk_level = "SAFE"
        action = "ALLOW"
        sanitized_output = raw_output

        # 1. Canary Token Tripwire (Instant CRITICAL response)
        tripped_canaries = self.canary_manager.scan_for_canaries(raw_output)
        if tripped_canaries:
            risk_level = "CRITICAL"
            action = "REDACTED"
            for token, desc in tripped_canaries:
                reasons.append(f"Canary Token Breach: System secret '{token}' ({desc}) detected in generation output.")
            owasp.append("LLM02: Sensitive Info Disclosure")
            events.append(SecurityEvent(
                risk_level="CRITICAL",
                owasp_category="LLM02: Sensitive Info Disclosure",
                layer="Layer 4: Output Guard",
                action="REDACTED",
                trigger=f"Canary Tripped: {tripped_canaries[0][0]}",
                target_payload="[REDACTED SYSTEM CANARY TOKEN]",
                mitigation_notes="Model output was immediately truncated and replaced with safe fallback",
                latency_ms=(time.perf_counter() - start_time) * 1000
            ))
            # Critical leak: completely replace output to protect system secrets
            sanitized_output = (
                "[SECURITY BREACH CONTAINED BY AEGIS-AI]: The system detected an unauthorized attempt "
                "to leak confidential internal system credentials or canary tokens. The output was blocked."
            )
            return GuardrailResult(
                allowed=False,
                risk_level=risk_level,
                action=action,
                modified_content=sanitized_output,
                reasons=reasons,
                owasp_categories=owasp,
                events=events,
                inspection_latency_ms=(time.perf_counter() - start_time) * 1000
            )

        # 2. System Prompt & Master API Key Leakage check
        sys_leak_match = self.secret_patterns["SYSTEM_PROMPT_LEAK"].search(sanitized_output)
        if sys_leak_match:
            risk_level = "CRITICAL"
            action = "REDACTED"
            reasons.append("Proprietary system prompt disclosure detected in generation stream.")
            if "LLM02: Sensitive Info Disclosure" not in owasp:
                owasp.append("LLM02: Sensitive Info Disclosure")
            events.append(SecurityEvent(
                risk_level="CRITICAL",
                owasp_category="LLM02: Sensitive Info Disclosure",
                layer="Layer 4: Output Guard",
                action="REDACTED",
                trigger="System Prompt Verbatim Leakage",
                target_payload=sys_leak_match.group(0),
                mitigation_notes="Truncated system prompt leak",
                latency_ms=(time.perf_counter() - start_time) * 1000
            ))
            sanitized_output = (
                "[SECURITY CONTAINMENT]: Output contained internal system prompt directives. "
                "Redacted by Aegis-AI Output Guard."
            )
            return GuardrailResult(
                allowed=False,
                risk_level=risk_level,
                action=action,
                modified_content=sanitized_output,
                reasons=reasons,
                owasp_categories=owasp,
                events=events,
                inspection_latency_ms=(time.perf_counter() - start_time) * 1000
            )

        # 3. PII & Secret Redaction (SSN, Credit Cards, API Keys)
        for pattern_name, regex in self.secret_patterns.items():
            if pattern_name in ["CANARY_TOKEN", "SYSTEM_PROMPT_LEAK"]:
                continue
            matches = regex.findall(sanitized_output)
            if matches:
                risk_level = "HIGH"
                action = "REDACTED"
                reasons.append(f"Exposed {pattern_name} detected and redacted from model response.")
                if "LLM02: Sensitive Info Disclosure" not in owasp:
                    owasp.append("LLM02: Sensitive Info Disclosure")
                # Redact match
                sanitized_output = regex.sub(f"[REDACTED_{pattern_name}]", sanitized_output)
                events.append(SecurityEvent(
                    risk_level="HIGH",
                    owasp_category="LLM02: Sensitive Info Disclosure",
                    layer="Layer 4: Output Guard",
                    action="REDACTED",
                    trigger=f"Exposed {pattern_name}",
                    target_payload=f"Redacted {len(matches)} instance(s)",
                    mitigation_notes=f"Replaced sensitive {pattern_name} with safe redaction placeholder",
                    latency_ms=(time.perf_counter() - start_time) * 1000
                ))

        # 4. Outbound Markdown Image Exfiltration Channel Neutralization
        images = self.markdown_image_regex.findall(sanitized_output)
        for alt_text, url in images:
            risk_level = "HIGH"
            action = "SANITIZED"
            sanitized_output = sanitized_output.replace(f"![{alt_text}]({url})", f"[IMAGE_EXFILTRATION_PREVENTED: {alt_text}]")
            reasons.append(f"Blocked unauthorized outbound markdown image render to '{url}'.")
            if "LLM02: Sensitive Info Disclosure" not in owasp:
                owasp.append("LLM02: Sensitive Info Disclosure")
            events.append(SecurityEvent(
                risk_level="HIGH",
                owasp_category="LLM02: Sensitive Info Disclosure",
                layer="Layer 4: Output Guard",
                action="SANITIZED",
                trigger=f"Markdown Image Render: {url}",
                target_payload=url,
                mitigation_notes="Sanitized covert image exfiltration channel",
                latency_ms=(time.perf_counter() - start_time) * 1000
            ))

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return GuardrailResult(
            allowed=True,
            risk_level=risk_level,
            action=action,
            modified_content=sanitized_output,
            reasons=reasons,
            owasp_categories=owasp,
            events=events,
            inspection_latency_ms=elapsed_ms
        )
