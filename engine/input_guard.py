"""
Layer 1: Input Guard
Performs pre-execution analysis on incoming user prompts:
- Direct prompt injection & jailbreak signature detection
- Delimiter injection & system command framing
- Statistical character entropy / obfuscation analysis
- Educational / benign inquiry allowance (reducing False Positives)
"""

import re
import time
import math
from typing import Tuple, List
import config
from engine.models import SecurityEvent, GuardrailResult

class InputGuard:
    def __init__(self):
        self.signatures = [re.compile(pattern) for pattern in config.INJECTION_SIGNATURES]
        # Benign academic/security inquiry indicators to avoid false positives
        self.educational_contexts = [
            r"(?i)what\s+is\s+(an?\s+)?(?:sql\s+injection|prompt\s+injection|jailbreak|xss|csrf)",
            r"(?i)explain\s+(?:how\s+)?(?:sql\s+injection|prompt\s+injection|jailbreak|security)\s+works",
            r"(?i)definition\s+of\s+(?:prompt\s+injection|jailbreak)",
            r"(?i)how\s+to\s+protect\s+against",
            r"(?i)examples\s+of\s+safe\s+coding"
        ]

    def _calculate_entropy(self, text: str) -> float:
        """Calculates Shannon entropy of the string to detect encoded or encrypted payloads."""
        if not text:
            return 0.0
        entropy = 0
        text_len = len(text)
        counts = {}
        for c in text:
            counts[c] = counts.get(c, 0) + 1
        for count in counts.values():
            p = count / text_len
            entropy -= p * math.log2(p)
        return entropy

    def inspect(self, prompt: str) -> GuardrailResult:
        start_time = time.perf_counter()
        reasons = []
        owasp = []
        events = []
        is_blocked = False
        risk_level = "SAFE"
        action = "ALLOW"

        # Check for educational benign inquiries first
        is_educational = any(re.search(pat, prompt) for pat in self.educational_contexts)
        
        # 1. Signature-based injection detection
        matched_sigs = []
        for sig in self.signatures:
            match = sig.search(prompt)
            if match:
                matched_sigs.append(match.group(0))

        if matched_sigs and not is_educational:
            is_blocked = True
            risk_level = "HIGH"
            action = "BLOCKED"
            reasons.append(f"Direct injection pattern detected: '{matched_sigs[0]}'")
            owasp.append("LLM01: Prompt Injection")
            events.append(SecurityEvent(
                risk_level="HIGH",
                owasp_category="LLM01: Prompt Injection",
                layer="Layer 1: Input Guard",
                action="BLOCKED",
                trigger=f"Signature Match: {matched_sigs[0]}",
                target_payload=prompt[:120],
                mitigation_notes="Dropped request before LLM execution",
                latency_ms=(time.perf_counter() - start_time) * 1000
            ))

        # 2. Structural Delimiter and Tag Tampering (<system_override>, ```system, Human:, Assistant:)
        delimiter_patterns = [
            r"<\/?(system|admin|override|root|internal)>",
            r"(?i)(?:^|\n)(?:Human|Assistant|System|User)\s*:\s*",
            r"(?i)```\s*(?:system|admin|root)"
        ]
        delimiter_matches = []
        for d_pat in delimiter_patterns:
            if re.search(d_pat, prompt):
                delimiter_matches.append(d_pat)

        if delimiter_matches and not is_educational:
            is_blocked = True
            risk_level = "HIGH"
            action = "BLOCKED"
            reasons.append("Structural delimiter tampering detected")
            if "LLM01: Prompt Injection" not in owasp:
                owasp.append("LLM01: Prompt Injection")
            events.append(SecurityEvent(
                risk_level="HIGH",
                owasp_category="LLM01: Prompt Injection",
                layer="Layer 1: Input Guard",
                action="BLOCKED",
                trigger="Structural Delimiter Injection",
                target_payload=prompt[:120],
                mitigation_notes="Structural tag stripped/blocked",
                latency_ms=(time.perf_counter() - start_time) * 1000
            ))

        # 3. High Obfuscation / Encoded Payload Analysis (Base64 / Rot13 / Binary patterns)
        base64_regex = r"(?:[A-Za-z0-9+/]{40,}={0,2})"
        b64_matches = re.findall(base64_regex, prompt)
        if b64_matches and not is_educational:
            risk_level = "MEDIUM"
            if not is_blocked:
                # We flag and sanitize or inspect high entropy
                entropy = self._calculate_entropy(prompt)
                if entropy > 4.8 and len(prompt) > 80:
                    is_blocked = True
                    action = "BLOCKED"
                    reasons.append(f"High-entropy obfuscated payload detected (Shannon Entropy: {entropy:.2f})")
                    owasp.append("LLM01: Prompt Injection")
                    events.append(SecurityEvent(
                        risk_level="HIGH",
                        owasp_category="LLM01: Prompt Injection",
                        layer="Layer 1: Input Guard",
                        action="BLOCKED",
                        trigger=f"Obfuscation Entropy ({entropy:.2f})",
                        target_payload=b64_matches[0][:60] + "...",
                        mitigation_notes="Blocked suspicious encoded instruction blob",
                        latency_ms=(time.perf_counter() - start_time) * 1000
                    ))

        # Check for educational bypass logging
        if is_educational and (matched_sigs or delimiter_matches):
            reasons.append("Query matches benign security inquiry context; allowed as educational benign sample.")
            events.append(SecurityEvent(
                risk_level="INFO",
                owasp_category="Benign Control",
                layer="Layer 1: Input Guard",
                action="ALLOW",
                trigger="Educational Security Context Override",
                target_payload=prompt[:120],
                mitigation_notes="Prevented False Positive on benign security question",
                latency_ms=(time.perf_counter() - start_time) * 1000
            ))

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return GuardrailResult(
            allowed=not is_blocked,
            risk_level=risk_level,
            action=action,
            modified_content="[REQUEST REJECTED BY AEGIS-AI INPUT GUARD: Malicious prompt injection or delimiter tampering detected.]" if is_blocked else prompt,
            reasons=reasons,
            owasp_categories=owasp,
            events=events,
            inspection_latency_ms=elapsed_ms
        )
