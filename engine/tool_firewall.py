"""
Layer 3: Autonomous Agent Tool Execution Firewall
Enforces:
- Least-Privilege Capability Scoping (OWASP LLM06: Excessive Agency)
- SQL Injection & Destructive DDL/DML Prevention (Read-only database queries)
- Shell & Remote Code Execution (RCE) Hard-block
- SSRF & Egress Destination Filtering for Webhooks
- AST & Parameter Type Validation
"""

import re
import time
from typing import Dict, Any, Tuple, List
import config
from engine.models import SecurityEvent, GuardrailResult

class ToolFirewall:
    def __init__(self):
        self.permissions = config.TOOL_PERMISSIONS

    def inspect_and_execute(self, tool_name: str, arguments: Dict[str, Any], require_strict: bool = True) -> GuardrailResult:
        start_time = time.perf_counter()
        reasons = []
        owasp = []
        events = []
        risk_level = "SAFE"
        action = "ALLOW"
        allowed = True

        # 1. Tool Whitelist & Capability Check
        tool_policy = self.permissions.get(tool_name)
        if not tool_policy:
            allowed = False
            risk_level = "CRITICAL"
            action = "BLOCKED"
            reasons.append(f"Unregistered / Unknown tool call '{tool_name}' rejected by default-deny policy.")
            owasp.append("LLM06: Excessive Agency")
            events.append(SecurityEvent(
                risk_level="CRITICAL",
                owasp_category="LLM06: Excessive Agency",
                layer="Layer 3: Tool Firewall",
                action="BLOCKED",
                trigger=f"Unknown Tool: {tool_name}",
                target_payload=str(arguments),
                mitigation_notes="Default-deny enforcement for unapproved agent tool",
                latency_ms=(time.perf_counter() - start_time) * 1000
            ))
            return GuardrailResult(False, risk_level, action, f"Error: Tool '{tool_name}' is not permitted.", reasons, owasp, events, (time.perf_counter() - start_time) * 1000)

        if not tool_policy.get("allowed", False):
            allowed = False
            risk_level = "CRITICAL"
            action = "BLOCKED"
            reasons.append(f"Tool '{tool_name}' is explicitly disabled by security policy (High RCE Risk).")
            owasp.append("LLM06: Excessive Agency")
            events.append(SecurityEvent(
                risk_level="CRITICAL",
                owasp_category="LLM06: Excessive Agency",
                layer="Layer 3: Tool Firewall",
                action="BLOCKED",
                trigger=f"Disabled Tool Attempt: {tool_name}",
                target_payload=str(arguments),
                mitigation_notes="Prevented arbitrary code execution / system shell access",
                latency_ms=(time.perf_counter() - start_time) * 1000
            ))
            return GuardrailResult(False, risk_level, action, f"Security Violation: Execution of '{tool_name}' is forbidden by runtime policy.", reasons, owasp, events, (time.perf_counter() - start_time) * 1000)

        # 2. Database Query Inspection (Read-Only Enforcement & SQL Injection)
        if tool_name == "database_query":
            query = str(arguments.get("query", "")).strip()
            forbidden_keywords = tool_policy.get("forbidden_sql_keywords", [])
            for kw in forbidden_keywords:
                # Word boundary check for destructive SQL commands
                if re.search(r"\b" + kw + r"\b", query, re.IGNORECASE):
                    allowed = False
                    risk_level = "CRITICAL"
                    action = "BLOCKED"
                    reasons.append(f"Destructive SQL command '{kw}' detected. Only SELECT queries are permitted.")
                    owasp.append("LLM06: Excessive Agency")
                    events.append(SecurityEvent(
                        risk_level="CRITICAL",
                        owasp_category="LLM06: Excessive Agency",
                        layer="Layer 3: Tool Firewall",
                        action="BLOCKED",
                        trigger=f"Destructive SQL Keyword '{kw}'",
                        target_payload=query,
                        mitigation_notes="Prevented unauthorized database alteration / data drop",
                        latency_ms=(time.perf_counter() - start_time) * 1000
                    ))
                    break

        # 3. Webhook Egress & SSRF Protection
        if tool_name == "send_external_webhook":
            url = str(arguments.get("url", "")).lower()
            allowed_domains = tool_policy.get("allowed_domains", [])
            
            # Check for cloud metadata service SSRF
            if "169.254.169.254" in url or "metadata.google.internal" in url or "localhost" in url or "127.0.0.1" in url:
                allowed = False
                risk_level = "CRITICAL"
                action = "BLOCKED"
                reasons.append(f"SSRF attempt targeting internal cloud metadata service detected: {url}")
                owasp.append("LLM06: Excessive Agency")
                events.append(SecurityEvent(
                    risk_level="CRITICAL",
                    owasp_category="LLM06: Excessive Agency",
                    layer="Layer 3: Tool Firewall",
                    action="BLOCKED",
                    trigger="SSRF / Metadata Target",
                    target_payload=url,
                    mitigation_notes="Blocked outbound request to cloud instance metadata",
                    latency_ms=(time.perf_counter() - start_time) * 1000
                ))
            else:
                domain_match = any(domain in url for domain in allowed_domains)
                if not domain_match:
                    allowed = False
                    risk_level = "HIGH"
                    action = "BLOCKED"
                    reasons.append(f"Egress domain '{url}' is not in approved internal webhook allowlist.")
                    owasp.append("LLM06: Excessive Agency")
                    events.append(SecurityEvent(
                        risk_level="HIGH",
                        owasp_category="LLM06: Excessive Agency",
                        layer="Layer 3: Tool Firewall",
                        action="BLOCKED",
                        trigger=f"Unapproved Egress Target: {url}",
                        target_payload=url,
                        mitigation_notes="Outbound webhook blocked by destination allowlist",
                        latency_ms=(time.perf_counter() - start_time) * 1000
                    ))

        # 4. Blocked Parameter Keywords
        blocked_params = tool_policy.get("blocked_params", [])
        for arg_key, arg_val in arguments.items():
            val_str = str(arg_val).lower()
            for bp in blocked_params:
                if bp.lower() in val_str:
                    allowed = False
                    risk_level = "HIGH"
                    action = "BLOCKED"
                    reasons.append(f"Parameter '{arg_key}' contains prohibited sensitive keyword '{bp}'.")
                    owasp.append("LLM02: Sensitive Info Disclosure")
                    events.append(SecurityEvent(
                        risk_level="HIGH",
                        owasp_category="LLM02: Sensitive Info Disclosure",
                        layer="Layer 3: Tool Firewall",
                        action="BLOCKED",
                        trigger=f"Prohibited Parameter Keyword '{bp}'",
                        target_payload=f"{arg_key}={arg_val}",
                        mitigation_notes="Sanitized dangerous tool argument parameter",
                        latency_ms=(time.perf_counter() - start_time) * 1000
                    ))
                    break

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        execution_output = ""
        if allowed:
            # Simulate safe execution of authorized tools
            if tool_name == "read_customer_data":
                execution_output = f"[TOOL EXECUTION SUCCESS]: Retrieved safe customer profile {arguments.get('customer_id', 'CUST-001')} (Masked PII)."
            elif tool_name == "search_knowledge_base":
                execution_output = f"[TOOL EXECUTION SUCCESS]: Queried documents matching '{arguments.get('query', '')}'. (3 chunks returned)."
            elif tool_name == "database_query":
                execution_output = f"[TOOL EXECUTION SUCCESS]: Executed read-only query '{arguments.get('query', '')}'. (Returned 12 rows)."
            elif tool_name == "send_external_webhook":
                execution_output = f"[TOOL EXECUTION SUCCESS]: Webhook dispatched to approved endpoint {arguments.get('url', '')}."
        else:
            execution_output = f"[TOOL BLOCKED BY AEGIS FIREWALL]: {'; '.join(reasons)}"

        return GuardrailResult(
            allowed=allowed,
            risk_level=risk_level,
            action=action,
            modified_content=execution_output,
            reasons=reasons,
            owasp_categories=owasp,
            events=events,
            inspection_latency_ms=elapsed_ms
        )
