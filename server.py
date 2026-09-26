"""
AegisAI Security Gateway & Web Server
Zero external dependencies - Uses Python 3 standard library exclusively.
Serves the SOC Dashboard and REST APIs for side-by-side defense evaluation.
"""

import http.server
import socketserver
import json
import os
import sys
import urllib.parse
from typing import Dict, Any

# Ensure UTF-8 output encoding across Windows shells
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import config
from engine.audit_logger import AuditLogger
from engine.agent_runtime import AgentRuntime
from engine.benchmark_harness import BenchmarkHarness

# Initialize singletons
audit_logger = AuditLogger(os.path.join(BASE_DIR, "audit_log.json"))
agent_runtime = AgentRuntime(audit_logger)
benchmark_harness = BenchmarkHarness(agent_runtime)

class AegisHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Serve static assets from 'web' directory
        super().__init__(*args, directory=os.path.join(BASE_DIR, "web"), **kwargs)

    def _send_json_response(self, data: Any, status: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        if path == "/api/status":
            self._send_json_response({
                "status": "ONLINE",
                "defense_engine": "AegisAI Zero-Trust Runtime",
                "active_layers": [
                    "Layer 1: Input Guard (Direct Injection & Delimiter Inspector)",
                    "Layer 2: RAG Sanitizer (Indirect Injection & Markdown Exfil Guard)",
                    "Layer 3: Autonomous Tool Firewall (Least Privilege & Egress Sandboxing)",
                    "Layer 4: Output Guard & Canary Tripwire (Secret & Canary Scanner)"
                ]
            })
            return

        elif path == "/api/logs":
            sev = params.get("severity", ["ALL"])[0]
            logs = audit_logger.get_events(limit=150, severity_filter=sev)
            self._send_json_response(logs)
            return

        elif path == "/api/export/csv":
            csv_data = audit_logger.export_csv().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=\"aegis_ai_audit_trail.csv\"")
            self.send_header("Content-Length", str(len(csv_data)))
            self.end_headers()
            self.wfile.write(csv_data)
            return

        elif path == "/api/export/json":
            json_data = json.dumps([e.to_dict() for e in audit_logger.events], indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=\"aegis_ai_audit_trail.json\"")
            self.send_header("Content-Length", str(len(json_data)))
            self.end_headers()
            self.wfile.write(json_data)
            return

        # Fallback to serving static frontend files
        super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Read POST body
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        
        try:
            body = json.loads(post_data) if post_data.strip() else {}
        except Exception:
            body = {}

        if path == "/api/execute":
            # Side-by-side Dual Execution
            prompt = body.get("prompt", "")
            context = body.get("context", None)
            tool_call = body.get("tool_call", None)

            # 1. Execute Vulnerable Baseline (Defense: OFF)
            baseline_result = agent_runtime.execute(
                prompt=prompt,
                retrieved_context=context,
                tool_call=tool_call,
                defense_active=False
            )

            # 2. Execute AegisAI Protected Gateway (Defense: ON)
            protected_result = agent_runtime.execute(
                prompt=prompt,
                retrieved_context=context,
                tool_call=tool_call,
                defense_active=True
            )

            self._send_json_response({
                "baseline_vulnerable": baseline_result,
                "protected_aegis": protected_result
            })
            return

        elif path == "/api/benchmark":
            # Run automated red-team benchmark suite
            bench_results = benchmark_harness.run_benchmark()
            self._send_json_response(bench_results)
            return

        elif path == "/api/logs/clear":
            audit_logger.clear()
            self._send_json_response({"status": "CLEARED"})
            return

        self.send_error(404, "Endpoint not found")

def start_server():
    server_address = (config.HOST, config.PORT)
    with socketserver.TCPServer(server_address, AegisHTTPRequestHandler) as httpd:
        print("=" * 70)
        print(" [AEGIS-SHIELD] AegisAI Zero-Trust AI Security Gateway & SOC Defense Platform")
        print(f" [*] Server running on http://{config.HOST}:{config.PORT}")
        print(" [*] Zero external dependencies. Uses Python 3 Standard Library.")
        print(" [*] Press Ctrl+C to terminate.")
        print("=" * 70)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down AegisAI Gateway cleanly.")
            httpd.shutdown()

if __name__ == "__main__":
    start_server()
