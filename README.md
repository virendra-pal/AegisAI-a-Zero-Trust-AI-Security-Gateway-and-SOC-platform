# AegisAI: Zero-Trust Runtime Defense & SOC Platform for LLMs & Autonomous Agents

> **Submission for Hackathon: "Cybersecurity in AI — Securing Systems That Learn"**  
> *Track: Defending an AI system against AI-specific attacks (with automated SOC telemetry)*

---

## 🚀 Quick Start (Zero External Dependencies)

AegisAI is built strictly with the Python 3 standard library and a modern browser frontend. **No `pip install` required, no third-party package conflicts.**

### 1. Launch the Gateway Server
On Windows:
```powershell
py server.py
```
*(Or simply double-click `run.bat`)*

### 2. Open the SOC Dashboard
Navigate to:
```
http://localhost:8000
```

---

## 🎯 How AegisAI Solves the Hackathon Challenge

| Hackathon Requirement | AegisAI Implementation & Verifiable Proof |
| :--- | :--- |
| **State threat model up front** | See [`THREAT_MODEL.md`](THREAT_MODEL.md). Clearly defines 4 attacker personas (untrusted user, poisoned content author, compromised agent, C2 harvester), asset inventories, and entry surfaces. |
| **Demonstrate at least 3 concrete attacks** | Pre-loaded in the UI with 1-click execution presets:<br>1. **Indirect RAG Injection with Markdown Image Exfiltration** (`LLM01` & `LLM02`)<br>2. **Autonomous Agent Tool Abuse: `DROP TABLE`** (`LLM06`)<br>3. **System Prompt & Cryptographic Canary Extraction** (`LLM02`)<br>4. *Bonus:* **Arbitrary Shell Execution & Cloud Metadata SSRF** (`LLM06`) |
| **Show defense detecting, blocking, or containing** | Side-by-side **Dual-Execution view** (*Baseline Vulnerable vs. AegisAI Protected*). Judges can see the unredacted exploit succeeding on the left, and instantly contained on the right with pipeline telemetry logs. |
| **Report misses and false positives honestly** | Built-in **Red-Team Benchmark Suite** (`/api/benchmark`) reporting empirical Confusion Matrix: **94.7% Detection Rate**, **0.0% False Positive Rate**, and an honest technical breakdown of the known bypass case (`ATK-19` Latin Cipher). See [`BENCHMARK_REPORT.md`](BENCHMARK_REPORT.md). |
| **Keep an audit trail for security teams** | Persistent **SOC SIEM Audit Stream** recording Event ID, Timestamp, Severity, OWASP Category, Layer, Action, and Latency, with 1-click **Export to CSV** and **Export to JSON**. |
| **State plainly what defense does not cover** | Formal defense boundaries documented: does not cover raw gradient tensor weight attacks (GCG), hardware physical memory side-channels, or low-resource non-English cipher framing in single-pass mode. |

---

## 🛡️ The 4-Layer Defense Architecture

```
User Query / API ──────────┐
                           ▼
                 ┌──────────────────┐
                 │  Layer 1:        │ ──► Direct Injection, Delimiters, Shannon Entropy
                 │  Input Guard     │
                 └─────────┬────────┘
                           ▼
                 ┌──────────────────┐
                 │  Layer 2:        │ ──► Zero-Width Steganography, Context Isolation XML,
                 │  RAG Sanitizer   │     Markdown Image Exfiltration URLs
                 └─────────┬────────┘
                           ▼
                 ┌──────────────────┐
                 │  Target LLM /    │ ──► Autonomous Agent Reasoning
                 │  Agent Engine    │
                 └─────────┬────────┘
                           ▼
                 ┌──────────────────┐
                 │  Layer 3:        │ ──► Capability Scoping, Read-Only SQL AST,
                 │  Tool Firewall   │     Shell RCE Denial, SSRF Cloud Metadata Filter
                 └─────────┬────────┘
                           ▼
                 ┌──────────────────┐
                 │  Layer 4:        │ ──► Cryptographic Canary Tripwires, PII Redaction,
                 │  Output Guard    │     System Prompt Leakage Truncation
                 └─────────┬────────┘
                           │
                           ▼
              Clean Response to Client + SIEM Event Logged
```

---

## 🖥️ Interactive Dashboard Walkthrough

1. **Live Threat Simulator Tab**:
   - Choose any attack preset (e.g. *Indirect RAG Injection*, *SQL Drop*, *Canary Leak*).
   - Click **Execute Dual-Execution Test**.
   - Inspect the live side-by-side split screen showing exploit execution on the Baseline vs. immediate containment on AegisAI.
   - Watch the microsecond step-by-step pipeline trace.

2. **SOC Audit Trail (SIEM) Tab**:
   - Filter logs by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `SAFE`).
   - Click **Export CSV** to generate a forensic audit log suitable for enterprise incident responders.
   - Click **Export JSON** for programmatic SIEM ingestion.

3. **Red-Team Benchmark Tab**:
   - Click **Run Automated Red-Team Suite**.
   - Runs 50 test cases across direct jailbreaks, RAG injections, tool exploits, and benign educational controls.
   - Generates the Confusion Matrix, Recall, Precision, and False Positive Rate metrics in real time.
   - Review the **Honest Bypass Report** explaining boundary limitations.

4. **Defense Engine Policy Tab**:
   - Review active layer rules, registered Canary Tokens, and the autonomous tool capability scoping matrix.

---

## 📂 Project Structure

```
cyberSecurityinAI/
├── README.md                 # Master project documentation
├── THREAT_MODEL.md           # Formal OWASP-aligned Threat Model
├── BENCHMARK_REPORT.md       # Empirical metrics, confusion matrix, bypass analysis
├── run.bat                   # 1-click Windows launcher
├── server.py                 # Zero-dependency Python 3 HTTP & REST API server
├── config.py                 # Security rules, canary tokens, tool permissions
├── engine/
│   ├── models.py             # Data classes (SecurityEvent, GuardrailResult, AttackScenario)
│   ├── canary_manager.py     # Cryptographic canary token tripwires
│   ├── input_guard.py        # Layer 1: Prompt injection & delimiter inspection
│   ├── rag_sanitizer.py      # Layer 2: Indirect injection & markdown exfil stripping
│   ├── tool_firewall.py      # Layer 3: Autonomous tool capability scoping & SQL/SSRF sandbox
│   ├── output_guard.py       # Layer 4: Post-generation canary scanner & PII redaction
│   ├── agent_runtime.py      # Orchestrator (Baseline vs Protected dual execution)
│   ├── benchmark_harness.py  # Automated 50-test benchmark suite
│   └── audit_logger.py       # Persistent SIEM telemetry logging & CSV/JSON export
└── web/
    ├── index.html            # Cyber-SOC dashboard interface
    ├── styles.css            # Custom CSS & glow animations
    └── app.js                # Frontend controller & API client
```

---

## 🏆 Why AegisAI Wins

1. **Real Code, Not Theoretical Slides**: Operates as a functioning, zero-dependency security runtime with an interactive web UI.
2. **Side-by-Side Verifiability**: Gives judges visual, unmistakable proof of the difference between an unprotected target system and a secured one.
3. **Intellectual Honesty**: Demonstrates empirical metrics, a measured False Positive Rate, and an analyzed bypass case rather than claiming an impossible "100% impenetrable" solution.
4. **Enterprise Operations Focus**: Provides the audit logs, CSV exports, and SIEM integration that actual security operations centers (SOCs) require to deploy AI agents safely.
