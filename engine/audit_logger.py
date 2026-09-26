"""
SIEM Audit Logger & Telemetry Hub
Records all security events, maintains chronological audit trails, and provides structured export.
"""

import json
import csv
import io
import os
from typing import List, Dict, Any, Optional
from engine.models import SecurityEvent

LOG_FILE_PATH = "audit_log.json"

class AuditLogger:
    def __init__(self, storage_path: str = LOG_FILE_PATH):
        self.storage_path = storage_path
        self.events: List[SecurityEvent] = []
        self._load_existing_logs()

    def _load_existing_logs(self):
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data:
                        self.events.append(SecurityEvent(**item))
            except Exception:
                self.events = []

    def _persist(self):
        try:
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump([e.to_dict() for e in self.events[-500:]], f, indent=2)
        except Exception:
            pass

    def log_event(self, event: SecurityEvent):
        self.events.insert(0, event)  # newest first
        self._persist()

    def log_events(self, events: List[SecurityEvent]):
        for e in events:
            self.events.insert(0, e)
        self._persist()

    def get_events(self, limit: int = 100, severity_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        filtered = self.events
        if severity_filter and severity_filter.upper() != "ALL":
            filtered = [e for e in filtered if e.risk_level.upper() == severity_filter.upper()]
        return [e.to_dict() for e in filtered[:limit]]

    def clear(self):
        self.events = []
        self._persist()

    def export_csv(self) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "Timestamp", "Risk Level", "OWASP Category", "Layer", "Action", "Trigger", "Payload Sample", "Mitigation", "Latency (ms)"])
        for e in self.events:
            writer.writerow([
                e.id,
                e.timestamp,
                e.risk_level,
                e.owasp_category,
                e.layer,
                e.action,
                e.trigger,
                e.target_payload.replace("\n", " ")[:100],
                e.mitigation_notes,
                round(e.latency_ms, 2)
            ])
        return output.getvalue()
