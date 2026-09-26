"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import time


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    @staticmethod
    def _key(request_id: str | None, user_id: str) -> str:
        """Return the same correlation key for an input/output pair."""
        return request_id or f"user:{user_id}"

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """TODO: store input + start timestamp keyed by request_id/user_id."""
        self._open[self._key(request_id, user_id)] = time.time()
        entry = {
            "timestamp": utc_now_iso(),
            "request_id": request_id,
            "user_id": user_id,
            "direction": "input",
            "blocked": False,
            "layer": None,
            "latency_ms": None,
            "text": text,
        }
        self.logs.append(entry)

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """TODO: store output, layer decision, latency; append to self.logs."""
        key = self._key(request_id, user_id)
        start = self._open.pop(key, None)
        latency_ms = round((time.time() - start) * 1000, 1) if start is not None else None

        entry = {
            "timestamp": utc_now_iso(),
            "request_id": request_id,
            "user_id": user_id,
            "direction": "output",
            "blocked": blocked,
            "layer": layer,
            "latency_ms": latency_ms,
            "text": text,
        }
        self.logs.append(entry)
        # raise NotImplementedError("Implement AuditLogPlugin.record_output")

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        # TODO: path = filepath or default_audit_log_path()
        #       ensure parent dirs exist, dump self.logs with indent=2
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(self.logs, f, indent=2, ensure_ascii=False)
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
