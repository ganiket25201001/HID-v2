"""Asynchronous advisory AI agent for grounded threat explanations."""

from __future__ import annotations

from typing import Any, Mapping

from PySide6.QtCore import QObject, QThread, Signal

from ai_agent.advisory_service import AdvisoryAIService
from core.event_bus import event_bus


class AgentWorker(QThread):
    """Worker thread that runs the advisory service without blocking UI."""

    finished_signal = Signal(dict)

    def __init__(self, service: AdvisoryAIService, event_id: int, payload: Mapping[str, Any]):
        super().__init__()
        self._service = service
        self._event_id = int(event_id)
        self._payload = dict(payload)

    def run(self) -> None:
        try:
            result = self._service.analyze_event(event_id=self._event_id, payload=self._payload)
            self.finished_signal.emit(result)
        except Exception as exc:
            self.finished_signal.emit(
                {
                    "status": "error",
                    "event_id": self._event_id,
                    "explanation": f"Advisory AI failed: {exc}",
                    "source": "exception",
                }
            )


class ExplanationAgent(QObject):
    """Generate asynchronous advisory explanations from local Ollama models."""

    def __init__(self) -> None:
        super().__init__()
        self._workers: list[AgentWorker] = []

    def request_explanation(self, event_id: int, payload: Mapping[str, Any]) -> None:
        """Run advisory analysis asynchronously and emit event bus result."""
        # Recreate service per request so runtime settings changes are picked up.
        service = AdvisoryAIService()
        worker = AgentWorker(service=service, event_id=event_id, payload=payload)
        worker.finished_signal.connect(self._on_worker_finished)
        self._workers.append(worker)
        worker.start()

    def test_connection(self) -> dict[str, Any]:
        """Check current local Ollama availability using active settings."""
        service = AdvisoryAIService()
        return service.test_connection()

    def _on_worker_finished(self, result: dict[str, Any]) -> None:
        event_bus.ai_explanation_ready.emit(result)
        self._workers = [worker for worker in self._workers if worker.isRunning()]
