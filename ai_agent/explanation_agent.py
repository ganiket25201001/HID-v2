"""Asynchronous local Gemma 4 agent for threat explanations via Ollama."""

import json
from typing import Any, Mapping

import ollama
from PySide6.QtCore import QObject, QThread, Signal

from core.event_bus import event_bus

class AgentWorker(QThread):
    finished_signal = Signal(dict)
    
    def __init__(self, prompt: str, event_id: int):
        super().__init__()
        self.prompt = prompt
        self.event_id = event_id

    def run(self):
        try:
            response = ollama.chat(
                model='gemma4:e2b',
                messages=[{
                    'role': 'user', 
                    'content': self.prompt
                }],
                options={'temperature': 0.3}
            )
            result_text = response.get('message', {}).get('content', '')
            self.finished_signal.emit({
                "status": "success",
                "explanation": str(result_text).strip(),
                "event_id": self.event_id
            })
        except Exception as str_exc:
            self.finished_signal.emit({
                "status": "error",
                "explanation": f"Gemma 4 agent failed: {str_exc}",
                "event_id": self.event_id
            })

class ExplanationAgent(QObject):
    """Generates rich text summaries using locally hosted Ollama/gemma4."""

    def __init__(self):
        super().__init__()
        self._workers: list[AgentWorker] = []

    def request_explanation(self, event_id: int, payload: Mapping[str, Any]) -> None:
        """Asynchronously trigger LLM for event explanation payload."""
        prompt = self._build_prompt(payload)
        
        worker = AgentWorker(prompt=prompt, event_id=event_id)
        worker.finished_signal.connect(self._on_worker_finished)
        self._workers.append(worker)
        worker.start()

    def _on_worker_finished(self, result: dict[str, Any]):
        event_bus.ai_explanation_ready.emit(result)
        # Clean up finished workers
        self._workers = [w for w in self._workers if w.isRunning()]

    def _build_prompt(self, payload: Mapping[str, Any]) -> str:
        """Format the threat parameters into a high-fidelity expert instruction context."""
        js = json.dumps(payload, indent=2, default=str)
        
        # Determine base tone based on risk
        risk_level = str(payload.get("device_level") or payload.get("risk_level") or "SAFE").upper()
        
        return (
            f"SYSTEM ROLE: You are the HID Shield Core AI, a high-level Cybersecurity Architect programmed with a 'Cyberpunk Executive' persona. "
            f"Your mission is to analyze USB threat telemetry and provide authoritative, concise, and technically accurate intelligence to the system operator.\n\n"
            f"TASK: Generate a 3-paragraph Security Executive Summary based on the provided JSON telemetry. "
            f"Use a tone that is direct, slightly cold, and highly professional.\n\n"
            f"STRUCTURE:\n"
            f"1. **Threat Vector**: Identify the primary risk (or lack thereof) based on file entropy, extension mismatches, or suspicious WMI properties.\n"
            f"2. **Analysis Reasoning**: Explain why the system assigned a risk level of '{risk_level}'. Reference specific data points like LightGBM scoring or suspicious imports.\n"
            f"3. **Enforcement Advice**: Provide a clear recommendation (e.g., 'Maintain quarantine', 'Allow access with monitoring').\n\n"
            f"RULES:\n"
            f"- Keep the total length under 100 words.\n"
            f"- Use technical terminology (e.g., entropy, PE header, heuristics, stager).\n"
            f"- If the device is SAFE, acknowledge the clean scan but remain vigilant.\n"
            f"- NEVER mention that you are an AI or a language model.\n\n"
            f"TELEMETRY DATA (JSON):\n{js}"
        )
