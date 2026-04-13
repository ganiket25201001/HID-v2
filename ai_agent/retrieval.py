"""Local embedding index for advisory similarity retrieval."""

from __future__ import annotations

import json
import math
import threading
from pathlib import Path
from typing import Any, Callable


EmbedFn = Callable[[str], list[float]]


class LocalEmbeddingIndex:
    """Simple JSONL embedding store for local similarity search."""

    def __init__(self, index_path: Path) -> None:
        self._path = index_path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def add_case(self, *, case_id: str, text: str, metadata: dict[str, Any], embed_fn: EmbedFn) -> bool:
        """Embed and append one case record into the local index."""
        clean_text = (text or "").strip()
        if not clean_text:
            return False

        try:
            vector = embed_fn(clean_text)
        except Exception:
            return False

        if not vector:
            return False

        payload = {
            "case_id": str(case_id),
            "text": clean_text,
            "metadata": metadata,
            "vector": [float(x) for x in vector],
        }

        line = json.dumps(payload, ensure_ascii=True)
        with self._lock:
            with self._path.open("a", encoding="utf-8") as stream:
                stream.write(line + "\n")
        return True

    def query_similar(self, *, query: str, top_k: int, embed_fn: EmbedFn) -> list[dict[str, Any]]:
        """Find nearest stored cases using cosine similarity."""
        clean_query = (query or "").strip()
        if not clean_query:
            return []

        try:
            query_vec = embed_fn(clean_query)
        except Exception:
            return []

        if not query_vec:
            return []

        entries = self._read_entries()
        scored: list[tuple[float, dict[str, Any]]] = []
        for entry in entries:
            vector = entry.get("vector")
            if not isinstance(vector, list) or not vector:
                continue
            score = cosine_similarity(query_vec, [float(x) for x in vector])
            scored.append((score, entry))

        ranked = sorted(scored, key=lambda item: item[0], reverse=True)
        return [
            {
                "score": round(score, 6),
                "case_id": str(entry.get("case_id", "")),
                "text": str(entry.get("text", "")),
                "metadata": entry.get("metadata", {}),
            }
            for score, entry in ranked[: max(0, int(top_k))]
            if score > 0.05
        ]

    def _read_entries(self) -> list[dict[str, Any]]:
        if not self._path.exists():
            return []
        rows: list[dict[str, Any]] = []
        with self._lock:
            with self._path.open("r", encoding="utf-8") as stream:
                for line in stream:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        payload = json.loads(stripped)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(payload, dict):
                        rows.append(payload)
        return rows


def cosine_similarity(left: list[float], right: list[float]) -> float:
    """Compute cosine similarity for equally sized vectors."""
    if not left or not right:
        return 0.0
    size = min(len(left), len(right))
    if size == 0:
        return 0.0

    dot = 0.0
    left_norm = 0.0
    right_norm = 0.0
    for idx in range(size):
        lv = float(left[idx])
        rv = float(right[idx])
        dot += lv * rv
        left_norm += lv * lv
        right_norm += rv * rv

    if left_norm <= 0.0 or right_norm <= 0.0:
        return 0.0

    return dot / (math.sqrt(left_norm) * math.sqrt(right_norm))
