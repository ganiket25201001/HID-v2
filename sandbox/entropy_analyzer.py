"""Shannon entropy analysis utilities for sandboxed file triage."""

from __future__ import annotations

import math
from pathlib import Path


class ShannonEntropyAnalyzer:
    """Compute Shannon entropy and classify probable file packing style.

    The analyzer works on raw bytes and can be applied to any file type.
    Entropy values near 0 indicate highly repetitive plain-text content,
    while values near 8 indicate compressed, packed, or encrypted payloads.
    """

    def analyze_bytes(self, payload: bytes) -> dict[str, object]:
        """Return entropy metadata for an in-memory byte sequence.

        Parameters
        ----------
        payload:
            Raw file bytes.

        Returns
        -------
        dict[str, object]
            Dictionary containing `entropy`, `classification`, and `explanation`.
        """
        if not payload:
            return {
                "entropy": 0.0,
                "classification": "plain_text",
                "explanation": "Empty payload has zero entropy.",
            }

        frequencies = [0] * 256
        for byte_value in payload:
            frequencies[byte_value] += 1

        payload_len = float(len(payload))
        entropy = 0.0
        for count in frequencies:
            if count == 0:
                continue
            probability = count / payload_len
            entropy -= probability * math.log2(probability)

        classification, explanation = self._classify_entropy(entropy)
        return {
            "entropy": round(entropy, 4),
            "classification": classification,
            "explanation": explanation,
        }

    def analyze_file(self, file_path: Path, max_bytes: int = 512 * 1024) -> dict[str, object]:
        """Read a file and compute its entropy information.

        Parameters
        ----------
        file_path:
            Target file path.
        max_bytes:
            Maximum number of bytes sampled from the start of the file.

        Returns
        -------
        dict[str, object]
            Entropy metadata with read status details.
        """
        if max_bytes <= 0:
            return {
                "entropy": 0.0,
                "classification": "unreadable",
                "explanation": "Invalid sampling size: max_bytes must be positive.",
            }

        try:
            with file_path.open("rb") as stream:
                sample = stream.read(max_bytes)
        except OSError as exc:
            return {
                "entropy": 0.0,
                "classification": "unreadable",
                "explanation": f"File read failed: {exc}",
            }

        result = self.analyze_bytes(sample)
        result["sampled_bytes"] = len(sample)
        return result

    def _classify_entropy(self, entropy: float) -> tuple[str, str]:
        """Map entropy score to a human-readable risk interpretation."""
        if entropy < 4.2:
            return (
                "plain_text",
                "Low entropy suggests plain text or highly structured data.",
            )
        if entropy < 6.2:
            return (
                "normal_binary",
                "Moderate entropy is common in regular executable or binary content.",
            )
        if entropy < 7.3:
            return (
                "compressed",
                "High entropy suggests compression or obfuscated binary sections.",
            )
        if entropy < 7.8:
            return (
                "packed",
                "Very high entropy suggests runtime packer usage and possible evasion.",
            )
        return (
            "encrypted",
            "Near-maximum entropy strongly indicates encrypted or heavily packed payload.",
        )
