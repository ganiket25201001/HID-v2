"""RandomForest-based threat classifier for HID Shield ensemble ML.

This module provides a secondary classification model using scikit-learn's
RandomForestClassifier alongside the primary LightGBM model. Both models
run in ensemble to produce more robust threat detection.

Feature vector (spec-mandated 8 features for RF):
[entropy, pe_flag, hid_type, descriptor_hash, keystroke_rate,
 vendor_id, product_id, is_composite]

Labels: SAFE / SUSPICIOUS / MALICIOUS
Confidence threshold for MALICIOUS: ≥ 0.85
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import numpy as np


class RFThreatLabel(str, Enum):
    """Three-class threat labels for the RandomForest classifier."""

    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


@dataclass(slots=True)
class RFClassificationResult:
    """Output of RandomForest classification."""

    label: RFThreatLabel
    confidence: float
    probabilities: dict[str, float]
    explanation: str


class RandomForestThreatClassifier:
    """Classify device/file threats using scikit-learn RandomForestClassifier.

    The classifier uses an 8-feature vector as specified:
    [entropy, pe_flag, hid_type_encoded, descriptor_hash_encoded,
     keystroke_rate, vendor_id_encoded, product_id_encoded, is_composite]

    The model is trained on synthetic data on first init if no persisted
    model exists. In production, a pre-trained model file is loaded.
    """

    _MALICIOUS_CONFIDENCE_THRESHOLD: float = 0.85
    _FEATURE_NAMES: tuple[str, ...] = (
        "entropy",
        "pe_flag",
        "hid_type_encoded",
        "descriptor_hash_encoded",
        "keystroke_rate",
        "vendor_id_encoded",
        "product_id_encoded",
        "is_composite",
    )

    _LABEL_MAP: dict[int, RFThreatLabel] = {
        0: RFThreatLabel.SAFE,
        1: RFThreatLabel.SUSPICIOUS,
        2: RFThreatLabel.MALICIOUS,
    }

    def __init__(self, model_path: Path | None = None) -> None:
        default_model = Path(__file__).resolve().parent / "models" / "rf_threat_model.joblib"
        self._model_path = model_path or default_model
        self._model: Any = None
        self._load_or_train()

    def classify(self, features: dict[str, float]) -> RFClassificationResult:
        """Classify using the RandomForest model.

        Parameters
        ----------
        features:
            Dictionary with the 8 feature values.

        Returns
        -------
        RFClassificationResult
            Label, confidence, probabilities, and explanation.
        """
        vector = self._to_vector(features)
        arr = np.asarray([vector], dtype=np.float64)

        probabilities = self._model.predict_proba(arr)[0]  # type: ignore[union-attr]
        class_labels = list(self._LABEL_MAP.values())

        prob_dict = {}
        for idx, label in enumerate(class_labels):
            prob_dict[label.value] = round(float(probabilities[idx]), 4) if idx < len(probabilities) else 0.0

        predicted_class = int(self._model.predict(arr)[0])  # type: ignore[union-attr]
        predicted_label = self._LABEL_MAP.get(predicted_class, RFThreatLabel.SAFE)
        max_confidence = float(max(probabilities))

        # Apply spec threshold: MALICIOUS only if confidence ≥ 0.85
        if predicted_label == RFThreatLabel.MALICIOUS and max_confidence < self._MALICIOUS_CONFIDENCE_THRESHOLD:
            predicted_label = RFThreatLabel.SUSPICIOUS

        explanation = (
            f"RF: label={predicted_label.value}, conf={max_confidence:.4f}; "
            f"probs=[SAFE={prob_dict.get('SAFE', 0):.3f}, "
            f"SUSP={prob_dict.get('SUSPICIOUS', 0):.3f}, "
            f"MAL={prob_dict.get('MALICIOUS', 0):.3f}]"
        )

        return RFClassificationResult(
            label=predicted_label,
            confidence=max_confidence,
            probabilities=prob_dict,
            explanation=explanation,
        )

    def _to_vector(self, features: dict[str, float]) -> list[float]:
        """Convert feature dict to ordered vector."""
        return [float(features.get(name, 0.0)) for name in self._FEATURE_NAMES]

    def _load_or_train(self) -> None:
        """Load persisted model or train on synthetic data."""
        if self._model_path.exists():
            try:
                import joblib  # type: ignore[import-untyped]
                self._model = joblib.load(str(self._model_path))
                print(f"[RF] Loaded RandomForest model from {self._model_path}")
                return
            except Exception as e:
                print(f"[RF] Failed to load model: {e}, training fresh model")

        self._train_synthetic()

    def _train_synthetic(self) -> None:
        """Train on synthetic HID Shield data and persist the model."""
        from sklearn.ensemble import RandomForestClassifier  # type: ignore[import-untyped]

        # Feature order: [entropy, pe_flag, hid_type_encoded, descriptor_hash,
        #                  keystroke_rate, vendor_id_encoded, product_id_encoded, is_composite]
        X = np.array([
            # SAFE devices (label=0)
            [1.2, 0, 1, 0.1, 3.0, 0.5, 0.3, 0],   # Normal mouse
            [2.0, 0, 1, 0.2, 5.0, 0.5, 0.4, 0],   # Normal keyboard
            [3.1, 0, 2, 0.3, 8.0, 0.6, 0.5, 0],   # USB storage
            [3.8, 0, 0, 0.4, 0.0, 0.3, 0.2, 0],   # Unknown benign
            [4.2, 0, 1, 0.5, 12.0, 0.4, 0.6, 0],  # Fast typist
            [2.5, 0, 1, 0.15, 7.0, 0.7, 0.3, 0],  # Normal keyboard
            [1.8, 0, 2, 0.25, 0.0, 0.5, 0.5, 0],  # USB drive
            [3.5, 0, 1, 0.35, 15.0, 0.6, 0.4, 0], # Fast typist
            [4.0, 1, 2, 0.6, 0.0, 0.5, 0.5, 0],   # USB with PE file
            [2.2, 0, 1, 0.12, 10.0, 0.8, 0.2, 0], # Branded keyboard

            # SUSPICIOUS devices (label=1)
            [6.5, 0, 1, 0.7, 25.0, 0.1, 0.1, 0],  # Faster than normal
            [6.8, 1, 2, 0.8, 30.0, 0.2, 0.3, 1],  # Composite + fast
            [7.0, 0, 1, 0.6, 45.0, 0.0, 0.0, 0],  # No vendor, fast typing
            [6.2, 1, 0, 0.5, 35.0, 0.1, 0.2, 1],  # Unknown composite
            [7.1, 0, 1, 0.9, 55.0, 0.3, 0.1, 0],  # Very fast injection
            [6.6, 1, 2, 0.7, 40.0, 0.0, 0.0, 1],  # Composite no VID
            [6.9, 0, 1, 0.75, 50.0, 0.1, 0.1, 0], # Fast injection
            [7.2, 0, 1, 0.85, 60.0, 0.2, 0.2, 0], # Suspicious boundary

            # MALICIOUS devices (label=2)
            [7.8, 1, 1, 0.95, 120.0, 0.0, 0.0, 1],  # Rubber Ducky profile
            [7.9, 1, 1, 0.9, 200.0, 0.0, 0.0, 1],   # Full attack speed
            [7.5, 1, 2, 0.88, 150.0, 0.0, 0.0, 1],  # BadUSB storage+HID
            [7.7, 0, 1, 0.92, 180.0, 0.0, 0.0, 0],  # Keystroke injector
            [7.6, 1, 0, 0.98, 250.0, 0.0, 0.0, 1],  # Critical injector
            [7.9, 1, 1, 0.87, 300.0, 0.0, 0.0, 1],  # Maximum attack
            [7.4, 1, 1, 0.91, 100.0, 0.1, 0.0, 1],  # Packed HID attack
            [7.8, 1, 2, 0.96, 160.0, 0.0, 0.0, 1],  # Mixed attack
        ], dtype=np.float64)

        y = np.array([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # SAFE
            1, 1, 1, 1, 1, 1, 1, 1,          # SUSPICIOUS
            2, 2, 2, 2, 2, 2, 2, 2,          # MALICIOUS
        ], dtype=np.int32)

        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=8,
            min_samples_split=2,
            min_samples_leaf=1,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X, y)
        self._model = model

        # Persist model
        try:
            import joblib  # type: ignore[import-untyped]
            self._model_path.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(model, str(self._model_path))
            print(f"[RF] RandomForest model trained and saved to {self._model_path}")
        except Exception as e:
            print(f"[RF] Warning: could not persist model — {e}")

        # Print feature importance
        importances = model.feature_importances_
        for name, imp in sorted(
            zip(self._FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True
        ):
            print(f"  [RF] {name:<28} importance={imp:.4f}")

    @staticmethod
    def encode_hid_type(device_type: str) -> float:
        """Encode device type string to numeric feature."""
        mapping = {
            "keyboard": 1.0,
            "mouse": 1.0,
            "storage": 2.0,
            "composite": 3.0,
            "audio": 4.0,
            "network": 5.0,
        }
        return mapping.get(device_type.lower(), 0.0)

    @staticmethod
    def encode_id_feature(hex_id: Optional[str]) -> float:
        """Encode a hex VID/PID to a normalized float."""
        if not hex_id:
            return 0.0
        try:
            return int(hex_id, 16) / 65535.0
        except (ValueError, TypeError):
            return 0.0

    @staticmethod
    def encode_descriptor_hash(hash_str: str) -> float:
        """Encode descriptor hash to normalized float."""
        if not hash_str:
            return 0.0
        try:
            return int(hash_str[:8], 16) / 0xFFFFFFFF
        except (ValueError, TypeError):
            return 0.0
