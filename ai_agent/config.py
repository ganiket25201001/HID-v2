"""AI integration configuration helpers for HID Shield."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "config.yaml"


@dataclass(slots=True)
class AISettings:
    """Runtime settings for local advisory AI integration."""

    enabled: bool = False
    text_model: str = "qwen2.5-coder:7b"
    vision_model: str = "qwen2.5vl:7b"
    embeddings_model: str = "nomic-embed-text"
    timeout_seconds: int = 20
    temperature: float = 0.2
    top_p: float = 0.9
    embedding_index_path: str = "database/ai_case_embeddings.jsonl"
    max_text_chars: int = 4500
    max_files_per_event: int = 30


def load_config(config_path: Path = CONFIG_PATH) -> dict[str, Any]:
    """Load full YAML configuration from disk."""
    if not config_path.exists():
        return {}

    with config_path.open("r", encoding="utf-8") as stream:
        payload = yaml.safe_load(stream) or {}
        return payload if isinstance(payload, dict) else {}


def load_ai_settings(config_path: Path = CONFIG_PATH) -> AISettings:
    """Read AI settings from config with compatibility fallbacks."""
    config = load_config(config_path)
    policy_cfg = config.get("policy", {}) if isinstance(config.get("policy"), dict) else {}
    ai_cfg = config.get("ai_agent", {}) if isinstance(config.get("ai_agent"), dict) else {}

    legacy_model = _as_str(ai_cfg.get("model"), default="")
    text_model = _as_str(ai_cfg.get("text_model"), default=legacy_model or AISettings.text_model)
    vision_model = _as_str(ai_cfg.get("vision_model"), default=legacy_model or AISettings.vision_model)
    embeddings_model = _as_str(ai_cfg.get("embeddings_model"), default=AISettings.embeddings_model)

    return AISettings(
        enabled=bool(ai_cfg.get("enabled", policy_cfg.get("enable_ai_agent", False))),
        text_model=text_model,
        vision_model=vision_model,
        embeddings_model=embeddings_model,
        timeout_seconds=_as_int(ai_cfg.get("timeout_seconds"), default=AISettings.timeout_seconds, minimum=3, maximum=180),
        temperature=_as_float(ai_cfg.get("temperature"), default=AISettings.temperature, minimum=0.0, maximum=2.0),
        top_p=_as_float(ai_cfg.get("top_p"), default=AISettings.top_p, minimum=0.05, maximum=1.0),
        embedding_index_path=_as_str(ai_cfg.get("embedding_index_path"), default=AISettings.embedding_index_path),
        max_text_chars=_as_int(ai_cfg.get("max_text_chars"), default=AISettings.max_text_chars, minimum=512, maximum=20000),
        max_files_per_event=_as_int(ai_cfg.get("max_files_per_event"), default=AISettings.max_files_per_event, minimum=1, maximum=200),
    )


def apply_ai_settings_to_config(config: dict[str, Any], settings: AISettings) -> dict[str, Any]:
    """Write AI settings into config dictionary and keep legacy compatibility."""
    cfg = dict(config)
    policy_cfg = cfg.get("policy") if isinstance(cfg.get("policy"), dict) else {}
    ai_cfg = cfg.get("ai_agent") if isinstance(cfg.get("ai_agent"), dict) else {}

    policy_cfg["enable_ai_agent"] = bool(settings.enabled)

    ai_cfg["enabled"] = bool(settings.enabled)
    ai_cfg["text_model"] = str(settings.text_model)
    ai_cfg["vision_model"] = str(settings.vision_model)
    ai_cfg["embeddings_model"] = str(settings.embeddings_model)
    ai_cfg["timeout_seconds"] = int(settings.timeout_seconds)
    ai_cfg["temperature"] = float(settings.temperature)
    ai_cfg["top_p"] = float(settings.top_p)
    ai_cfg["embedding_index_path"] = str(settings.embedding_index_path)
    ai_cfg["max_text_chars"] = int(settings.max_text_chars)
    ai_cfg["max_files_per_event"] = int(settings.max_files_per_event)

    cfg["policy"] = policy_cfg
    cfg["ai_agent"] = ai_cfg
    return cfg


def save_ai_settings(settings: AISettings, config_path: Path = CONFIG_PATH) -> None:
    """Persist AI settings back to config.yaml while preserving other sections."""
    config = load_config(config_path)
    merged = apply_ai_settings_to_config(config, settings)
    with config_path.open("w", encoding="utf-8") as stream:
        yaml.safe_dump(merged, stream, sort_keys=False, allow_unicode=False)


def _as_str(value: Any, *, default: str) -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def _as_int(value: Any, *, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _as_float(value: Any, *, default: float, minimum: float, maximum: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))
