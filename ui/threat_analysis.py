"""
hid_shield.ui.threat_analysis
=============================
Threat Analysis screen (Screen 3) shown after scan completion.

Design
------
* Split-view layout:
  - Left 40%: FileTreeWidget with color-coded threat rows
  - Right 60%: DetailPanel with deep metadata
* Top band includes a large RiskGauge and a custom donut chart breakdown.
* Listens to global ``event_bus.scan_completed`` and auto-populates results.
* Supports SIMULATION_MODE with realistic synthetic scan rows.
"""

from __future__ import annotations

import os
import random
from pathlib import Path
from typing import Any

import yaml
from PySide6.QtCore import QEasingCurve, QTimer, Qt, QVariantAnimation
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QSplitter,
    QVBoxLayout,
    QWidget,
)
from sqlalchemy import desc

from core.event_bus import event_bus
from database.db import get_db
from database.models import DeviceEvent, FileScanResult
from ui.styles.theme import Theme
from ui.widgets.detail_panel import DetailPanel
from ui.widgets.file_tree_widget import FileTreeWidget
from ui.widgets.glass_card import GlassCard
from ui.widgets.risk_gauge import RiskGauge
from ui.widgets.threat_badge import ThreatBadge


def _is_simulation_mode() -> bool:
    """Resolve simulation mode from env override and config fallback."""
    env_val = os.getenv("HID_SHIELD_SIMULATION_MODE", "").strip().lower()
    if env_val in ("true", "1", "yes"):
        return True
    if env_val in ("false", "0", "no"):
        return False

    cfg_path = Path(__file__).resolve().parent.parent / "config.yaml"
    if cfg_path.exists():
        with open(cfg_path, "r", encoding="utf-8") as cfg_file:
            return bool((yaml.safe_load(cfg_file) or {}).get("simulation_mode", True))
    return True


class _ThreatDonutChart(QWidget):
    """Donut chart rendering low/medium/high threat distribution."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumSize(230, 230)

        self._counts: dict[str, int] = {"low": 0, "medium": 0, "high": 0}
        self._display_ratio: float = 1.0

        self._anim = QVariantAnimation(self)
        self._anim.setDuration(620)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.valueChanged.connect(self._on_anim_step)

    def set_breakdown(self, low: int, medium: int, high: int) -> None:
        """Update threat counts and animate chart reveal."""
        self._counts = {
            "low": max(0, int(low)),
            "medium": max(0, int(medium)),
            "high": max(0, int(high)),
        }
        self._anim.stop()
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)
        self._anim.start()

    def _on_anim_step(self, value: Any) -> None:
        """Animation callback controlling the rendered arc span factor."""
        self._display_ratio = float(value)
        self.update()

    def paintEvent(self, event: Any) -> None:  # noqa: ARG002 - Qt override
        """Draw segmented donut and centered summary text."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = self.rect().adjusted(18, 18, -18, -18)

        total = self._counts["low"] + self._counts["medium"] + self._counts["high"]
        if total <= 0:
            painter.setPen(QPen(QColor(Theme.TEXT_SECONDARY)))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No data")
            return

        segments = [
            ("low", self._counts["low"], QColor(Theme.ACCENT_GREEN)),
            ("medium", self._counts["medium"], QColor(Theme.ACCENT_AMBER)),
            ("high", self._counts["high"], QColor(Theme.ACCENT_MAGENTA)),
        ]

        start_angle = 90 * 16
        painter.setPen(Qt.PenStyle.NoPen)

        for _, count, color in segments:
            if count <= 0:
                continue
            span_degrees = int((count / total) * 360 * self._display_ratio)
            color.setAlpha(220)
            painter.setBrush(color)
            painter.drawPie(rect, start_angle, -span_degrees * 16)
            start_angle -= span_degrees * 16

        # Donut cutout
        inner = rect.adjusted(44, 44, -44, -44)
        painter.setBrush(QColor(Theme.BG_SECONDARY))
        painter.drawEllipse(inner)

        painter.setPen(QPen(QColor(Theme.TEXT_PRIMARY)))
        label_font = painter.font()
        label_font.setPointSize(18)
        label_font.setBold(True)
        painter.setFont(label_font)
        painter.drawText(inner, Qt.AlignmentFlag.AlignCenter, str(total))

        sub_rect = inner.adjusted(0, 36, 0, 0)
        sub_font = painter.font()
        sub_font.setPointSize(9)
        sub_font.setBold(False)
        painter.setFont(sub_font)
        painter.setPen(QPen(QColor(Theme.TEXT_SECONDARY)))
        painter.drawText(sub_rect, Qt.AlignmentFlag.AlignHCenter, "FILES ANALYZED")


class ThreatAnalysisScreen(QWidget):
    """Screen 3 split-view analysis module for post-scan investigation."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self._simulation_mode: bool = _is_simulation_mode()
        self._current_device_info: dict[str, Any] = {}
        self._file_rows: list[dict[str, Any]] = []

        self._build_ui()
        self._wire_signals()

    # ------------------------------------------------------------------
    # UI build
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Compose top summary region and lower split investigation layout."""
        root = QVBoxLayout(self)
        root.setContentsMargins(26, 22, 26, 22)
        root.setSpacing(18)

        # Header band
        header_card = GlassCard(glow=True)
        header_layout = QGridLayout(header_card)
        header_layout.setContentsMargins(20, 16, 20, 16)
        header_layout.setHorizontalSpacing(18)
        header_layout.setVerticalSpacing(8)

        self.header_title = QLabel("Scan Complete - Threat Analysis")
        self.header_title.setProperty("class", "h1")
        self.header_title.setStyleSheet(
            f"font-size: 30px; font-weight: 800; letter-spacing: 1px; color: {Theme.ACCENT_CYAN};"
        )

        self.device_info_label = QLabel("Awaiting scan completion event...")
        self.device_info_label.setStyleSheet(f"font-size: 14px; color: {Theme.TEXT_SECONDARY};")

        self.device_risk_badge = ThreatBadge("low")

        header_layout.addWidget(self.header_title, 0, 0)
        header_layout.addWidget(self.device_risk_badge, 0, 1, alignment=Qt.AlignmentFlag.AlignRight)
        header_layout.addWidget(self.device_info_label, 1, 0, 1, 2)

        root.addWidget(header_card)

        # Risk and donut row
        top_metrics_row = QHBoxLayout()
        top_metrics_row.setSpacing(14)

        gauge_card = GlassCard(glow=False)
        gauge_layout = QVBoxLayout(gauge_card)
        gauge_layout.setContentsMargins(16, 12, 16, 14)
        gauge_layout.setSpacing(8)

        gauge_title = QLabel("Device-Level Risk")
        gauge_title.setProperty("class", "h2")

        self.risk_gauge = RiskGauge(self)
        self.risk_gauge.setMinimumSize(250, 250)

        gauge_layout.addWidget(gauge_title)
        gauge_layout.addWidget(self.risk_gauge, alignment=Qt.AlignmentFlag.AlignCenter)

        donut_card = GlassCard(glow=False)
        donut_layout = QVBoxLayout(donut_card)
        donut_layout.setContentsMargins(16, 12, 16, 14)
        donut_layout.setSpacing(8)

        donut_title = QLabel("Threat Breakdown")
        donut_title.setProperty("class", "h2")

        self.donut = _ThreatDonutChart(self)

        legend = QLabel("LOW  MEDIUM  HIGH")
        legend.setStyleSheet(
            f"font-size: 11px; color: {Theme.TEXT_SECONDARY}; letter-spacing: 1px;"
        )

        donut_layout.addWidget(donut_title)
        donut_layout.addWidget(self.donut, alignment=Qt.AlignmentFlag.AlignCenter)
        donut_layout.addWidget(legend, alignment=Qt.AlignmentFlag.AlignCenter)

        top_metrics_row.addWidget(gauge_card, stretch=1)
        top_metrics_row.addWidget(donut_card, stretch=1)

        root.addLayout(top_metrics_row)

        # Lower split
        split = QSplitter(Qt.Orientation.Horizontal)
        split.setChildrenCollapsible(False)

        left_card = GlassCard(glow=False)
        left_layout = QVBoxLayout(left_card)
        left_layout.setContentsMargins(14, 14, 14, 14)
        left_layout.setSpacing(8)

        tree_title = QLabel("Scanned Files")
        tree_title.setProperty("class", "h2")

        self.file_tree = FileTreeWidget(self)

        left_layout.addWidget(tree_title)
        left_layout.addWidget(self.file_tree, stretch=1)

        right_card = GlassCard(glow=False)
        right_layout = QVBoxLayout(right_card)
        right_layout.setContentsMargins(14, 14, 14, 14)
        right_layout.setSpacing(8)

        detail_title = QLabel("Selected File Details")
        detail_title.setProperty("class", "h2")

        self.detail_panel = DetailPanel(self)

        right_layout.addWidget(detail_title)
        right_layout.addWidget(self.detail_panel, stretch=1)

        split.addWidget(left_card)
        split.addWidget(right_card)
        split.setSizes([40, 60])

        root.addWidget(split, stretch=1)

    def _wire_signals(self) -> None:
        """Connect global event bus and internal interactions."""
        event_bus.scan_completed.connect(self._on_scan_completed)
        self.file_tree.file_selected.connect(self.detail_panel.update_details)

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _on_scan_completed(self, device_event_id: int, summary: dict[str, Any]) -> None:
        """Hydrate the screen from incoming scan summary + DB fallback sources."""
        payload = summary if isinstance(summary, dict) else {}
        device_payload = payload.get("device")
        if isinstance(device_payload, dict):
            self._current_device_info = dict(device_payload)

        rows = payload.get("files")
        if isinstance(rows, list):
            normalized_rows = [self._normalize_file_entry(item) for item in rows if isinstance(item, dict)]
        else:
            normalized_rows = self._load_files_from_database(device_event_id)

        if not normalized_rows and self._simulation_mode:
            normalized_rows = self._generate_fake_results()

        self._apply_results(normalized_rows)

    def showEvent(self, event: Any) -> None:
        """Auto-seed screen in simulation mode for standalone testing."""
        super().showEvent(event)

        if self._simulation_mode and not self._file_rows:
            QTimer.singleShot(220, self._simulate_bootstrap)

    def _simulate_bootstrap(self) -> None:
        """Trigger a synthetic completion flow for direct screen testing."""
        self._current_device_info = {
            "device_name": "Simulated USB Composite Device",
            "serial_number": "SIM-ANALYSIS-221",
            "manufacturer": "HID Shield Lab",
        }
        rows = self._generate_fake_results()
        self._apply_results(rows)

    # ------------------------------------------------------------------
    # Data preparation
    # ------------------------------------------------------------------

    def _apply_results(self, rows: list[dict[str, Any]]) -> None:
        """Bind normalized rows into tree, detail panel, gauge, and donut chart."""
        self._file_rows = list(rows)

        self._update_header_text(rows)
        self.file_tree.populate_results(rows, animated=True)

        if rows:
            self.detail_panel.update_details(rows[0])

        risk_score = self._compute_device_risk(rows)
        self.risk_gauge.set_value(risk_score)

        low_count = sum(1 for row in rows if str(row.get("risk_level", "low")).lower() in ("safe", "low"))
        medium_count = sum(1 for row in rows if str(row.get("risk_level", "low")).lower() == "medium")
        high_count = sum(1 for row in rows if str(row.get("risk_level", "low")).lower() in ("high", "critical"))

        self.donut.set_breakdown(low_count, medium_count, high_count)

        if high_count > 0:
            self.device_risk_badge.set_risk_level("high")
        elif medium_count > 0:
            self.device_risk_badge.set_risk_level("medium")
        else:
            self.device_risk_badge.set_risk_level("low")

    def _update_header_text(self, rows: list[dict[str, Any]]) -> None:
        """Render a concise top-line device summary."""
        device_name = str(self._current_device_info.get("device_name") or "Unknown USB Device")
        serial = str(self._current_device_info.get("serial_number") or self._current_device_info.get("serial") or "n/a")
        manufacturer = str(self._current_device_info.get("manufacturer") or "Unknown")

        high_count = sum(1 for row in rows if str(row.get("risk_level", "low")).lower() in ("high", "critical"))
        medium_count = sum(1 for row in rows if str(row.get("risk_level", "low")).lower() == "medium")

        self.device_info_label.setText(
            f"Device: {device_name}   |   Serial: {serial}   |   Maker: {manufacturer}   |   "
            f"Files: {len(rows)} (High: {high_count}, Medium: {medium_count})"
        )

    def _compute_device_risk(self, rows: list[dict[str, Any]]) -> float:
        """Calculate a device-level risk score from per-file severity signals."""
        if not rows:
            return 0.0

        score = 0.0
        for row in rows:
            risk = str(row.get("risk_level") or "low").lower()
            entropy = float(row.get("entropy") or 0.0)
            malicious = bool(row.get("is_malicious") or False)

            if risk in ("critical", "high"):
                score += 18.0
            elif risk == "medium":
                score += 9.0
            else:
                score += 2.5

            if entropy > 7.0:
                score += 3.5
            elif entropy > 6.4:
                score += 1.8

            if malicious:
                score += 4.0

        return max(0.0, min(100.0, score / max(1.0, len(rows) / 5.5)))

    def _normalize_file_entry(self, item: dict[str, Any]) -> dict[str, Any]:
        """Normalize incoming scan dict to the schema expected by tree/detail widgets."""
        file_name = str(item.get("file_name") or "unknown.bin")
        file_path = str(item.get("file_path") or file_name)
        risk_level = str(item.get("risk_level") or "low").lower()

        entropy = item.get("entropy")
        if entropy is None:
            entropy = float(item.get("shannon_entropy") or 0.0)

        indicators = item.get("indicators")
        if not isinstance(indicators, list):
            indicators = []

        yara_matches = item.get("yara_matches")
        if not isinstance(yara_matches, list):
            yara_matches = []

        pe_imports = item.get("pe_imports")
        if not isinstance(pe_imports, list):
            pe_imports = []

        normalized = {
            "file_name": file_name,
            "file_path": file_path,
            "file_type": str(item.get("file_type") or self._infer_type(file_name)).lower(),
            "file_size_bytes": int(item.get("file_size_bytes") or item.get("size") or 0),
            "risk_level": risk_level,
            "is_malicious": bool(item.get("is_malicious") or False),
            "threat_name": str(item.get("threat_name") or ""),
            "entropy": float(entropy),
            "sha256_hash": str(item.get("sha256_hash") or item.get("hash") or "-"),
            "scan_engine": str(item.get("scan_engine") or "HIDShield Engine 1.0"),
            "indicators": [str(v) for v in indicators],
            "yara_matches": [str(v) for v in yara_matches],
            "pe_imports": [str(v) for v in pe_imports],
        }

        if normalized["is_malicious"] and normalized["threat_name"]:
            normalized["indicators"] = normalized["indicators"] + [f"Threat: {normalized['threat_name']}"]

        return normalized

    def _load_files_from_database(self, device_event_id: int) -> list[dict[str, Any]]:
        """Load latest file scan rows from DB, scoped by event when possible."""
        rows: list[dict[str, Any]] = []

        try:
            with get_db() as session:
                query = session.query(FileScanResult)

                if device_event_id > 0:
                    query = query.filter(FileScanResult.device_event_id == device_event_id)
                else:
                    latest_event = session.query(DeviceEvent).order_by(desc(DeviceEvent.id)).first()
                    if latest_event is not None:
                        device_event_id = int(latest_event.id)
                        self._current_device_info = {
                            "device_name": latest_event.device_name,
                            "serial_number": latest_event.serial,
                            "manufacturer": latest_event.manufacturer,
                        }
                        query = query.filter(FileScanResult.device_event_id == latest_event.id)

                db_rows = query.order_by(desc(FileScanResult.id)).limit(250).all()

                for db_row in db_rows:
                    threat_name = str(db_row.threat_name or "")
                    risk_level = str(db_row.risk_level or "low").lower()

                    indicators: list[str] = []
                    if db_row.is_malicious:
                        indicators.append("Malicious Signature")
                    if risk_level in ("high", "critical"):
                        indicators.append("High Severity")
                    if threat_name:
                        indicators.append(f"Family: {threat_name}")

                    normalized = {
                        "file_name": db_row.file_name,
                        "file_path": db_row.file_path,
                        "file_type": self._infer_type(db_row.file_name),
                        "file_size_bytes": int(db_row.file_size_bytes or 0),
                        "risk_level": risk_level,
                        "is_malicious": bool(db_row.is_malicious),
                        "threat_name": threat_name,
                        # Older DB rows may not have entropy stored; estimate for visual continuity.
                        "entropy": self._estimate_entropy(db_row.file_name, risk_level),
                        "sha256_hash": str(db_row.sha256_hash or "-"),
                        "scan_engine": str(db_row.scan_engine or "HIDShield Engine 1.0"),
                        "indicators": indicators,
                        "yara_matches": self._mock_yara_from_threat(threat_name, risk_level),
                        "pe_imports": self._mock_imports_from_type(db_row.file_name),
                    }
                    rows.append(normalized)
        except Exception:
            rows = []

        return rows

    def _generate_fake_results(self) -> list[dict[str, Any]]:
        """Generate realistic synthetic file scan records for SIMULATION_MODE."""
        templates: list[dict[str, Any]] = [
            {
                "file_name": "autorun.ps1",
                "file_path": "E:/scripts/autorun.ps1",
                "file_size_bytes": 28431,
                "risk_level": "high",
                "is_malicious": True,
                "threat_name": "Trojan.BadUSB.Loader",
                "entropy": 7.62,
                "sha256_hash": "9f3a6cc6aa4b5cb9f43c5b8f0f8e3bbf95bc9f9258aac16ae6d8761f715645fe",
                "indicators": ["Obfuscated Script", "Auto Execution", "PowerShell Stager"],
                "yara_matches": ["PS_Obfuscated_Invoke", "BadUSB_Dropper_Stage1"],
                "pe_imports": ["kernel32.CreateProcessW", "advapi32.RegSetValueExW"],
            },
            {
                "file_name": "invoice_apr_2026.xlsm",
                "file_path": "E:/docs/invoice_apr_2026.xlsm",
                "file_size_bytes": 128432,
                "risk_level": "medium",
                "is_malicious": False,
                "threat_name": "",
                "entropy": 6.41,
                "sha256_hash": "44a7a7f4aa7652ce3f95dfdb8f274ce8f82b0a763871dcb70f08c65af665a208",
                "indicators": ["Macro Enabled", "Suspicious VBA Pattern"],
                "yara_matches": ["Office_Macro_Downloader"],
                "pe_imports": [],
            },
            {
                "file_name": "firmware_update.exe",
                "file_path": "E:/tools/firmware_update.exe",
                "file_size_bytes": 582193,
                "risk_level": "critical",
                "is_malicious": True,
                "threat_name": "Ransom.Dropper.Injector",
                "entropy": 7.88,
                "sha256_hash": "d5fcd8f6e47f3224f0d8a6d6f77042467c52a90ef79d40f7aa64967b3a5dd8bd",
                "indicators": ["Packed Binary", "Reflective Injection", "C2 Beacon Strings"],
                "yara_matches": ["PE_Packer_Themida", "Ransom_Inj_Stub"],
                "pe_imports": [
                    "kernel32.VirtualAlloc",
                    "kernel32.WriteProcessMemory",
                    "kernel32.CreateRemoteThread",
                    "ws2_32.connect",
                ],
            },
            {
                "file_name": "readme.txt",
                "file_path": "E:/readme.txt",
                "file_size_bytes": 1742,
                "risk_level": "low",
                "is_malicious": False,
                "threat_name": "",
                "entropy": 3.22,
                "sha256_hash": "d6ca4e85ee901948f89ef31d4dcf6bb0937ed9fcecb9f29eddbf8f5c113f2fc0",
                "indicators": ["Benign Text"],
                "yara_matches": [],
                "pe_imports": [],
            },
            {
                "file_name": "driver_patch.dll",
                "file_path": "E:/bin/driver_patch.dll",
                "file_size_bytes": 221904,
                "risk_level": "medium",
                "is_malicious": False,
                "threat_name": "",
                "entropy": 6.08,
                "sha256_hash": "a531f454f6d2c45e4f8fca4f88b1f8ec2ea659a6a7f9f6b9249162b96f6c9fc2",
                "indicators": ["Unsigned DLL", "Privilege API Access"],
                "yara_matches": ["DLL_Sideloading_Pattern"],
                "pe_imports": ["advapi32.OpenProcessToken", "shell32.ShellExecuteW"],
            },
        ]

        # Shuffle to make repeated simulations feel more realistic.
        random.shuffle(templates)
        return [self._normalize_file_entry(entry) for entry in templates]

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def _infer_type(self, file_name: str) -> str:
        """Infer file type from suffix."""
        suffix = Path(file_name).suffix.lower()
        if suffix in (".exe", ".dll", ".sys"):
            return suffix.lstrip(".")
        if suffix in (".ps1", ".bat", ".cmd", ".js", ".vbs"):
            return "script"
        if suffix in (".zip", ".rar", ".7z"):
            return "archive"
        if suffix in (".doc", ".docx", ".xls", ".xlsx", ".xlsm", ".pdf", ".txt"):
            return "doc"
        return "file"

    def _estimate_entropy(self, file_name: str, risk_level: str) -> float:
        """Estimate entropy for DB rows that do not store this metric yet."""
        suffix = Path(file_name).suffix.lower()
        base = 3.4 if suffix in (".txt", ".md") else 5.4

        risk = risk_level.lower()
        if risk in ("critical", "high"):
            base += 2.0
        elif risk == "medium":
            base += 0.9

        return max(0.0, min(8.0, base + random.uniform(-0.25, 0.25)))

    def _mock_yara_from_threat(self, threat_name: str, risk_level: str) -> list[str]:
        """Provide deterministic fallback YARA-like matches for DB-only rows."""
        if threat_name:
            return [f"Signature_{threat_name.replace('.', '_')}"]

        level = risk_level.lower()
        if level in ("critical", "high"):
            return ["Generic_Packed_PE"]
        if level == "medium":
            return ["Suspicious_Office_Macro"]
        return []

    def _mock_imports_from_type(self, file_name: str) -> list[str]:
        """Derive plausible import list from file extension for detail rendering."""
        suffix = Path(file_name).suffix.lower()
        if suffix in (".exe", ".dll"):
            return ["kernel32.LoadLibraryA", "kernel32.GetProcAddress"]
        if suffix in (".ps1", ".bat", ".cmd"):
            return ["powershell.Invoke-Expression"]
        return []
