"""
hid_shield.ui.decision_panel
============================
Screen 4: Critical decision gate shown after scan completion.

Design
------
* Modal-style full-screen overlay with a dramatic glowing header.
* Displays device identity, summary cards, approval table, and risk gauge.
* Provides four high-impact action buttons for operator decisions.
* Integrates with global ``event_bus`` and database/repository layers.
* In ``SIMULATION_MODE`` auto-populates realistic synthetic scan rows.
"""

from __future__ import annotations

import ctypes
import json
import math
import os
import random
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from PySide6.QtCore import QEasingCurve, QPropertyAnimation, QRect, Qt, QTimer
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from core.event_bus import event_bus
from database.db import get_db
from database.repository import DeviceRepository, FileScanRepository
from ui.styles.theme import Theme
from ui.widgets.animated_button import AnimatedButton
from ui.widgets.file_approval_table import FileApprovalTable
from ui.widgets.glass_card import GlassCard
from ui.widgets.risk_gauge import RiskGauge
from ui.widgets.threat_badge import ThreatBadge


def _is_simulation_mode() -> bool:
    """Resolve simulation mode from environment variable and config fallback."""
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


def _is_admin_user() -> bool:
    """Return True when the current process has administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class _AnimatedDeviceIcon(QWidget):
    """Pulsing circular USB icon used in the decision header."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(92, 92)

        self._pulse: float = 0.0
        self._timer = QTimer(self)
        self._timer.setInterval(60)
        self._timer.timeout.connect(self._tick)
        self._timer.start()

    def _tick(self) -> None:
        """Advance pulse phase and trigger repaint."""
        self._pulse += 0.08
        self.update()

    def paintEvent(self, event: Any) -> None:  # noqa: ARG002 - Qt override
        """Draw pulsing icon with subtle neon aura."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = self.rect().adjusted(6, 6, -6, -6)
        glow_alpha = int(48 + (abs(math.sin(self._pulse)) * 72))

        glow = QColor(Theme.ACCENT_CYAN)
        glow.setAlpha(glow_alpha)

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(glow)
        painter.drawEllipse(rect.adjusted(-8, -8, 8, 8))

        painter.setBrush(QColor(Theme.BG_TERTIARY))
        painter.setPen(QPen(QColor(Theme.ACCENT_CYAN), 2))
        painter.drawEllipse(rect)

        painter.setPen(QPen(QColor(Theme.ACCENT_CYAN), 3))
        c = rect.center()
        painter.drawLine(c.x(), c.y() + 20, c.x(), c.y() - 8)
        painter.drawLine(c.x(), c.y() - 8, c.x() - 12, c.y() - 20)
        painter.drawLine(c.x(), c.y() - 8, c.x() + 12, c.y() - 20)
        painter.drawEllipse(c.x() - 2, c.y() - 25, 4, 4)


class DecisionPanel(QWidget):
    """Post-scan operator decision gate with risk-aware approval controls."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self._simulation_mode: bool = _is_simulation_mode()
        self._is_admin: bool = _is_admin_user()

        self._last_device_payload: dict[str, Any] = {}
        self._scan_files: list[dict[str, Any]] = []
        self._last_event_id: int = 0
        self._slide_animation: QPropertyAnimation | None = None

        self._build_ui()
        self._wire_signals()

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Build modal overlay layout with header, summaries, and decision controls."""
        self.setObjectName("decisionPanel")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet("background: transparent;")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 22, 24, 22)
        outer.setSpacing(12)

        # Main modal shell
        self.shell = QWidget(self)
        self.shell.setObjectName("decisionPanelShell")
        self.shell.setStyleSheet(
            f"""
            QWidget#decisionPanelShell {{
                background-color: rgba(10, 14, 23, 242);
                border: 2px solid {Theme.ACCENT_CYAN};
                border-radius: 16px;
            }}
            """
        )

        shell_layout = QVBoxLayout(self.shell)
        shell_layout.setContentsMargins(18, 16, 18, 16)
        shell_layout.setSpacing(14)

        # Header block
        self.header_card = GlassCard(glow=True)
        header_layout = QHBoxLayout(self.header_card)
        header_layout.setContentsMargins(18, 14, 18, 14)
        header_layout.setSpacing(14)

        self.device_icon = _AnimatedDeviceIcon(self)
        header_layout.addWidget(self.device_icon)

        header_text_col = QVBoxLayout()
        header_text_col.setSpacing(6)

        self.title_label = QLabel("Decision Required - USB Scan Complete")
        self.title_label.setProperty("class", "h1")
        self.title_label.setStyleSheet(
            f"font-size: 28px; color: {Theme.ACCENT_CYAN}; font-weight: 800;"
        )

        self.device_label = QLabel("Device: Awaiting scan results")
        self.device_label.setStyleSheet(f"font-size: 14px; color: {Theme.TEXT_PRIMARY};")

        self.serial_label = QLabel("Serial: n/a")
        self.serial_label.setStyleSheet(f"font-size: 13px; color: {Theme.TEXT_SECONDARY};")

        header_text_col.addWidget(self.title_label)
        header_text_col.addWidget(self.device_label)
        header_text_col.addWidget(self.serial_label)

        header_layout.addLayout(header_text_col, stretch=1)

        self.overall_badge = ThreatBadge("low")
        header_layout.addWidget(self.overall_badge, alignment=Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)

        shell_layout.addWidget(self.header_card)

        # Summary + gauge row
        summary_row = QHBoxLayout()
        summary_row.setSpacing(10)

        cards_grid_host = QWidget(self)
        cards_grid = QGridLayout(cards_grid_host)
        cards_grid.setContentsMargins(0, 0, 0, 0)
        cards_grid.setHorizontalSpacing(10)
        cards_grid.setVerticalSpacing(10)

        self.total_card, self.total_value = self._summary_card("Total Files", Theme.ACCENT_CYAN)
        self.safe_card, self.safe_value = self._summary_card("Safe", Theme.ACCENT_GREEN)
        self.susp_card, self.susp_value = self._summary_card("Suspicious", Theme.ACCENT_AMBER)
        self.danger_card, self.danger_value = self._summary_card("Dangerous", Theme.ACCENT_MAGENTA)

        cards_grid.addWidget(self.total_card, 0, 0)
        cards_grid.addWidget(self.safe_card, 0, 1)
        cards_grid.addWidget(self.susp_card, 1, 0)
        cards_grid.addWidget(self.danger_card, 1, 1)

        gauge_card = GlassCard(glow=False)
        gauge_layout = QVBoxLayout(gauge_card)
        gauge_layout.setContentsMargins(12, 10, 12, 10)

        gauge_title = QLabel("Overall Device Risk")
        gauge_title.setProperty("class", "h2")

        self.risk_gauge = RiskGauge(self)
        self.risk_gauge.setMinimumSize(220, 220)

        gauge_layout.addWidget(gauge_title)
        gauge_layout.addWidget(self.risk_gauge, alignment=Qt.AlignmentFlag.AlignCenter)

        summary_row.addWidget(cards_grid_host, stretch=3)
        summary_row.addWidget(gauge_card, stretch=2)

        shell_layout.addLayout(summary_row)

        # Approval table controls + table
        self.file_table = FileApprovalTable(self)
        shell_layout.addWidget(self.file_table.build_control_bar(self))
        shell_layout.addWidget(self.file_table, stretch=1)

        # Footer actions
        footer = QVBoxLayout()
        footer.setSpacing(10)

        action_row = QHBoxLayout()
        action_row.setSpacing(10)

        self.allow_safe_btn = AnimatedButton("✅ Allow Safe Files Only", accent_color=Theme.ACCENT_GREEN)
        self.manage_susp_btn = AnimatedButton("⚠️ Manage Suspicious Files", accent_color=Theme.ACCENT_AMBER)
        self.block_all_btn = AnimatedButton("🚫 Block All & Eject", accent_color=Theme.ACCENT_MAGENTA)
        self.grant_full_btn = AnimatedButton("🔓 Grant Full Access", accent_color=Theme.ACCENT_CYAN)

        for btn in (self.allow_safe_btn, self.manage_susp_btn, self.block_all_btn, self.grant_full_btn):
            btn.setMinimumHeight(50)

        if self._simulation_mode and not self._is_admin:
            self.grant_full_btn.setDisabled(True)
            self.grant_full_btn.setToolTip("Disabled in simulation unless running as administrator")

        action_row.addWidget(self.allow_safe_btn)
        action_row.addWidget(self.manage_susp_btn)
        action_row.addWidget(self.block_all_btn)
        action_row.addWidget(self.grant_full_btn)

        report_row = QHBoxLayout()
        report_row.addStretch(1)
        self.export_report_btn = AnimatedButton("Export Threat Report", accent_color=Theme.ACCENT_CYAN)
        self.export_report_btn.setMinimumHeight(40)
        self.export_report_btn.setMinimumWidth(220)
        report_row.addWidget(self.export_report_btn)

        self.status_label = QLabel("Awaiting scan completion...")
        self.status_label.setStyleSheet(f"color: {Theme.TEXT_SECONDARY}; font-size: 12px;")

        footer.addLayout(action_row)
        footer.addLayout(report_row)
        footer.addWidget(self.status_label)

        shell_layout.addLayout(footer)

        outer.addWidget(self.shell)

    def _wire_signals(self) -> None:
        """Connect global events and local button handlers."""
        event_bus.usb_device_inserted.connect(self._on_usb_device_inserted)
        event_bus.scan_completed.connect(self._on_scan_completed)

        self.allow_safe_btn.clicked.connect(self._allow_safe_files_only)
        self.manage_susp_btn.clicked.connect(self._manage_suspicious_files)
        self.block_all_btn.clicked.connect(self._block_all_and_eject)
        self.grant_full_btn.clicked.connect(self._grant_full_access)
        self.export_report_btn.clicked.connect(self._export_threat_report)

        self.file_table.selection_summary_changed.connect(self._on_table_summary_changed)

    # ------------------------------------------------------------------
    # Summary cards
    # ------------------------------------------------------------------

    def _summary_card(self, label: str, accent: str) -> tuple[GlassCard, QLabel]:
        """Create a GlassCard summary metric widget."""
        card = GlassCard(glow=False)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 10, 14, 10)

        caption = QLabel(label)
        caption.setStyleSheet(f"font-size: 12px; color: {Theme.TEXT_SECONDARY};")

        value_lbl = QLabel("0")
        value_lbl.setStyleSheet(f"font-size: 28px; color: {accent}; font-weight: 800;")

        layout.addWidget(caption)
        layout.addWidget(value_lbl)
        return card, value_lbl

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _on_usb_device_inserted(self, payload: dict[str, Any]) -> None:
        """Cache latest detected device payload for simulation fallback."""
        self._last_device_payload = dict(payload)

    def _on_scan_completed(self, event_id: int, summary: dict[str, Any]) -> None:
        """Populate panel from scan completion payload and auto-show with animation."""
        self._last_event_id = int(event_id)

        incoming = summary if isinstance(summary, dict) else {}
        device_payload = incoming.get("device")
        if isinstance(device_payload, dict):
            self._last_device_payload = dict(device_payload)

        rows = incoming.get("files")
        normalized_rows: list[dict[str, Any]]
        if isinstance(rows, list):
            normalized_rows = [self._normalize_file_row(row) for row in rows if isinstance(row, dict)]
        else:
            normalized_rows = self._load_rows_from_repository(event_id)

        if not normalized_rows and self._simulation_mode:
            normalized_rows = self._generate_fake_rows()

        self._apply_results(normalized_rows)
        self._show_with_slide_in()

    def showEvent(self, event: Any) -> None:
        """Bootstrap synthetic data in simulation when panel is opened standalone."""
        super().showEvent(event)
        if self._simulation_mode and not self._scan_files:
            QTimer.singleShot(200, lambda: self._apply_results(self._generate_fake_rows()))

    # ------------------------------------------------------------------
    # Data loading / normalization
    # ------------------------------------------------------------------

    def _load_rows_from_repository(self, event_id: int) -> list[dict[str, Any]]:
        """Load real scan rows from repository using DB-backed event context."""
        rows: list[dict[str, Any]] = []

        try:
            with get_db() as session:
                target_event_id = int(event_id)
                if target_event_id <= 0:
                    recent_events = DeviceRepository.get_recent_events(limit=1, session=session)
                    if recent_events:
                        latest_event = recent_events[0]
                        target_event_id = int(latest_event.id)
                        self._last_device_payload = {
                            "device_name": latest_event.device_name,
                            "serial_number": latest_event.serial,
                            "manufacturer": latest_event.manufacturer,
                        }

                if target_event_id > 0:
                    scan_rows = FileScanRepository.get_scans_for_event(target_event_id, session=session)
                    rows = [
                        self._normalize_file_row(
                            {
                                "file_name": scan.file_name,
                                "file_path": scan.file_path,
                                "file_size_bytes": int(scan.file_size_bytes or 0),
                                "risk_level": str(scan.risk_level or "low"),
                                "threat_name": str(scan.threat_name or ""),
                                "is_malicious": bool(scan.is_malicious),
                                "sha256_hash": str(scan.sha256_hash or "-"),
                                "scan_engine": str(scan.scan_engine or "HIDShield Engine"),
                                "entropy": self._estimate_entropy(scan.file_name, str(scan.risk_level or "low")),
                            }
                        )
                        for scan in scan_rows
                    ]
        except Exception:
            rows = []

        return rows

    def _normalize_file_row(self, row: dict[str, Any]) -> dict[str, Any]:
        """Normalize file row payload to decision table schema."""
        risk = str(row.get("risk_level") or "low").lower()

        explanation = str(row.get("explanation") or "")
        if not explanation:
            threat_name = str(row.get("threat_name") or "")
            if threat_name:
                explanation = f"Threat signature matched: {threat_name}"
            elif risk in ("high", "critical"):
                explanation = "Dangerous execution and persistence indicators"
            elif risk == "medium":
                explanation = "Suspicious entropy/profile requiring manual approval"
            else:
                explanation = "No critical indicators detected"

        return {
            "file_name": str(row.get("file_name") or "unknown.bin"),
            "file_path": str(row.get("file_path") or "-"),
            "file_size_bytes": int(row.get("file_size_bytes") or 0),
            "risk_level": risk,
            "entropy": float(row.get("entropy") or 0.0),
            "threat_name": str(row.get("threat_name") or ""),
            "is_malicious": bool(row.get("is_malicious") or False),
            "sha256_hash": str(row.get("sha256_hash") or "-"),
            "scan_engine": str(row.get("scan_engine") or "HIDShield Engine"),
            "explanation": explanation,
            "indicators": row.get("indicators", []),
        }

    def _generate_fake_rows(self) -> list[dict[str, Any]]:
        """Generate realistic simulation rows when no live scan data is available."""
        templates = [
            {
                "file_name": "startup_sync.ps1",
                "file_path": "E:/scripts/startup_sync.ps1",
                "file_size_bytes": 23140,
                "risk_level": "high",
                "threat_name": "Trojan.Startup.Injector",
                "entropy": 7.35,
                "is_malicious": True,
                "explanation": "Obfuscated startup script with remote command stager",
            },
            {
                "file_name": "employee_policy.pdf",
                "file_path": "E:/docs/employee_policy.pdf",
                "file_size_bytes": 345672,
                "risk_level": "low",
                "entropy": 3.16,
                "is_malicious": False,
                "explanation": "Benign document with no suspicious traits",
            },
            {
                "file_name": "pricing_2026.xlsm",
                "file_path": "E:/finance/pricing_2026.xlsm",
                "file_size_bytes": 120784,
                "risk_level": "medium",
                "entropy": 6.48,
                "is_malicious": False,
                "explanation": "Macro-enabled sheet with suspicious VBA execution chain",
            },
            {
                "file_name": "driver_patch.exe",
                "file_path": "E:/bin/driver_patch.exe",
                "file_size_bytes": 694208,
                "risk_level": "critical",
                "threat_name": "Ransom.Dropper.Core",
                "entropy": 7.89,
                "is_malicious": True,
                "explanation": "Packed binary with process injection and encryption routine markers",
            },
            {
                "file_name": "readme.txt",
                "file_path": "E:/readme.txt",
                "file_size_bytes": 1432,
                "risk_level": "low",
                "entropy": 2.91,
                "is_malicious": False,
                "explanation": "Plain text metadata file",
            },
        ]

        random.shuffle(templates)
        return [self._normalize_file_row(entry) for entry in templates]

    def _estimate_entropy(self, file_name: str, risk_level: str) -> float:
        """Estimate entropy for repository rows that do not store this metric."""
        suffix = Path(file_name).suffix.lower()
        base = 3.2 if suffix in (".txt", ".md", ".pdf") else 5.4

        risk = risk_level.lower()
        if risk in ("high", "critical"):
            base += 2.0
        elif risk == "medium":
            base += 0.8

        return max(0.0, min(8.0, base + random.uniform(-0.3, 0.3)))

    # ------------------------------------------------------------------
    # UI update
    # ------------------------------------------------------------------

    def _apply_results(self, rows: list[dict[str, Any]]) -> None:
        """Apply rows to widgets and refresh summary/risk visuals."""
        self._scan_files = list(rows)
        self.file_table.set_files(rows)

        device_name = str(self._last_device_payload.get("device_name") or "Unknown USB Device")
        serial = str(self._last_device_payload.get("serial_number") or self._last_device_payload.get("serial") or "n/a")

        self.device_label.setText(f"Device: {device_name}")
        self.serial_label.setText(f"Serial: {serial}")

        total = len(rows)
        safe = sum(1 for row in rows if str(row.get("risk_level") or "low").lower() in ("safe", "low"))
        suspicious = sum(1 for row in rows if str(row.get("risk_level") or "low").lower() == "medium")
        dangerous = sum(1 for row in rows if str(row.get("risk_level") or "low").lower() in ("high", "critical"))

        self.total_value.setText(str(total))
        self.safe_value.setText(str(safe))
        self.susp_value.setText(str(suspicious))
        self.danger_value.setText(str(dangerous))

        risk_score = self._compute_risk_score(rows)
        self.risk_gauge.set_value(risk_score)

        if dangerous > 0:
            self.overall_badge.set_risk_level("high")
            self.shell.setStyleSheet(
                f"QWidget#decisionPanelShell {{ background-color: rgba(10, 14, 23, 242); border: 2px solid {Theme.ACCENT_MAGENTA}; border-radius: 16px; }}"
            )
        elif suspicious > 0:
            self.overall_badge.set_risk_level("medium")
            self.shell.setStyleSheet(
                f"QWidget#decisionPanelShell {{ background-color: rgba(10, 14, 23, 242); border: 2px solid {Theme.ACCENT_AMBER}; border-radius: 16px; }}"
            )
        else:
            self.overall_badge.set_risk_level("low")
            self.shell.setStyleSheet(
                f"QWidget#decisionPanelShell {{ background-color: rgba(10, 14, 23, 242); border: 2px solid {Theme.ACCENT_GREEN}; border-radius: 16px; }}"
            )

        self.status_label.setText("Decision required: choose an action to continue")

    def _compute_risk_score(self, rows: list[dict[str, Any]]) -> float:
        """Compute aggregate risk score from row severities and entropy."""
        if not rows:
            return 0.0

        score = 0.0
        for row in rows:
            risk = str(row.get("risk_level") or "low").lower()
            entropy = float(row.get("entropy") or 0.0)

            if risk in ("high", "critical"):
                score += 16.0
            elif risk == "medium":
                score += 8.0
            else:
                score += 2.0

            if entropy >= 7.0:
                score += 4.0
            elif entropy >= 6.3:
                score += 2.0

        normalized = score / max(1.0, len(rows) / 5.0)
        return max(0.0, min(100.0, normalized))

    # ------------------------------------------------------------------
    # Overlay behavior
    # ------------------------------------------------------------------

    def _show_with_slide_in(self) -> None:
        """Show this panel with a smooth bottom-up slide animation."""
        if self.parentWidget() is not None:
            parent_rect = self.parentWidget().rect()
        elif self.screen() is not None:
            parent_rect = self.screen().geometry()
        else:
            parent_rect = QRect(0, 0, 1280, 800)

        target = QRect(
            int(parent_rect.width() * 0.03),
            int(parent_rect.height() * 0.03),
            int(parent_rect.width() * 0.94),
            int(parent_rect.height() * 0.94),
        )
        start = QRect(target.x(), parent_rect.height() + 24, target.width(), target.height())

        self.setGeometry(start)
        self.show()
        self.raise_()

        self._slide_animation = QPropertyAnimation(self, b"geometry", self)
        self._slide_animation.setDuration(420)
        self._slide_animation.setStartValue(start)
        self._slide_animation.setEndValue(target)
        self._slide_animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._slide_animation.start()

    def paintEvent(self, event: Any) -> None:  # noqa: ARG002 - Qt override
        """Paint translucent backdrop to enforce modal-overlay visual style."""
        super().paintEvent(event)

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Dimmed backdrop
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(4, 8, 14, 170))
        painter.drawRect(self.rect())

        # Subtle cyan vignette
        frame = self.rect().adjusted(16, 12, -16, -12)
        glow_path = QPainterPath()
        glow_path.addRoundedRect(frame, 18, 18)
        painter.setBrush(QColor(0, 212, 255, 20))
        painter.drawPath(glow_path)

    # ------------------------------------------------------------------
    # Action handlers
    # ------------------------------------------------------------------

    def _allow_safe_files_only(self) -> None:
        """Allow checked safe files and emit policy action event."""
        checked = self.file_table.get_checked_files()
        allowed_safe = [
            row for row in checked if str(row.get("risk_level") or "low").lower() in ("safe", "low")
        ]

        self.status_label.setText(
            f"Allowed {len(allowed_safe)} safe file(s). Suspicious/dangerous files remain blocked pending review."
        )
        event_bus.policy_action_applied.emit(self._last_event_id, "allow")
        self._update_event_action("allow")

    def _manage_suspicious_files(self) -> None:
        """Switch table into threats-only mode for focused triage."""
        if not self.file_table.filter_threats_button.isChecked():
            self.file_table.filter_threats_button.click()
        self.status_label.setText("Threat-focused view enabled. Review suspicious and dangerous files.")

    def _block_all_and_eject(self) -> None:
        """Block all file access and emit immediate block policy action."""
        self.file_table.blockSignals(True)
        for row in range(self.file_table.rowCount()):
            item = self.file_table.item(row, 0)
            if item is not None:
                item.setCheckState(Qt.CheckState.Unchecked)
        self.file_table.blockSignals(False)

        self.status_label.setText("All files blocked. Device marked for ejection/quarantine.")
        event_bus.policy_action_applied.emit(self._last_event_id, "block")
        self._update_event_action("block")

    def _grant_full_access(self) -> None:
        """Grant full access when allowed by mode/privileges."""
        if self._simulation_mode and not self._is_admin:
            self.status_label.setText("Full access denied: admin privileges required in simulation mode.")
            return

        self.status_label.setText("Full access granted for this device session.")
        event_bus.policy_action_applied.emit(self._last_event_id, "allow")
        self._update_event_action("allow")

    def _update_event_action(self, action: str) -> None:
        """Persist high-level action decision back to the latest device event."""
        if self._last_event_id <= 0:
            return

        try:
            with get_db() as session:
                DeviceRepository.update_action(session, self._last_event_id, action)
        except Exception:
            # Keep UI responsive even when persistence fails.
            pass

    def _export_threat_report(self) -> None:
        """Export current decision context and rows into a JSON threat report."""
        if not self._scan_files:
            self.status_label.setText("No scan data available to export.")
            return

        default_name = f"hid_shield_threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        default_path = str((Path.cwd() / default_name).resolve())

        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Threat Report",
            default_path,
            "JSON Files (*.json);;All Files (*)",
        )

        if not save_path:
            self.status_label.setText("Threat report export cancelled.")
            return

        report_payload = {
            "exported_at": datetime.now().isoformat(),
            "simulation_mode": self._simulation_mode,
            "event_id": self._last_event_id,
            "device": self._last_device_payload,
            "summary": {
                "total": len(self._scan_files),
                "safe": sum(1 for row in self._scan_files if str(row.get("risk_level") or "low").lower() in ("safe", "low")),
                "suspicious": sum(1 for row in self._scan_files if str(row.get("risk_level") or "low").lower() == "medium"),
                "dangerous": sum(1 for row in self._scan_files if str(row.get("risk_level") or "low").lower() in ("high", "critical")),
            },
            "selected_files": self.file_table.get_checked_files(),
            "files": self._scan_files,
        }

        try:
            Path(save_path).write_text(json.dumps(report_payload, indent=2), encoding="utf-8")
            self.status_label.setText(f"Threat report exported: {save_path}")
        except Exception as exc:
            self.status_label.setText(f"Failed to export report: {exc}")

    def _on_table_summary_changed(self, summary: dict[str, Any]) -> None:
        """Reflect current table-selection counters in status line."""
        selected = int(summary.get("selected") or 0)
        total = int(summary.get("total") or 0)
        self.status_label.setText(f"Selected {selected}/{total} file(s) for approval.")
