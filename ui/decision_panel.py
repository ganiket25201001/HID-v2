"""Decision panel for operator approval and USB access gating."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, QRect, Qt
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import QFileDialog, QGridLayout, QHBoxLayout, QLabel, QVBoxLayout, QWidget, QInputDialog, QLineEdit

from core.event_bus import event_bus
from database.db import get_db
from database.repository import DeviceRepository, FileScanRepository
from security.auth_manager import AuthManager
from ui.styles.theme import Theme
from ui.widgets.animated_button import AnimatedButton
from ui.widgets.glass_card import GlassCard
from ui.widgets.risk_gauge import RiskGauge
from ui.widgets.threat_badge import ThreatBadge


class DecisionPanel(QWidget):
    """Modal decision gate shown after scan completion."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._last_event_id = 0
        self._device_payload: dict[str, Any] = {}
        self._scan_files: list[dict[str, Any]] = []
        self._slide_anim: QPropertyAnimation | None = None
        self._auth_manager = AuthManager()

        self._build_ui()
        self._wire_signals()

    def _build_ui(self) -> None:
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet("background: transparent;")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 20, 24, 20)

        self.shell = QWidget(self)
        self.shell.setObjectName("decisionPanelShell")
        self.shell.setStyleSheet(
            f"""
            QWidget#decisionPanelShell {{
                background-color: rgba(10, 14, 23, 245);
                border: 2px solid {Theme.ACCENT_CYAN};
                border-radius: 18px;
            }}
            """
        )

        shell_layout = QVBoxLayout(self.shell)
        shell_layout.setContentsMargins(18, 16, 18, 16)
        shell_layout.setSpacing(14)

        head = GlassCard(glow=True)
        head_layout = QHBoxLayout(head)
        head_layout.setContentsMargins(16, 12, 16, 12)

        left = QVBoxLayout()
        self.title = QLabel("Approval Required Before USB Access")
        self.title.setStyleSheet(f"font-size: 27px; font-weight: 800; color: {Theme.ACCENT_CYAN};")
        self.device_label = QLabel("Device: waiting...")
        self.device_label.setStyleSheet(f"font-size: 14px; color: {Theme.TEXT_PRIMARY};")
        self.serial_label = QLabel("Serial: n/a")
        self.serial_label.setStyleSheet(f"font-size: 13px; color: {Theme.TEXT_SECONDARY};")

        left.addWidget(self.title)
        left.addWidget(self.device_label)
        left.addWidget(self.serial_label)

        self.overall_badge = ThreatBadge("low")

        head_layout.addLayout(left, stretch=1)
        head_layout.addWidget(self.overall_badge, alignment=Qt.AlignmentFlag.AlignTop)
        shell_layout.addWidget(head)

        metrics = QHBoxLayout()
        metrics.setSpacing(12)

        grid_host = QWidget(self)
        grid = QGridLayout(grid_host)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(10)

        self.total_card, self.total_value = self._metric_card("Total Files", Theme.ACCENT_CYAN)
        self.safe_card, self.safe_value = self._metric_card("Safe", Theme.ACCENT_GREEN)
        self.susp_card, self.susp_value = self._metric_card("Suspicious", Theme.ACCENT_AMBER)
        self.danger_card, self.danger_value = self._metric_card("Dangerous", Theme.ACCENT_MAGENTA)

        grid.addWidget(self.total_card, 0, 0)
        grid.addWidget(self.safe_card, 0, 1)
        grid.addWidget(self.susp_card, 1, 0)
        grid.addWidget(self.danger_card, 1, 1)

        gauge_card = GlassCard(glow=False)
        gauge_layout = QVBoxLayout(gauge_card)
        gauge_layout.setContentsMargins(12, 10, 12, 10)
        gauge_layout.addWidget(QLabel("Overall Risk"))
        self.risk_gauge = RiskGauge(self)
        gauge_layout.addWidget(self.risk_gauge, alignment=Qt.AlignmentFlag.AlignCenter)

        metrics.addWidget(grid_host, stretch=3)
        metrics.addWidget(gauge_card, stretch=2)
        shell_layout.addLayout(metrics)

        actions = QHBoxLayout()
        actions.setSpacing(10)

        self.allow_safe_btn = AnimatedButton("Allow Safe Files Only", accent_color=Theme.ACCENT_GREEN)
        self.manage_susp_btn = AnimatedButton("Manage Suspicious Files", accent_color=Theme.ACCENT_AMBER)
        self.block_all_btn = AnimatedButton("Block All & Eject", accent_color=Theme.ACCENT_MAGENTA)
        self.grant_full_btn = AnimatedButton("Grant Full Access", accent_color=Theme.ACCENT_CYAN)

        for b in (self.allow_safe_btn, self.manage_susp_btn, self.block_all_btn, self.grant_full_btn):
            b.setMinimumHeight(52)
            actions.addWidget(b)

        shell_layout.addLayout(actions)

        bottom = QHBoxLayout()
        self.export_report_btn = AnimatedButton("Export Threat Report", accent_color=Theme.ACCENT_CYAN)
        self.export_report_btn.setMinimumHeight(40)
        self.close_btn = AnimatedButton("Close", accent_color=Theme.TEXT_SECONDARY)
        self.close_btn.setMinimumHeight(40)
        bottom.addStretch(1)
        bottom.addWidget(self.export_report_btn)
        bottom.addWidget(self.close_btn)
        shell_layout.addLayout(bottom)

        self.status_label = QLabel("Waiting for scan result...")
        self.status_label.setStyleSheet(f"font-size: 13px; color: {Theme.TEXT_SECONDARY};")
        shell_layout.addWidget(self.status_label)

        outer.addWidget(self.shell)

    def _metric_card(self, title: str, color: str) -> tuple[GlassCard, QLabel]:
        card = GlassCard(glow=False)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.addWidget(QLabel(title))
        value = QLabel("0")
        value.setStyleSheet(f"font-size: 28px; font-weight: 800; color: {color};")
        layout.addWidget(value)
        return card, value

    def _wire_signals(self) -> None:
        event_bus.usb_device_inserted.connect(self._on_usb_inserted)
        event_bus.scan_completed.connect(self._on_scan_completed)

        self.allow_safe_btn.clicked.connect(self._allow_safe_files_only)
        self.manage_susp_btn.clicked.connect(self._manage_suspicious_files)
        self.block_all_btn.clicked.connect(self._block_all_and_eject)
        self.grant_full_btn.clicked.connect(self._grant_full_access)
        self.export_report_btn.clicked.connect(self._export_threat_report)
        self.close_btn.clicked.connect(self.hide)

    def _on_usb_inserted(self, payload: dict[str, Any]) -> None:
        self._device_payload = dict(payload)

    def _on_scan_completed(self, event_id: int, summary: dict[str, Any]) -> None:
        self._last_event_id = int(event_id)
        if isinstance(summary, dict):
            device = summary.get("device")
            if isinstance(device, dict):
                self._device_payload = dict(device)
            files = summary.get("files")
            if isinstance(files, list):
                self._scan_files = [f for f in files if isinstance(f, dict)]
            else:
                self._scan_files = self._load_rows_from_repo(event_id)
        else:
            self._scan_files = self._load_rows_from_repo(event_id)

        self._apply_results()
        self._show_with_slide()

        event_bus.decision_panel_refresh_requested.emit({"event_id": event_id, "summary": summary})

    def _load_rows_from_repo(self, event_id: int) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        try:
            with get_db() as session:
                for r in FileScanRepository.get_scans_for_event(int(event_id), session=session):
                    rows.append(
                        {
                            "file_name": r.file_name,
                            "file_path": r.file_path,
                            "file_size_bytes": int(r.file_size_bytes or 0),
                            "risk_level": str(r.risk_level or "low").lower(),
                            "entropy": 0.0,
                            "threat_name": str(r.threat_name or ""),
                            "is_malicious": bool(r.is_malicious),
                            "scan_engine": str(r.scan_engine or "HIDShield Engine"),
                            "sha256_hash": str(r.sha256_hash or "-"),
                            "explanation": str(r.notes or ""),
                        }
                    )
        except Exception:
            rows = []
        return rows

    def _apply_results(self) -> None:
        dname = str(self._device_payload.get("device_name") or "Unknown USB")
        serial = str(self._device_payload.get("serial_number") or self._device_payload.get("serial") or "n/a")
        self.device_label.setText(f"Device: {dname}")
        self.serial_label.setText(f"Serial: {serial}")

        total = len(self._scan_files)
        safe = sum(1 for f in self._scan_files if str(f.get("risk_level", "low")).lower() in {"safe", "low"})
        susp = sum(1 for f in self._scan_files if str(f.get("risk_level", "low")).lower() == "medium")
        danger = sum(1 for f in self._scan_files if str(f.get("risk_level", "low")).lower() in {"high", "critical", "dangerous"})

        self.total_value.setText(str(total))
        self.safe_value.setText(str(safe))
        self.susp_value.setText(str(susp))
        self.danger_value.setText(str(danger))

        if danger > 0:
            self.overall_badge.set_risk_level("high")
            self.risk_gauge.set_value(84.0)
        elif susp > 0:
            self.overall_badge.set_risk_level("medium")
            self.risk_gauge.set_value(58.0)
        else:
            self.overall_badge.set_risk_level("low")
            self.risk_gauge.set_value(24.0)

        self.status_label.setText("Decision required: USB remains blocked until approval.")

    def _show_with_slide(self) -> None:
        if self.parentWidget() is not None:
            prect = self.parentWidget().rect()
        else:
            prect = QRect(0, 0, 1280, 800)

        target = QRect(int(prect.width() * 0.03), int(prect.height() * 0.03), int(prect.width() * 0.94), int(prect.height() * 0.94))
        start = QRect(target.x(), prect.height() + 24, target.width(), target.height())

        self.setGeometry(start)
        self.show()
        self.raise_()

        self._slide_anim = QPropertyAnimation(self, b"geometry", self)
        self._slide_anim.setDuration(400)
        self._slide_anim.setStartValue(start)
        self._slide_anim.setEndValue(target)
        self._slide_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._slide_anim.start()

    def _request_security_key(self) -> bool:
        key, ok = QInputDialog.getText(
            self,
            "Security Key Required",
            "Enter Security Key to authorize this action:",
            QLineEdit.EchoMode.Password
        )
        if ok and key:
            if self._auth_manager.verify_security_key(key):
                return True
            else:
                self.status_label.setText("Invalid security key entered. Action blocked.")
                return False
        self.status_label.setText("Action cancelled.")
        return False

    def _allow_safe_files_only(self) -> None:
        if not self._request_security_key():
            return
        self.status_label.setText("Safe files approved. USB access enabled for approved items.")
        event_bus.policy_action_applied.emit(self._last_event_id, "allow_safe")
        event_bus.device_access_state_changed.emit(self._last_event_id, "allow")
        self._update_action("allow")

    def _manage_suspicious_files(self) -> None:
        if not self._request_security_key():
            return
        self.status_label.setText("Threat-focused review enabled. USB remains blocked until allow action.")
        event_bus.policy_action_applied.emit(self._last_event_id, "review")

    def _block_all_and_eject(self) -> None:
        if not self._request_security_key():
            return
        self.status_label.setText("All files blocked. USB access remains denied.")
        event_bus.policy_action_applied.emit(self._last_event_id, "block")
        event_bus.device_access_state_changed.emit(self._last_event_id, "block")
        self._update_action("block")

    def _grant_full_access(self) -> None:
        if not self._request_security_key():
            return
        self.status_label.setText("Full access granted by operator.")
        event_bus.policy_action_applied.emit(self._last_event_id, "allow")
        event_bus.device_access_state_changed.emit(self._last_event_id, "allow")
        self._update_action("allow")

    def _update_action(self, action: str) -> None:
        if self._last_event_id <= 0:
            return
        try:
            with get_db() as session:
                DeviceRepository.update_action(session, self._last_event_id, action)
        except Exception:
            pass

    def _export_threat_report(self) -> None:
        if not self._scan_files:
            self.status_label.setText("No files available to export.")
            return

        default_name = f"hidshield_threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        output, _ = QFileDialog.getSaveFileName(self, "Export Threat Report", str((Path.cwd() / default_name).resolve()), "JSON Files (*.json)")
        if not output:
            self.status_label.setText("Export cancelled.")
            return

        payload = {
            "event_id": self._last_event_id,
            "device": self._device_payload,
            "exported_at": datetime.now().isoformat(),
            "files": self._scan_files,
            "selected_files": [],
        }

        try:
            Path(output).write_text(json.dumps(payload, indent=2), encoding="utf-8")
            self.status_label.setText(f"Threat report exported: {output}")
        except Exception as exc:
            self.status_label.setText(f"Export failed: {exc}")

            self.status_label.setText(f"Export failed: {exc}")

    def paintEvent(self, event: Any) -> None:
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(4, 8, 14, 170))
        painter.drawRect(self.rect())
