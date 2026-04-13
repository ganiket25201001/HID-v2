"""Logs and reports screen with working filters, cleanup, and PDF export."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtCore import QDate
from PySide6.QtWidgets import QComboBox, QDateEdit, QHBoxLayout, QLabel, QTabWidget, QVBoxLayout, QWidget

from core.event_bus import event_bus
from database.db import get_db
from database.models import DeviceEvent, FileScanResult, SystemAlert
from database.repository import AlertRepository, DeviceRepository, FileScanRepository
from reports import PDFExporter
from ui.styles.theme import Theme
from ui.widgets.animated_button import AnimatedButton
from ui.widgets.glass_card import GlassCard
from ui.widgets.log_table_widget import LogTableWidget


class LogsScreen(QWidget):
    """Operational history screen with export and maintenance actions."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._device_rows: list[dict[str, Any]] = []
        self._scan_rows: list[dict[str, Any]] = []
        self._alert_rows: list[dict[str, Any]] = []

        self._build_ui()
        self._wire_signals()
        self.refresh_all_tables()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 18, 24, 18)
        root.setSpacing(12)

        toolbar = GlassCard(glow=True)
        bar = QHBoxLayout(toolbar)
        bar.setContentsMargins(14, 10, 14, 10)
        bar.setSpacing(10)

        title = QLabel("Logs & Reports")
        title.setStyleSheet(f"font-size: 26px; font-weight: 800; color: {Theme.ACCENT_CYAN};")

        self.export_pdf_btn = AnimatedButton("Export PDF", accent_color=Theme.ACCENT_CYAN)
        self.select_all_btn = AnimatedButton("Select All", accent_color=Theme.ACCENT_GREEN)
        self.clear_selection_btn = AnimatedButton("Clear Selection", accent_color=Theme.TEXT_SECONDARY)
        self.clear_logs_btn = AnimatedButton("Clear Old Logs", accent_color=Theme.ACCENT_MAGENTA)
        self.apply_date_filter_btn = AnimatedButton("Apply Date Filter", accent_color=Theme.ACCENT_AMBER)

        self.risk_filter_combo = QComboBox(self)
        self.risk_filter_combo.addItems(["All", "Safe", "Low", "Medium", "High", "Critical", "Dangerous"])

        self.from_date_edit = QDateEdit(self)
        self.from_date_edit.setCalendarPopup(True)
        self.from_date_edit.setDisplayFormat("yyyy-MM-dd")
        self.from_date_edit.setDate(QDate.currentDate().addDays(-7))

        self.to_date_edit = QDateEdit(self)
        self.to_date_edit.setCalendarPopup(True)
        self.to_date_edit.setDisplayFormat("yyyy-MM-dd")
        self.to_date_edit.setDate(QDate.currentDate())

        for w in (
            self.export_pdf_btn,
            self.select_all_btn,
            self.clear_selection_btn,
            self.clear_logs_btn,
            self.apply_date_filter_btn,
            self.risk_filter_combo,
            self.from_date_edit,
            self.to_date_edit,
        ):
            w.setMinimumHeight(38)

        bar.addWidget(title)
        bar.addStretch(1)
        bar.addWidget(QLabel("Risk"))
        bar.addWidget(self.risk_filter_combo)
        bar.addWidget(QLabel("From"))
        bar.addWidget(self.from_date_edit)
        bar.addWidget(QLabel("To"))
        bar.addWidget(self.to_date_edit)
        bar.addWidget(self.apply_date_filter_btn)
        bar.addWidget(self.select_all_btn)
        bar.addWidget(self.clear_selection_btn)
        bar.addWidget(self.clear_logs_btn)
        bar.addWidget(self.export_pdf_btn)

        root.addWidget(toolbar)

        self.tabs = QTabWidget(self)
        self.device_table = LogTableWidget(self)
        self.device_table.set_headers(["Timestamp", "Device", "Type", "Risk", "Action"])
        self.file_table = LogTableWidget(self)
        self.file_table.enable_checkboxes(True, header="Pick")
        self.file_table.set_headers(["Timestamp", "File", "Risk", "Threat", "Engine"])
        self.alert_table = LogTableWidget(self)
        self.alert_table.set_headers(["Timestamp", "Severity", "Category", "Title", "Message"])

        self.tabs.addTab(self._table_card(self.device_table), "Device History")
        self.tabs.addTab(self._table_card(self.file_table), "File Scans")
        self.tabs.addTab(self._table_card(self.alert_table), "System Alerts")

        root.addWidget(self.tabs, stretch=1)

        self.status = QLabel("Logs ready")
        self.status.setStyleSheet(f"font-size: 13px; color: {Theme.TEXT_SECONDARY};")
        root.addWidget(self.status)

    def _table_card(self, table: LogTableWidget) -> QWidget:
        card = GlassCard(glow=False)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.addWidget(table)
        return card

    def _wire_signals(self) -> None:
        self.export_pdf_btn.clicked.connect(self.export_pdf_report)
        self.select_all_btn.clicked.connect(self._select_all_file_rows)
        self.clear_selection_btn.clicked.connect(self._clear_file_row_selection)
        self.clear_logs_btn.clicked.connect(self.clear_old_logs)
        self.apply_date_filter_btn.clicked.connect(self.apply_date_filter)
        self.risk_filter_combo.currentTextChanged.connect(self.apply_risk_filter)

        event_bus.scan_completed.connect(lambda _id, _summary: self.refresh_all_tables())
        event_bus.threat_detected.connect(lambda _payload: self.refresh_all_tables())
        event_bus.policy_action_applied.connect(lambda _id, _action: self.refresh_all_tables())
        event_bus.logs_refresh_requested.connect(lambda _payload: self.refresh_all_tables())

    def refresh_all_tables(self) -> None:
        self._device_rows = self._load_device_history_rows()
        self._scan_rows = self._load_file_scan_rows()
        self._alert_rows = self._load_alert_rows()

        self.device_table.set_rows(self._device_rows)
        self.file_table.set_rows(self._scan_rows)
        self.alert_table.set_rows(self._alert_rows)

        self.apply_risk_filter(self.risk_filter_combo.currentText())
        self.apply_date_filter()

        self.status.setText(
            f"Loaded: devices={len(self._device_rows)} scans={len(self._scan_rows)} alerts={len(self._alert_rows)}"
        )

    def _load_device_history_rows(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        try:
            with get_db() as session:
                events = DeviceRepository.get_recent_events(limit=500, session=session)
                for event in events:
                    ts = event.timestamp if isinstance(event.timestamp, datetime) else datetime.now()
                    out.append(
                        {
                            "timestamp": ts,
                            "risk_level": str(getattr(event.risk_level, "value", event.risk_level) or "low").lower(),
                            "columns": [
                                ts.strftime("%Y-%m-%d %H:%M:%S"),
                                str(event.device_name or "Unknown Device"),
                                str(getattr(event.device_type, "value", event.device_type) or "unknown").title(),
                                str(getattr(event.risk_level, "value", event.risk_level) or "low").upper(),
                                str(getattr(event.action_taken, "value", event.action_taken) or "prompt").title(),
                            ],
                        }
                    )
        except Exception:
            out = []
        return out

    def _load_file_scan_rows(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        try:
            with get_db() as session:
                recents = DeviceRepository.get_recent_events(limit=60, session=session)
                scans: list[FileScanResult] = []
                for ev in recents:
                    scans.extend(FileScanRepository.get_scans_for_event(int(ev.id), session=session))
                scans.sort(key=lambda r: r.timestamp or datetime.min, reverse=True)

                for r in scans[:1200]:
                    ts = r.timestamp if isinstance(r.timestamp, datetime) else datetime.now()
                    out.append(
                        {
                            "row_id": int(r.id),
                            "timestamp": ts,
                            "risk_level": str(getattr(r.risk_level, "value", r.risk_level) or "low").lower(),
                            "columns": [
                                ts.strftime("%Y-%m-%d %H:%M:%S"),
                                str(r.file_name or "unknown.bin"),
                                str(getattr(r.risk_level, "value", r.risk_level) or "low").upper(),
                                str(r.threat_name or "-"),
                                str(r.scan_engine or "HIDShield Engine"),
                            ],
                            "raw": {
                                "file_size_bytes": int(r.file_size_bytes or 0),
                                "risk_level": str(getattr(r.risk_level, "value", r.risk_level) or "low").lower(),
                                "threat_name": str(r.threat_name or ""),
                            },
                        }
                    )
        except Exception:
            out = []
        return out

    def _load_alert_rows(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        try:
            with get_db() as session:
                alerts = AlertRepository.get_recent_alerts(limit=600, session=session)
                for a in alerts:
                    ts = a.timestamp if isinstance(a.timestamp, datetime) else datetime.now()
                    sev = str(a.severity or "info").lower()
                    risk = "high" if sev in {"critical", "error"} else ("medium" if sev == "warning" else "low")
                    out.append(
                        {
                            "timestamp": ts,
                            "risk_level": risk,
                            "columns": [
                                ts.strftime("%Y-%m-%d %H:%M:%S"),
                                sev.upper(),
                                str(getattr(a.category, "value", a.category) or "system").title(),
                                str(a.title or "Alert"),
                                str(a.message or ""),
                            ],
                        }
                    )
        except Exception:
            out = []
        return out

    def apply_risk_filter(self, text: str) -> None:
        risk = (text or "all").strip().lower()
        self.device_table.set_risk_filter(risk)
        self.file_table.set_risk_filter(risk)
        self.alert_table.set_risk_filter(risk)
        self.status.setText(f"Risk filter applied: {text}")

    def apply_date_filter(self) -> None:
        from_py = self.from_date_edit.date().toPython()
        to_py = self.to_date_edit.date().toPython()

        if from_py > to_py:
            from_py, to_py = to_py, from_py
            self.from_date_edit.setDate(QDate(from_py.year, from_py.month, from_py.day))
            self.to_date_edit.setDate(QDate(to_py.year, to_py.month, to_py.day))

        self.device_table.set_date_filter(from_py, to_py)
        self.file_table.set_date_filter(from_py, to_py)
        self.alert_table.set_date_filter(from_py, to_py)
        self.status.setText(f"Date filter applied: {from_py.isoformat()} to {to_py.isoformat()}")

    def clear_old_logs(self) -> None:
        cutoff = self.from_date_edit.date().toPython()
        cutoff_dt = datetime.combine(cutoff, datetime.min.time())
        try:
            with get_db() as session:
                session.query(FileScanResult).filter(FileScanResult.timestamp < cutoff_dt).delete(synchronize_session=False)
                session.query(SystemAlert).filter(SystemAlert.timestamp < cutoff_dt).delete(synchronize_session=False)
                session.query(DeviceEvent).filter(DeviceEvent.timestamp < cutoff_dt).delete(synchronize_session=False)
            self.status.setText(f"Cleared logs older than {cutoff.isoformat()}")
            self.refresh_all_tables()
        except Exception as exc:
            self.status.setText(f"Failed to clear logs: {exc}")

    def export_pdf_report(self) -> None:
        visible = self.file_table.get_visible_rows()
        if not visible:
            self.status.setText("No visible file-scan rows to export")
            return

        checked_visible = self.file_table.get_checked_visible_rows()
        rows_for_export = checked_visible if checked_visible else visible

        try:
            device_name = "Unknown USB Device"
            risk_level = "low"
            if self._device_rows:
                cols = self._device_rows[0].get("columns", [])
                if len(cols) > 1:
                    device_name = str(cols[1])
                if len(cols) > 3:
                    risk_level = str(cols[3]).lower()

            pdf_rows: list[dict[str, Any]] = []
            for row in rows_for_export[:300]:
                cols = row.get("columns", [])
                raw = row.get("raw", {})
                pdf_rows.append(
                    {
                        "file_name": cols[1] if len(cols) > 1 else "unknown.bin",
                        "risk_level": str(raw.get("risk_level") or (cols[2].lower() if len(cols) > 2 else "low")),
                        "entropy": 0.0,
                        "file_size_bytes": int(raw.get("file_size_bytes") or 0),
                        "explanation": cols[3] if len(cols) > 3 else "No indicator text",
                    }
                )

            exporter = PDFExporter(output_dir=Path.cwd())
            out = exporter.export_report(
                device_metadata={
                    "device_name": device_name,
                    "serial": "N/A",
                    "manufacturer": "Unknown",
                    "risk_level": risk_level,
                },
                file_rows=pdf_rows,
                ml_confidence=0.78,
                user_decision="Operator Review",
            )
            if checked_visible:
                self.status.setText(f"PDF exported ({len(rows_for_export)} selected rows): {out}")
            else:
                self.status.setText(f"PDF exported ({len(rows_for_export)} rows): {out}")
        except Exception as exc:
            self.status.setText(f"PDF export failed: {exc}")

    def _select_all_file_rows(self) -> None:
        """Select all currently visible file-scan rows via checkbox."""
        self.file_table.select_all_visible_rows()
        count = len(self.file_table.get_checked_visible_rows())
        self.status.setText(f"Selected {count} visible file row(s)")

    def _clear_file_row_selection(self) -> None:
        """Clear all selected file-scan row checkboxes."""
        self.file_table.clear_all_checked_rows()
        self.status.setText("Cleared file-row selection")
