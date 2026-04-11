"""Threat analysis screen with hierarchical file explorer and live updates."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QSplitter, QVBoxLayout, QWidget

from core.event_bus import event_bus
from database.db import get_db
from database.models import FileScanResult
from ui.styles.theme import Theme
from ui.widgets.detail_panel import DetailPanel
from ui.widgets.file_tree_widget import FileTreeWidget
from ui.widgets.glass_card import GlassCard
from ui.widgets.risk_gauge import RiskGauge
from ui.widgets.threat_badge import ThreatBadge


class ThreatAnalysisScreen(QWidget):
    """Show full scan result tree + rich details for selected file."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rows: list[dict[str, Any]] = []
        self._device_info: dict[str, Any] = {}
        self._build_ui()
        self._wire_signals()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(14)

        self.title = QLabel("Threat Analysis")
        self.title.setStyleSheet(f"font-size: 28px; font-weight: 800; color: {Theme.ACCENT_CYAN};")
        self.subtitle = QLabel("Awaiting scan completion event")
        self.subtitle.setStyleSheet(f"font-size: 14px; color: {Theme.TEXT_SECONDARY};")

        root.addWidget(self.title)
        root.addWidget(self.subtitle)

        # AI Insight Card (Enhanced)
        self.ai_card = GlassCard(glow=True)
        self.ai_card.setVisible(False)
        self.ai_card.setStyleSheet(
            f"""
            QFrame {{
                border: 1px solid {Theme.ACCENT_CYAN};
                background: rgba(0, 255, 255, 10);
                border-radius: 12px;
            }}
            """
        )
        ai_layout = QVBoxLayout(self.ai_card)
        ai_layout.setContentsMargins(18, 14, 18, 14)
        ai_layout.setSpacing(8)

        ai_header = QHBoxLayout()
        ai_header.addWidget(QLabel("󰚩"), alignment=Qt.AlignmentFlag.AlignVCenter) # Robot icon placeholder
        ai_title = QLabel("AI SECURITY ARCHITECT")
        ai_title.setStyleSheet(f"font-weight: 900; letter-spacing: 1px; color: {Theme.ACCENT_CYAN}; font-size: 13px;")
        ai_header.addWidget(ai_title)
        ai_header.addStretch()
        
        self.ai_text = QLabel("Initializing neural link...")
        self.ai_text.setWordWrap(True)
        self.ai_text.setStyleSheet(
            f"color: {Theme.TEXT_PRIMARY}; font-family: 'Consolas'; font-size: 13px; line-height: 1.4;"
        )
        
        ai_layout.addLayout(ai_header)
        ai_layout.addWidget(self.ai_text)
        root.addWidget(self.ai_card)

        # Animation state
        from PySide6.QtCore import QTimer
        self._typewriter_timer = QTimer(self)
        self._typewriter_timer.timeout.connect(self._type_next_char)
        self._full_text = ""
        self._current_index = 0

        top = QHBoxLayout()
        top.setSpacing(14)

        gauge_card = GlassCard(glow=True)
        gauge_layout = QVBoxLayout(gauge_card)
        gauge_layout.setContentsMargins(16, 14, 16, 14)
        gauge_layout.setSpacing(8)

        gauge_title = QLabel("Device Risk")
        gauge_title.setStyleSheet(f"font-size: 16px; font-weight: 700; color: {Theme.TEXT_PRIMARY};")
        self.risk_gauge = RiskGauge(self)
        self.badge = ThreatBadge("low")

        gauge_layout.addWidget(gauge_title)
        gauge_layout.addWidget(self.risk_gauge, alignment=Qt.AlignmentFlag.AlignCenter)
        gauge_layout.addWidget(self.badge, alignment=Qt.AlignmentFlag.AlignCenter)

        counts_card = GlassCard(glow=False)
        counts_layout = QVBoxLayout(counts_card)
        counts_layout.setContentsMargins(16, 14, 16, 14)
        counts_layout.setSpacing(8)

        counts_title = QLabel("Scan Summary")
        counts_title.setStyleSheet(f"font-size: 16px; font-weight: 700; color: {Theme.TEXT_PRIMARY};")
        self.counts_label = QLabel("Files: 0 | High: 0 | Medium: 0 | Safe: 0")
        self.counts_label.setStyleSheet(f"font-size: 14px; color: {Theme.TEXT_SECONDARY};")

        counts_layout.addWidget(counts_title)
        counts_layout.addWidget(self.counts_label)
        counts_layout.addStretch(1)

        top.addWidget(gauge_card, stretch=1)
        top.addWidget(counts_card, stretch=2)
        root.addLayout(top)

        split = QSplitter(Qt.Orientation.Horizontal)
        split.setChildrenCollapsible(False)

        tree_card = GlassCard(glow=False)
        tree_layout = QVBoxLayout(tree_card)
        tree_layout.setContentsMargins(14, 14, 14, 14)
        tree_layout.setSpacing(8)
        tree_layout.addWidget(QLabel("Hierarchical USB File Explorer"))

        self.tree = FileTreeWidget(self)
        tree_layout.addWidget(self.tree)

        detail_card = GlassCard(glow=False)
        detail_layout = QVBoxLayout(detail_card)
        detail_layout.setContentsMargins(14, 14, 14, 14)
        detail_layout.setSpacing(8)
        detail_layout.addWidget(QLabel("File Detail"))

        self.detail = DetailPanel(self)
        detail_layout.addWidget(self.detail)

        split.addWidget(tree_card)
        split.addWidget(detail_card)
        split.setStretchFactor(0, 5)
        split.setStretchFactor(1, 4)
        split.setSizes([760, 560])

        root.addWidget(split, stretch=1)

    def _wire_signals(self) -> None:
        self.tree.file_selected.connect(self.detail.update_details)
        event_bus.scan_completed.connect(self._on_scan_completed)
        event_bus.ai_explanation_ready.connect(self._on_ai_ready)
        event_bus.threat_analysis_refresh_requested.connect(lambda payload: self._on_scan_completed(int(payload.get("event_id", 0)), payload.get("summary", {})))

    def _type_next_char(self) -> None:
        if self._current_index < len(self._full_text):
            self._current_index += 1
            self.ai_text.setText(self._full_text[:self._current_index] + "█")
        else:
            self._typewriter_timer.stop()
            self.ai_text.setText(self._full_text)

    def _on_ai_ready(self, result: dict[str, Any]) -> None:
        """Update the top-level AI insight with neural-link animation."""
        if result.get("status") == "success":
            self.ai_card.setVisible(True)
            self._full_text = str(result.get("explanation", ""))
            self._current_index = 0
            self.ai_text.setText("")
            self._typewriter_timer.start(20)
        else:
            self.ai_card.setVisible(False)
            self._typewriter_timer.stop()

    def showEvent(self, event: Any) -> None:
        super().showEvent(event)
        if not self._rows:
            self._load_latest_from_db()

    def _on_scan_completed(self, event_id: int, summary: dict[str, Any]) -> None:
        data = summary if isinstance(summary, dict) else {}
        device = data.get("device")
        if isinstance(device, dict):
            self._device_info = dict(device)
        mount_root = self._resolve_mount_root()

        rows = data.get("files")
        if isinstance(rows, list) and rows:
            normalized = [self._normalize_row(r) for r in rows if isinstance(r, dict)]
        else:
            normalized = self._load_rows_for_event(event_id)

        normalized = self._filter_rows_to_mount(normalized, mount_root)

        self._apply_rows(normalized)

    def _load_latest_from_db(self) -> None:
        self._apply_rows(self._load_rows_for_event(0))

    def _load_rows_for_event(self, event_id: int) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        try:
            with get_db() as session:
                query = session.query(FileScanResult)
                if event_id > 0:
                    query = query.filter(FileScanResult.device_event_id == event_id)
                rows = query.order_by(FileScanResult.id.desc()).limit(500).all()
                for r in rows:
                    out.append(
                        self._normalize_row(
                            {
                                "file_name": r.file_name,
                                "file_path": r.file_path,
                                "file_size_bytes": int(r.file_size_bytes or 0),
                                "risk_level": str(r.risk_level or "low"),
                                "threat_name": str(r.threat_name or ""),
                                "is_malicious": bool(r.is_malicious),
                                "entropy": self._entropy_guess(r.file_name, str(r.risk_level or "low")),
                                "sha256_hash": str(r.sha256_hash or "-"),
                                "scan_engine": str(r.scan_engine or "HIDShield Engine"),
                                "indicators": [],
                                "yara_matches": [],
                                "pe_imports": [],
                            }
                        )
                    )
        except Exception:
            out = []
        return out

    def _apply_rows(self, rows: list[dict[str, Any]]) -> None:
        self._rows = list(rows)
        self.tree.populate_results(self._rows, animated=False)

        if self._rows:
            self.detail.update_details(self._rows[0])

        device_name = str(self._device_info.get("device_name") or "USB Device")
        serial = str(self._device_info.get("serial_number") or self._device_info.get("serial") or "n/a")

        high = sum(1 for r in self._rows if str(r.get("risk_level", "low")).lower() in {"high", "critical", "dangerous"})
        medium = sum(1 for r in self._rows if str(r.get("risk_level", "low")).lower() == "medium")
        safe = len(self._rows) - high - medium

        self.subtitle.setText(f"Device: {device_name} | Serial: {serial}")
        self.counts_label.setText(f"Files: {len(self._rows)} | High: {high} | Medium: {medium} | Safe: {max(0, safe)}")

        if high > 0:
            self.badge.set_risk_level("high")
            self.risk_gauge.set_value(82.0)
        elif medium > 0:
            self.badge.set_risk_level("medium")
            self.risk_gauge.set_value(57.0)
        else:
            self.badge.set_risk_level("low")
            self.risk_gauge.set_value(22.0)

    def _normalize_row(self, row: dict[str, Any]) -> dict[str, Any]:
        file_name = str(row.get("file_name") or "unknown.bin")
        file_path = str(row.get("file_path") or file_name)
        mount_root = self._resolve_mount_root()
        display_path = self._display_path(file_path=file_path, mount_root=mount_root)
        return {
            "file_name": file_name,
            "file_path": display_path,
            "source_file_path": file_path,
            "file_type": str(row.get("file_type") or self._infer_type(file_name)).lower(),
            "file_size_bytes": int(row.get("file_size_bytes") or row.get("size") or 0),
            "risk_level": str(row.get("risk_level") or "low").lower(),
            "is_malicious": bool(row.get("is_malicious") or False),
            "threat_name": str(row.get("threat_name") or ""),
            "entropy": float(row.get("entropy") or 0.0),
            "sha256_hash": str(row.get("sha256_hash") or row.get("sha256") or "-"),
            "scan_engine": str(row.get("scan_engine") or "HIDShield Engine"),
            "indicators": [str(v) for v in row.get("indicators", []) if str(v).strip()],
            "yara_matches": [str(v) for v in row.get("yara_matches", []) if str(v).strip()],
            "pe_imports": [str(v) for v in row.get("pe_imports", []) if str(v).strip()],
        }

    def _infer_type(self, name: str) -> str:
        suffix = Path(name).suffix.lower()
        if suffix in {".ps1", ".bat", ".cmd", ".js", ".vbs", ".py"}:
            return "script"
        if suffix in {".exe", ".dll", ".sys", ".scr", ".com"}:
            return "exe"
        if suffix in {".zip", ".7z", ".rar"}:
            return "archive"
        if suffix in {".doc", ".docx", ".xls", ".xlsx", ".pdf", ".txt"}:
            return "doc"
        return "file"

    def _entropy_guess(self, file_name: str | None, risk: str) -> float:
        suffix = Path(file_name or "unknown.bin").suffix.lower()
        base = 3.1 if suffix in {".txt", ".pdf", ".md"} else 5.4
        rl = risk.lower()
        if rl in {"high", "critical", "dangerous"}:
            base += 1.9
        elif rl == "medium":
            base += 0.8
        return max(0.0, min(8.0, base))

    def _resolve_mount_root(self) -> Path | None:
        candidate = self._device_info.get("mount_point") or self._device_info.get("drive_letter")
        if not candidate:
            return None
        try:
            return Path(str(candidate)).resolve()
        except Exception:
            return None

    def _filter_rows_to_mount(self, rows: list[dict[str, Any]], mount_root: Path | None) -> list[dict[str, Any]]:
        if mount_root is None:
            return rows
        if not rows:
            return rows
        # Accept all rows from a single scan event.  The old logic dropped
        # every row because sandbox copy paths (in %APPDATA%) never match the
        # USB mount root (e.g. E:\).  Scan events are already device-scoped so
        # cross-device contamination is not a concern.
        return rows

    def _display_path(self, file_path: str, mount_root: Path | None) -> str:
        if mount_root is None:
            return file_path
        try:
            absolute = Path(file_path).resolve()
            if absolute == mount_root:
                return absolute.name
            if mount_root in absolute.parents:
                rel = absolute.relative_to(mount_root)
                return str(rel).replace("\\", "/")
        except Exception:
            return file_path
        return file_path
