"""
hid_shield.ui.widgets.file_approval_table
=========================================
Approval table widget for post-scan file decision workflows.

Design
------
* Subclasses ``QTableWidget`` for explicit row/column control and checkboxes.
* Displays scanned files with risk-aware row coloring and inline ``ThreatBadge``.
* Provides built-in control buttons for:
  - Select All Safe
  - Filter Threats Only
* Emits updated selection summaries for parent decision panels.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
)

from ui.styles.theme import Theme
from ui.widgets.animated_button import AnimatedButton
from ui.widgets.threat_badge import ThreatBadge


class FileApprovalTable(QTableWidget):
    """Threat-aware file approval table with selection and filtering controls."""

    selection_summary_changed = Signal(dict)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self._all_rows: list[dict[str, Any]] = []
        self._show_threats_only: bool = False

        self.select_all_safe_button = AnimatedButton(
            "Select All Safe",
            accent_color=Theme.ACCENT_GREEN,
        )
        self.filter_threats_button = AnimatedButton(
            "Filter Threats Only",
            accent_color=Theme.ACCENT_AMBER,
        )
        self.filter_threats_button.setCheckable(True)

        self._configure_table()
        self._wire_controls()

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _configure_table(self) -> None:
        """Initialize columns, behavior, and base cyberpunk table styling."""
        self.setColumnCount(5)
        self.setHorizontalHeaderLabels(
            ["File Name", "Threat Level", "Explanation", "Size", "Entropy"]
        )

        self.setAlternatingRowColors(False)
        self.setSelectionBehavior(self.SelectionBehavior.SelectRows)
        self.setSelectionMode(self.SelectionMode.SingleSelection)
        self.setEditTriggers(self.EditTrigger.NoEditTriggers)
        self.setSortingEnabled(True)

        self.verticalHeader().setVisible(False)

        self.setStyleSheet(
            f"""
            QTableWidget {{
                background-color: {Theme.BG_SECONDARY};
                border: 1px solid {Theme.BORDER};
                border-radius: 10px;
                color: {Theme.TEXT_PRIMARY};
                gridline-color: {Theme.BORDER};
                selection-background-color: rgba(0, 212, 255, 0.16);
                selection-color: {Theme.TEXT_PRIMARY};
            }}
            QHeaderView::section {{
                background-color: {Theme.BG_TERTIARY};
                color: {Theme.TEXT_SECONDARY};
                font-weight: 700;
                border: none;
                border-right: 1px solid {Theme.BORDER};
                padding: 8px;
            }}
            """
        )

        self.setColumnWidth(0, 300)
        self.setColumnWidth(1, 130)
        self.setColumnWidth(2, 350)
        self.setColumnWidth(3, 110)
        self.setColumnWidth(4, 90)

    def _wire_controls(self) -> None:
        """Connect button controls and table change notifications."""
        self.select_all_safe_button.clicked.connect(self.select_all_safe)
        self.filter_threats_button.clicked.connect(self.toggle_threat_filter)
        self.itemChanged.connect(self._emit_selection_summary)

    # ------------------------------------------------------------------
    # Control bar
    # ------------------------------------------------------------------

    def build_control_bar(self, parent: QWidget | None = None) -> QWidget:
        """Create an external control bar hosting table action buttons."""
        bar = QWidget(parent)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        hint = QLabel("File Approval Controls")
        hint.setStyleSheet(f"color: {Theme.TEXT_SECONDARY}; font-size: 12px;")

        layout.addWidget(hint)
        layout.addStretch(1)
        layout.addWidget(self.select_all_safe_button)
        layout.addWidget(self.filter_threats_button)
        return bar

    # ------------------------------------------------------------------
    # Data population
    # ------------------------------------------------------------------

    def set_files(self, rows: list[dict[str, Any]]) -> None:
        """Set table data from normalized file scan rows."""
        self._all_rows = [dict(row) for row in rows]
        self._render_rows()

    def _render_rows(self) -> None:
        """Render visible rows based on current filter state."""
        self.blockSignals(True)
        self.setRowCount(0)

        visible_rows: list[dict[str, Any]] = []
        for row in self._all_rows:
            risk = str(row.get("risk_level") or "low").lower()
            if self._show_threats_only and risk in ("safe", "low"):
                continue
            visible_rows.append(row)

        for payload in visible_rows:
            self._append_row(payload)

        self.blockSignals(False)
        self._emit_selection_summary()

    def _append_row(self, payload: dict[str, Any]) -> None:
        """Append one row with checkbox, threat badge, and risk coloring."""
        row_idx = self.rowCount()
        self.insertRow(row_idx)

        file_name = str(payload.get("file_name") or "unknown.bin")
        risk_level = str(payload.get("risk_level") or "low").lower()
        explanation = str(payload.get("explanation") or self._build_explanation(payload))
        size_label = self._format_size(int(payload.get("file_size_bytes") or 0))
        entropy = float(payload.get("entropy") or 0.0)

        # Column 0: checkbox + file name
        file_item = QTableWidgetItem(file_name)
        file_item.setFlags(file_item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
        default_checked = risk_level in ("safe", "low")
        file_item.setCheckState(Qt.CheckState.Checked if default_checked else Qt.CheckState.Unchecked)
        file_item.setData(Qt.ItemDataRole.UserRole, payload)
        self.setItem(row_idx, 0, file_item)

        # Column 1: threat badge via cell widget
        badge_host = QWidget(self)
        badge_layout = QHBoxLayout(badge_host)
        badge_layout.setContentsMargins(6, 2, 6, 2)
        badge_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge_layout.addWidget(ThreatBadge(risk_level=risk_level))
        self.setCellWidget(row_idx, 1, badge_host)

        # Remaining textual columns
        explanation_item = QTableWidgetItem(explanation)
        explanation_item.setData(Qt.ItemDataRole.UserRole, payload)

        size_item = QTableWidgetItem(size_label)
        entropy_item = QTableWidgetItem(f"{entropy:.2f}")

        self.setItem(row_idx, 2, explanation_item)
        self.setItem(row_idx, 3, size_item)
        self.setItem(row_idx, 4, entropy_item)

        bg, fg = self._risk_colors(risk_level)
        for column in range(self.columnCount()):
            item = self.item(row_idx, column)
            if item is not None:
                item.setBackground(bg)
                item.setForeground(fg)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def select_all_safe(self) -> None:
        """Check all rows classified as safe/low and uncheck others."""
        self.blockSignals(True)
        for row in range(self.rowCount()):
            file_item = self.item(row, 0)
            if file_item is None:
                continue

            payload = file_item.data(Qt.ItemDataRole.UserRole)
            risk = "low"
            if isinstance(payload, dict):
                risk = str(payload.get("risk_level") or "low").lower()

            file_item.setCheckState(
                Qt.CheckState.Checked if risk in ("safe", "low") else Qt.CheckState.Unchecked
            )
        self.blockSignals(False)
        self._emit_selection_summary()

    def toggle_threat_filter(self) -> None:
        """Toggle between all rows and medium/high/critical-only rows."""
        self._show_threats_only = self.filter_threats_button.isChecked()
        if self._show_threats_only:
            self.filter_threats_button.setText("Show All Files")
        else:
            self.filter_threats_button.setText("Filter Threats Only")
        self._render_rows()

    def get_checked_files(self) -> list[dict[str, Any]]:
        """Return payload dictionaries for all currently checked rows."""
        selected: list[dict[str, Any]] = []
        for row in range(self.rowCount()):
            file_item = self.item(row, 0)
            if file_item is None or file_item.checkState() != Qt.CheckState.Checked:
                continue

            payload = file_item.data(Qt.ItemDataRole.UserRole)
            if isinstance(payload, dict):
                selected.append(dict(payload))
        return selected

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_explanation(self, payload: dict[str, Any]) -> str:
        """Build a concise explanation string when upstream one is absent."""
        threat_name = str(payload.get("threat_name") or "")
        if threat_name:
            return f"Matched threat signature: {threat_name}"

        indicators = payload.get("indicators")
        if isinstance(indicators, list) and indicators:
            return ", ".join(str(v) for v in indicators[:2])

        risk = str(payload.get("risk_level") or "low").lower()
        if risk in ("high", "critical"):
            return "High-risk behavior and entropy profile detected"
        if risk == "medium":
            return "Suspicious traits detected; manual review recommended"
        return "No malicious indicators detected"

    def _risk_colors(self, risk_level: str) -> tuple[QColor, QColor]:
        """Map risk level to row background and foreground colors."""
        level = risk_level.lower()
        if level in ("critical", "high"):
            return QColor(56, 9, 24, 160), QColor(255, 182, 208)
        if level == "medium":
            return QColor(72, 45, 8, 160), QColor(255, 222, 164)
        return QColor(9, 50, 34, 130), QColor(176, 255, 224)

    def _format_size(self, size_bytes: int) -> str:
        """Format bytes to human-readable units."""
        if size_bytes <= 0:
            return "0 B"

        value = float(size_bytes)
        units = ["B", "KB", "MB", "GB"]
        idx = 0
        while value >= 1024.0 and idx < len(units) - 1:
            value /= 1024.0
            idx += 1
        return f"{value:.1f} {units[idx]}"

    def _emit_selection_summary(self) -> None:
        """Emit selected/total counters for parent decision panel summaries."""
        selected_rows = len(self.get_checked_files())
        total_rows = self.rowCount()
        self.selection_summary_changed.emit(
            {
                "selected": selected_rows,
                "total": total_rows,
                "threat_filter": self._show_threats_only,
            }
        )
