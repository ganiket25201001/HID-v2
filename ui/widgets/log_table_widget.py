"""
hid_shield.ui.widgets.log_table_widget
======================================
Reusable logs table widget for device/file/alert timelines.

Design
------
* Subclasses ``QTableWidget`` with built-in filtering by risk and date.
* Supports sortable columns and risk-aware row color coding.
* Adds hover highlighting with a neon-cyan accent for faster scanning.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QTableWidget, QTableWidgetItem, QWidget

from ui.styles.theme import Theme


class LogTableWidget(QTableWidget):
    """Generic table widget for log-like rows with rich filtering support."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self._all_rows: list[dict[str, Any]] = []
        self._visible_rows: list[dict[str, Any]] = []

        self._risk_filter: str = "all"
        self._from_date: date | None = None
        self._to_date: date | None = None

        self._hovered_row: int = -1

        self._configure_table()

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _configure_table(self) -> None:
        """Initialize visual style and interaction defaults."""
        self.setAlternatingRowColors(False)
        self.setSortingEnabled(True)
        self.setSelectionBehavior(self.SelectionBehavior.SelectRows)
        self.setSelectionMode(self.SelectionMode.SingleSelection)
        self.setEditTriggers(self.EditTrigger.NoEditTriggers)

        self.verticalHeader().setVisible(False)
        self.setMouseTracking(True)

        self.itemEntered.connect(self._on_item_entered)

        self.setStyleSheet(
            f"""
            QTableWidget {{
                background-color: {Theme.BG_SECONDARY};
                border: 1px solid {Theme.BORDER};
                border-radius: 10px;
                color: {Theme.TEXT_PRIMARY};
                gridline-color: {Theme.BORDER};
                selection-background-color: rgba(0, 212, 255, 0.18);
                selection-color: {Theme.TEXT_PRIMARY};
            }}
            QHeaderView::section {{
                background-color: {Theme.BG_TERTIARY};
                color: {Theme.TEXT_SECONDARY};
                font-weight: 700;
                padding: 8px;
                border: none;
                border-right: 1px solid {Theme.BORDER};
            }}
            QTableWidget::item:hover {{
                border: 1px solid #00d4ff;
                background-color: rgba(0, 212, 255, 0.10);
            }}
            """
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_headers(self, headers: list[str]) -> None:
        """Set table headers and reset column count accordingly."""
        self.setColumnCount(len(headers))
        self.setHorizontalHeaderLabels(headers)

    def set_rows(self, rows: list[dict[str, Any]]) -> None:
        """Set table source rows and apply current active filters."""
        self._all_rows = [dict(row) for row in rows]
        self.apply_filters()

    def set_risk_filter(self, risk_filter: str) -> None:
        """Set risk filter mode (all/safe/low/medium/high/critical)."""
        self._risk_filter = risk_filter.strip().lower() or "all"
        self.apply_filters()

    def set_date_filter(self, from_date: date | None, to_date: date | None) -> None:
        """Set date range filter boundaries and re-apply view filter."""
        self._from_date = from_date
        self._to_date = to_date
        self.apply_filters()

    def apply_filters(self) -> None:
        """Apply current risk/date filters and render table rows."""
        self._visible_rows = []
        for row in self._all_rows:
            if not self._matches_risk_filter(row):
                continue
            if not self._matches_date_filter(row):
                continue
            self._visible_rows.append(row)

        self._render_visible_rows()

    def get_visible_rows(self) -> list[dict[str, Any]]:
        """Return currently visible rows after active filtering."""
        return [dict(row) for row in self._visible_rows]

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _render_visible_rows(self) -> None:
        """Render filtered rows into QTableWidget cells with risk-aware styling."""
        self.blockSignals(True)
        self.setRowCount(0)

        for row_payload in self._visible_rows:
            row_idx = self.rowCount()
            self.insertRow(row_idx)

            columns = row_payload.get("columns")
            if not isinstance(columns, list):
                columns = []

            for col_idx in range(self.columnCount()):
                value = columns[col_idx] if col_idx < len(columns) else ""
                item = QTableWidgetItem(str(value))
                item.setData(Qt.ItemDataRole.UserRole, row_payload)
                self.setItem(row_idx, col_idx, item)

            risk = str(row_payload.get("risk_level") or "low").lower()
            bg, fg = self._risk_colors(risk)
            for col_idx in range(self.columnCount()):
                item = self.item(row_idx, col_idx)
                if item is not None:
                    item.setBackground(bg)
                    item.setForeground(fg)

        self.blockSignals(False)

    # ------------------------------------------------------------------
    # Filters
    # ------------------------------------------------------------------

    def _matches_risk_filter(self, row: dict[str, Any]) -> bool:
        """Return True when row satisfies current risk level filter."""
        if self._risk_filter in ("all", ""):
            return True

        row_risk = str(row.get("risk_level") or "low").lower()
        if self._risk_filter == "safe":
            return row_risk in ("safe", "low")
        if self._risk_filter == "dangerous":
            return row_risk in ("high", "critical")
        return row_risk == self._risk_filter

    def _matches_date_filter(self, row: dict[str, Any]) -> bool:
        """Return True when row timestamp falls within configured date range."""
        if self._from_date is None and self._to_date is None:
            return True

        timestamp = self._extract_row_datetime(row)
        if timestamp is None:
            return True

        row_date = timestamp.date()
        if self._from_date is not None and row_date < self._from_date:
            return False
        if self._to_date is not None and row_date > self._to_date:
            return False
        return True

    # ------------------------------------------------------------------
    # Hover behavior
    # ------------------------------------------------------------------

    def leaveEvent(self, event: Any) -> None:
        """Reset hover state when cursor leaves the table viewport."""
        self._hovered_row = -1
        self._render_visible_rows()
        super().leaveEvent(event)

    def _on_item_entered(self, item: QTableWidgetItem) -> None:
        """Apply a temporary neon hover highlight to the entered row."""
        row = item.row()
        if row == self._hovered_row:
            return

        self._hovered_row = row
        self._render_visible_rows()

        for col_idx in range(self.columnCount()):
            row_item = self.item(row, col_idx)
            if row_item is not None:
                hover_bg = QColor(0, 212, 255, 38)
                row_item.setBackground(hover_bg)
                row_item.setForeground(QColor(Theme.TEXT_PRIMARY))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_row_datetime(self, row: dict[str, Any]) -> datetime | None:
        """Extract datetime from row payload where available."""
        raw_ts = row.get("timestamp")
        if isinstance(raw_ts, datetime):
            return raw_ts
        if isinstance(raw_ts, str):
            try:
                return datetime.fromisoformat(raw_ts)
            except ValueError:
                return None
        return None

    def _risk_colors(self, risk: str) -> tuple[QColor, QColor]:
        """Map risk level to default row background/foreground colors."""
        level = risk.lower()
        if level in ("critical", "high"):
            return QColor(59, 10, 24, 155), QColor(255, 184, 210)
        if level == "medium":
            return QColor(70, 47, 8, 155), QColor(255, 224, 164)
        return QColor(9, 50, 34, 130), QColor(175, 255, 226)
