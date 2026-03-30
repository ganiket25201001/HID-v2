"""
hid_shield.ui.widgets.file_tree_widget
======================================
Threat-aware file tree widget for the Threat Analysis screen.

Design
------
* Subclasses ``QTreeWidget`` for sortable, structured scan-file presentation.
* Rows are color-coded by threat level (green/amber/magenta) for fast triage.
* Each item includes a file-type icon, metadata columns, and a ThreatBadge.
* New rows fade in on insertion to create progressive scan-population feedback.
* Emits ``file_selected`` with the full file detail payload on click.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import QEasingCurve, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QIcon
from PySide6.QtWidgets import (
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QTreeWidget,
    QTreeWidgetItem,
    QWidget,
)

from ui.styles.theme import Theme
from ui.widgets.threat_badge import ThreatBadge


class FileTreeWidget(QTreeWidget):
    """Threat analysis file tree with animated inserts and click-to-detail behavior."""

    file_selected = Signal(dict)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self._pending_insertions: list[dict[str, Any]] = []
        self._insertion_timer = QTimer(self)
        self._insertion_timer.setInterval(120)
        self._insertion_timer.timeout.connect(self._insert_next_pending_item)

        self._icon_cache: dict[str, QIcon] = {}

        self._configure_tree()
        self.itemClicked.connect(self._on_item_clicked)

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def _configure_tree(self) -> None:
        """Initialize columns, interactions, and the cyberpunk baseline style."""
        self.setColumnCount(5)
        self.setHeaderLabels(["File", "Type", "Size", "Risk", "Entropy"])

        self.setAlternatingRowColors(False)
        self.setUniformRowHeights(True)
        self.setRootIsDecorated(False)
        self.setAnimated(True)
        self.setIndentation(12)
        self.setSortingEnabled(True)
        self.sortByColumn(3, Qt.SortOrder.DescendingOrder)

        self.setSelectionMode(self.SelectionMode.SingleSelection)
        self.setSelectionBehavior(self.SelectionBehavior.SelectRows)
        self.setEditTriggers(self.EditTrigger.NoEditTriggers)

        self.setStyleSheet(
            f"""
            QTreeWidget {{
                background-color: {Theme.BG_SECONDARY};
                border: 1px solid {Theme.BORDER};
                border-radius: 10px;
                color: {Theme.TEXT_PRIMARY};
                gridline-color: {Theme.BORDER};
                alternate-background-color: {Theme.BG_TERTIARY};
                selection-background-color: rgba(0, 212, 255, 0.18);
                selection-color: {Theme.TEXT_PRIMARY};
            }}
            QTreeWidget::item {{
                height: 34px;
                border-bottom: 1px solid {Theme.BORDER};
            }}
            QHeaderView::section {{
                background-color: {Theme.BG_TERTIARY};
                color: {Theme.TEXT_SECONDARY};
                padding: 8px;
                border: none;
                border-right: 1px solid {Theme.BORDER};
                font-weight: 700;
            }}
            """
        )

        self.setColumnWidth(0, 320)
        self.setColumnWidth(1, 90)
        self.setColumnWidth(2, 110)
        self.setColumnWidth(3, 90)
        self.setColumnWidth(4, 90)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def clear_results(self) -> None:
        """Clear all current tree items and pending insertion queue."""
        self._pending_insertions.clear()
        self._insertion_timer.stop()
        self.clear()

    def populate_results(self, files: list[dict[str, Any]], animated: bool = True) -> None:
        """Load file scan rows.

        Parameters
        ----------
        files:
            List of normalized file dictionaries.
        animated:
            When true, items are appended one-by-one with fade animation.
        """
        self.clear_results()

        if not files:
            return

        if animated:
            self._pending_insertions = [dict(row) for row in files]
            self._insertion_timer.start()
        else:
            for payload in files:
                self._append_item(payload, fade=False)

    # ------------------------------------------------------------------
    # Item creation
    # ------------------------------------------------------------------

    def _insert_next_pending_item(self) -> None:
        """Consume one pending payload entry and insert it with fade-in."""
        if not self._pending_insertions:
            self._insertion_timer.stop()
            return

        payload = self._pending_insertions.pop(0)
        self._append_item(payload, fade=True)

    def _append_item(self, payload: dict[str, Any], fade: bool) -> None:
        """Create and style a ``QTreeWidgetItem`` from scan metadata."""
        file_name = str(payload.get("file_name") or "unknown.bin")
        file_type = str(payload.get("file_type") or self._infer_file_type(file_name)).upper()
        risk_level = str(payload.get("risk_level") or "low").lower()
        size_bytes = int(payload.get("file_size_bytes") or 0)
        entropy = float(payload.get("entropy") or 0.0)

        item = QTreeWidgetItem(self)
        item.setText(0, file_name)
        item.setText(1, file_type)
        item.setText(2, self._format_size(size_bytes))
        item.setText(3, risk_level.upper())
        item.setText(4, f"{entropy:.2f}")
        item.setData(0, Qt.ItemDataRole.UserRole, payload)

        row_bg, row_fg = self._risk_colors(risk_level)
        for column in range(self.columnCount()):
            item.setBackground(column, row_bg)
            item.setForeground(column, row_fg)

        # Column 0 custom widget: icon + filename.
        file_widget = self._build_file_cell_widget(file_name, file_type)
        self.setItemWidget(item, 0, file_widget)

        # Column 3 custom threat badge.
        badge_holder = QWidget(self)
        badge_layout = QHBoxLayout(badge_holder)
        badge_layout.setContentsMargins(4, 2, 4, 2)
        badge_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge_layout.addWidget(ThreatBadge(risk_level=risk_level))
        self.setItemWidget(item, 3, badge_holder)

        if fade:
            self._apply_fade_in(file_widget)
            self._apply_fade_in(badge_holder)

    def _build_file_cell_widget(self, file_name: str, file_type: str) -> QWidget:
        """Create the file cell with icon and typography matching app style."""
        container = QWidget(self)
        layout = QHBoxLayout(container)
        layout.setContentsMargins(6, 0, 6, 0)
        layout.setSpacing(8)

        icon_lbl = QLabel(container)
        icon_lbl.setPixmap(self._icon_for_type(file_type).pixmap(16, 16))

        name_lbl = QLabel(file_name, container)
        name_lbl.setStyleSheet(f"color: {Theme.TEXT_PRIMARY}; font-weight: 600;")
        name_lbl.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        layout.addWidget(icon_lbl)
        layout.addWidget(name_lbl)
        return container

    # ------------------------------------------------------------------
    # Interactions
    # ------------------------------------------------------------------

    def _on_item_clicked(self, item: QTreeWidgetItem, _column: int) -> None:
        """Emit selected file detail payload for the right-side detail panel."""
        payload = item.data(0, Qt.ItemDataRole.UserRole)
        if isinstance(payload, dict):
            self.file_selected.emit(payload)

    # ------------------------------------------------------------------
    # Styling helpers
    # ------------------------------------------------------------------

    def _risk_colors(self, risk_level: str) -> tuple[QColor, QColor]:
        """Map risk level to row background and foreground colors."""
        level = risk_level.lower()
        if level in ("critical", "high"):
            return QColor(60, 10, 28, 165), QColor(255, 180, 208)
        if level == "medium":
            return QColor(70, 46, 8, 165), QColor(255, 218, 152)
        return QColor(10, 52, 37, 140), QColor(173, 255, 221)

    def _apply_fade_in(self, widget: QWidget) -> None:
        """Attach a one-shot opacity animation to highlight fresh insertions."""
        effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(effect)
        effect.setOpacity(0.0)

        from PySide6.QtCore import QPropertyAnimation  # local import avoids module-level clutter

        fade_anim = QPropertyAnimation(effect, b"opacity", widget)
        fade_anim.setDuration(260)
        fade_anim.setStartValue(0.0)
        fade_anim.setEndValue(1.0)
        fade_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        widget._fade_anim_ref = fade_anim  # type: ignore[attr-defined]
        fade_anim.start()

    # ------------------------------------------------------------------
    # File metadata helpers
    # ------------------------------------------------------------------

    def _infer_file_type(self, file_name: str) -> str:
        """Infer concise file type from extension."""
        suffix = Path(file_name).suffix.lower()
        mapping = {
            ".exe": "exe",
            ".dll": "dll",
            ".sys": "sys",
            ".ps1": "script",
            ".bat": "script",
            ".cmd": "script",
            ".js": "script",
            ".vbs": "script",
            ".doc": "doc",
            ".docx": "doc",
            ".xls": "doc",
            ".xlsx": "doc",
            ".pdf": "doc",
            ".zip": "archive",
            ".rar": "archive",
            ".7z": "archive",
        }
        return mapping.get(suffix, "file")

    def _icon_for_type(self, file_type: str) -> QIcon:
        """Return a cached icon for the provided logical file type."""
        kind = file_type.strip().lower()
        if kind in self._icon_cache:
            return self._icon_cache[kind]

        # Use standard pixmaps to avoid external assets while preserving clarity.
        style = self.style()
        if kind in ("exe", "dll", "sys"):
            icon = style.standardIcon(style.StandardPixmap.SP_ComputerIcon)
        elif kind in ("script",):
            icon = style.standardIcon(style.StandardPixmap.SP_CommandLink)
        elif kind in ("archive",):
            icon = style.standardIcon(style.StandardPixmap.SP_DirClosedIcon)
        elif kind in ("doc",):
            icon = style.standardIcon(style.StandardPixmap.SP_FileIcon)
        else:
            icon = style.standardIcon(style.StandardPixmap.SP_FileIcon)

        self._icon_cache[kind] = icon
        return icon

    def _format_size(self, size_bytes: int) -> str:
        """Convert bytes to compact human-readable units."""
        if size_bytes <= 0:
            return "0 B"

        value = float(size_bytes)
        units = ["B", "KB", "MB", "GB"]
        idx = 0
        while value >= 1024.0 and idx < len(units) - 1:
            value /= 1024.0
            idx += 1
        return f"{value:.1f} {units[idx]}"
