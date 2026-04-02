"""Hierarchical threat-aware file tree widget."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem, QWidget

from ui.styles.theme import Theme


class FileTreeWidget(QTreeWidget):
    """Display folders/files as expandable hierarchy with risk-aware file rows."""

    file_selected = Signal(dict)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._folder_index: dict[str, QTreeWidgetItem] = {}
        self._configure_tree()
        self.itemClicked.connect(self._on_item_clicked)

    def _configure_tree(self) -> None:
        self.setColumnCount(5)
        self.setHeaderLabels(["Name", "Type", "Size", "Risk", "Entropy"])
        self.setAnimated(True)
        self.setRootIsDecorated(True)
        self.setIndentation(20)
        self.setSortingEnabled(False)
        self.setUniformRowHeights(True)
        self.setSelectionBehavior(self.SelectionBehavior.SelectRows)
        self.setEditTriggers(self.EditTrigger.NoEditTriggers)

        self.setStyleSheet(
            f"""
            QTreeWidget {{
                background-color: {Theme.BG_SECONDARY};
                border: 1px solid {Theme.BORDER};
                border-radius: 12px;
                color: {Theme.TEXT_PRIMARY};
                font-size: 14px;
            }}
            QTreeWidget::item {{
                height: 34px;
            }}
            QTreeWidget::item:selected {{
                background-color: rgba(0, 212, 255, 0.16);
            }}
            QHeaderView::section {{
                background-color: {Theme.BG_TERTIARY};
                color: {Theme.TEXT_SECONDARY};
                font-weight: 700;
                padding: 9px;
                border: none;
                border-right: 1px solid {Theme.BORDER};
            }}
            """
        )

        self.setColumnWidth(0, 430)
        self.setColumnWidth(1, 100)
        self.setColumnWidth(2, 110)
        self.setColumnWidth(3, 100)
        self.setColumnWidth(4, 90)

    def clear_results(self) -> None:
        self.clear()
        self._folder_index.clear()

    def populate_results(self, files: list[dict[str, Any]], animated: bool = True) -> None:
        """Populate tree from scan rows using file_path hierarchy."""
        del animated  # API compatibility
        self.clear_results()
        if not files:
            return

        for row in files:
            self._add_file_row(row)

        self.expandToDepth(1)

    def _add_file_row(self, row: dict[str, Any]) -> None:
        file_name = str(row.get("file_name") or "unknown.bin")
        file_path = str(row.get("file_path") or file_name).replace("\\", "/")
        risk_level = str(row.get("risk_level") or "low").lower()
        entropy = float(row.get("entropy") or 0.0)
        size_bytes = int(row.get("file_size_bytes") or row.get("size") or 0)

        parent_item = self._ensure_parent_folders(file_path)
        item = QTreeWidgetItem(parent_item)

        item.setText(0, file_name)
        item.setText(1, str(row.get("file_type") or self._infer_file_type(file_name)).upper())
        item.setText(2, self._format_size(size_bytes))
        item.setText(3, risk_level.upper())
        item.setText(4, f"{entropy:.2f}")
        item.setData(0, Qt.ItemDataRole.UserRole, row)

        style = self.style()
        item.setIcon(0, style.standardIcon(style.StandardPixmap.SP_FileIcon))

        bg, fg = self._risk_colors(risk_level)
        for col in range(self.columnCount()):
            item.setBackground(col, bg)
            item.setForeground(col, fg)

    def _ensure_parent_folders(self, file_path: str) -> QTreeWidgetItem:
        style = self.style()
        p = PurePosixPath(file_path)
        folder_parts = p.parent.parts if str(p.parent) not in ("", ".") else ()

        current_parent: QTreeWidgetItem | None = None
        key_accum: list[str] = []
        for part in folder_parts:
            key_accum.append(part)
            key = "/".join(key_accum)
            existing = self._folder_index.get(key)
            if existing is None:
                folder_item = QTreeWidgetItem(current_parent or self)
                folder_item.setText(0, part)
                folder_item.setText(1, "FOLDER")
                folder_item.setIcon(0, style.standardIcon(style.StandardPixmap.SP_DirIcon))
                folder_item.setData(0, Qt.ItemDataRole.UserRole, {"type": "folder", "path": key})
                for col in range(self.columnCount()):
                    folder_item.setForeground(col, QColor(Theme.TEXT_SECONDARY))
                self._folder_index[key] = folder_item
                existing = folder_item
            current_parent = existing

        if current_parent is None:
            # virtual root
            root = self.invisibleRootItem()
            return root
        return current_parent

    def _on_item_clicked(self, item: QTreeWidgetItem, _column: int) -> None:
        payload = item.data(0, Qt.ItemDataRole.UserRole)
        if isinstance(payload, dict) and payload.get("type") != "folder":
            self.file_selected.emit(payload)

    def _risk_colors(self, level: str) -> tuple[QColor, QColor]:
        if level in {"high", "critical", "dangerous"}:
            return QColor(60, 12, 24, 165), QColor(255, 190, 210)
        if level == "medium":
            return QColor(70, 50, 10, 160), QColor(255, 224, 164)
        return QColor(10, 52, 37, 135), QColor(172, 255, 220)

    def _format_size(self, size: int) -> str:
        if size <= 0:
            return "0 B"
        value = float(size)
        units = ["B", "KB", "MB", "GB"]
        i = 0
        while value >= 1024 and i < len(units) - 1:
            value /= 1024.0
            i += 1
        return f"{value:.1f} {units[i]}"

    def _infer_file_type(self, file_name: str) -> str:
        suffix = PurePosixPath(file_name).suffix.lower()
        mapping = {
            ".exe": "exe",
            ".dll": "dll",
            ".sys": "sys",
            ".ps1": "script",
            ".bat": "script",
            ".cmd": "script",
            ".js": "script",
            ".vbs": "script",
            ".pdf": "doc",
            ".doc": "doc",
            ".docx": "doc",
            ".xls": "doc",
            ".xlsx": "doc",
            ".zip": "archive",
            ".7z": "archive",
            ".rar": "archive",
        }
        return mapping.get(suffix, "file")
