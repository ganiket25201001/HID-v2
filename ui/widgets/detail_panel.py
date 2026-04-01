"""
hid_shield.ui.widgets.detail_panel
==================================
Detailed metadata panel for a selected scanned file.

Design
------
* Uses GlassCard sections for consistent cyberpunk panel styling.
* Displays metadata, YARA hits, PE imports, and risk indicators.
* Includes a custom-painted entropy bar and Shannon entropy visualization.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ui.styles.theme import Theme
from ui.widgets.glass_card import GlassCard
from ui.widgets.threat_badge import ThreatBadge


class _EntropyBar(QWidget):
    """Painted entropy bar rendering normalized Shannon entropy and threshold bands."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(28)
        self._entropy: float = 0.0

    def set_entropy(self, entropy: float) -> None:
        """Update the displayed entropy value in the range 0.0..8.0."""
        self._entropy = max(0.0, min(8.0, float(entropy)))
        self.update()

    def paintEvent(self, event: Any) -> None:  # noqa: ARG002 - Qt override
        """Draw segmented track and filled portion according to entropy severity."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = self.rect().adjusted(4, 6, -4, -6)

        # Background track.
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(Theme.BG_TERTIARY))
        painter.drawRoundedRect(rect, 8, 8)

        # Threshold overlays for low/medium/high entropy guidance.
        total_w = rect.width()
        low_w = int(total_w * (4.0 / 8.0))
        med_w = int(total_w * (2.0 / 8.0))

        low_rect = rect.adjusted(0, 0, -(total_w - low_w), 0)
        med_rect = rect.adjusted(low_w, 0, -(total_w - (low_w + med_w)), 0)
        high_rect = rect.adjusted(low_w + med_w, 0, 0, 0)

        painter.setBrush(QColor(0, 255, 136, 36))
        painter.drawRoundedRect(low_rect, 8, 8)
        painter.setBrush(QColor(255, 184, 0, 36))
        painter.drawRect(med_rect)
        painter.setBrush(QColor(255, 0, 110, 32))
        painter.drawRoundedRect(high_rect, 8, 8)

        # Active fill.
        progress = self._entropy / 8.0
        fill_w = int(rect.width() * progress)
        if fill_w > 0:
            fill_rect = rect.adjusted(0, 0, -(rect.width() - fill_w), 0)

            if self._entropy < 4.0:
                fill_color = QColor(Theme.ACCENT_GREEN)
            elif self._entropy < 6.8:
                fill_color = QColor(Theme.ACCENT_AMBER)
            else:
                fill_color = QColor(Theme.ACCENT_MAGENTA)

            painter.setBrush(fill_color)
            painter.drawRoundedRect(fill_rect, 8, 8)

        painter.setPen(QPen(QColor(Theme.BORDER_LIGHT), 1))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRoundedRect(rect, 8, 8)


class DetailPanel(QWidget):
    """Right-side file detail presentation widget for Threat Analysis screen."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self._current_payload: dict[str, Any] = {}
        self._threat_tags: list[QLabel] = []

        self._build_ui()
        self.show_placeholder()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Create metadata, entropy, signatures, and imports sections."""
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        content = QWidget(self)
        root = QVBoxLayout(content)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(12)
        scroll.setWidget(content)
        outer.addWidget(scroll)

        # Metadata card
        meta_card = GlassCard(glow=False)
        meta_layout = QGridLayout(meta_card)
        meta_layout.setContentsMargins(18, 16, 18, 16)
        meta_layout.setHorizontalSpacing(16)
        meta_layout.setVerticalSpacing(10)

        title = QLabel("File Intelligence")
        title.setProperty("class", "h2")

        self.badge = ThreatBadge("low")

        self.file_name_value = QLabel("-")
        self.path_value = QLabel("-")
        self.hash_value = QLabel("-")
        self.size_value = QLabel("-")
        self.engine_value = QLabel("-")

        self.path_value.setWordWrap(True)
        self.hash_value.setWordWrap(True)

        for value in (
            self.file_name_value,
            self.path_value,
            self.hash_value,
            self.size_value,
            self.engine_value,
        ):
            value.setStyleSheet(f"color: {Theme.TEXT_PRIMARY}; font-weight: 600;")

        meta_layout.addWidget(title, 0, 0)
        meta_layout.addWidget(self.badge, 0, 1, alignment=Qt.AlignmentFlag.AlignRight)

        meta_layout.addWidget(self._meta_label("Name"), 1, 0)
        meta_layout.addWidget(self.file_name_value, 1, 1)
        meta_layout.addWidget(self._meta_label("Path"), 2, 0)
        meta_layout.addWidget(self.path_value, 2, 1)
        meta_layout.addWidget(self._meta_label("SHA256"), 3, 0)
        meta_layout.addWidget(self.hash_value, 3, 1)
        meta_layout.addWidget(self._meta_label("Size"), 4, 0)
        meta_layout.addWidget(self.size_value, 4, 1)
        meta_layout.addWidget(self._meta_label("Scan Engine"), 5, 0)
        meta_layout.addWidget(self.engine_value, 5, 1)

        root.addWidget(meta_card)

        # Entropy and tags card
        entropy_card = GlassCard(glow=True)
        entropy_layout = QVBoxLayout(entropy_card)
        entropy_layout.setContentsMargins(18, 16, 18, 16)
        entropy_layout.setSpacing(10)

        entropy_title = QLabel("Shannon Entropy")
        entropy_title.setProperty("class", "h2")

        self.entropy_bar = _EntropyBar(self)
        self.entropy_value = QLabel("0.00 / 8.00")
        self.entropy_value.setStyleSheet(f"color: {Theme.ACCENT_CYAN}; font-weight: 700;")

        self.tags_row = QHBoxLayout()
        self.tags_row.setSpacing(8)
        self.tags_row.addStretch(1)

        entropy_layout.addWidget(entropy_title)
        entropy_layout.addWidget(self.entropy_bar)
        entropy_layout.addWidget(self.entropy_value, alignment=Qt.AlignmentFlag.AlignRight)

        tag_wrap = QWidget(self)
        tag_wrap.setLayout(self.tags_row)
        entropy_layout.addWidget(tag_wrap)

        root.addWidget(entropy_card)

        # YARA and imports card
        intel_card = GlassCard(glow=False)
        intel_layout = QGridLayout(intel_card)
        intel_layout.setContentsMargins(18, 16, 18, 16)
        intel_layout.setHorizontalSpacing(14)
        intel_layout.setVerticalSpacing(8)

        yara_title = QLabel("YARA Matches")
        yara_title.setProperty("class", "h2")
        imports_title = QLabel("PE Imports")
        imports_title.setProperty("class", "h2")

        self.yara_list = QListWidget()
        self.imports_list = QListWidget()
        self.yara_list.setMinimumHeight(180)
        self.imports_list.setMinimumHeight(180)

        list_css = f"""
            QListWidget {{
                background-color: {Theme.BG_TERTIARY};
                border: 1px solid {Theme.BORDER};
                border-radius: 8px;
                color: {Theme.TEXT_PRIMARY};
                padding: 4px;
            }}
            QListWidget::item {{
                padding: 4px 6px;
                border-bottom: 1px solid {Theme.BORDER};
            }}
            QListWidget::item:selected {{
                background-color: rgba(0, 212, 255, 0.16);
            }}
        """
        self.yara_list.setStyleSheet(list_css)
        self.imports_list.setStyleSheet(list_css)

        intel_layout.addWidget(yara_title, 0, 0)
        intel_layout.addWidget(imports_title, 0, 1)
        intel_layout.addWidget(self.yara_list, 1, 0)
        intel_layout.addWidget(self.imports_list, 1, 1)

        root.addWidget(intel_card, stretch=1)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def show_placeholder(self) -> None:
        """Render default state before a file is selected."""
        self.update_details(
            {
                "file_name": "No file selected",
                "file_path": "Choose a row from the file tree to inspect details.",
                "sha256_hash": "-",
                "file_size_bytes": 0,
                "scan_engine": "-",
                "risk_level": "low",
                "entropy": 0.0,
                "indicators": ["Awaiting Selection"],
                "yara_matches": [],
                "pe_imports": [],
            }
        )

    def update_details(self, payload: dict[str, Any]) -> None:
        """Update all panel fields from selected file metadata."""
        self._current_payload = dict(payload)

        risk = str(payload.get("risk_level") or "low").lower()

        self.badge.set_risk_level(risk)
        self.file_name_value.setText(str(payload.get("file_name") or "unknown.bin"))
        self.path_value.setText(str(payload.get("file_path") or "-"))
        self.hash_value.setText(str(payload.get("sha256_hash") or "-"))
        self.size_value.setText(self._format_size(int(payload.get("file_size_bytes") or 0)))
        self.engine_value.setText(str(payload.get("scan_engine") or "HIDShield Engine"))

        entropy = float(payload.get("entropy") or 0.0)
        self.entropy_bar.set_entropy(entropy)
        self.entropy_value.setText(f"{entropy:.2f} / 8.00")

        indicators = payload.get("indicators")
        if not isinstance(indicators, list):
            indicators = []
        self._set_indicator_tags([str(entry) for entry in indicators])

        yara_matches = payload.get("yara_matches")
        if not isinstance(yara_matches, list):
            yara_matches = []

        imports = payload.get("pe_imports")
        if not isinstance(imports, list):
            imports = []

        self._populate_list(self.yara_list, [str(entry) for entry in yara_matches], fallback="No YARA hits")
        self._populate_list(self.imports_list, [str(entry) for entry in imports], fallback="No PE imports captured")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _meta_label(self, text: str) -> QLabel:
        """Build a muted metadata field label."""
        label = QLabel(text)
        label.setStyleSheet(f"color: {Theme.TEXT_SECONDARY}; font-size: 12px;")
        return label

    def _set_indicator_tags(self, tags: list[str]) -> None:
        """Refresh colored threat-indicator tags based on textual markers."""
        for old_tag in self._threat_tags:
            old_tag.deleteLater()
        self._threat_tags.clear()

        while self.tags_row.count() > 1:
            item = self.tags_row.takeAt(0)
            if item.widget() is not None:
                item.widget().deleteLater()

        for marker in tags:
            label = QLabel(marker)
            marker_l = marker.lower()
            if any(word in marker_l for word in ("critical", "inject", "packed", "ransom", "trojan")):
                fg = Theme.ACCENT_MAGENTA
                bg = "rgba(255, 0, 110, 0.16)"
            elif any(word in marker_l for word in ("macro", "obfus", "suspicious", "beacon", "exec")):
                fg = Theme.ACCENT_AMBER
                bg = "rgba(255, 184, 0, 0.16)"
            else:
                fg = Theme.ACCENT_GREEN
                bg = "rgba(0, 255, 136, 0.16)"

            label.setStyleSheet(
                f"""
                QLabel {{
                    color: {fg};
                    background-color: {bg};
                    border: 1px solid {fg};
                    border-radius: 10px;
                    padding: 3px 8px;
                    font-size: 11px;
                    font-weight: 700;
                }}
                """
            )
            self.tags_row.insertWidget(self.tags_row.count() - 1, label)
            self._threat_tags.append(label)

        if not tags:
            placeholder = QLabel("No active indicators")
            placeholder.setStyleSheet(f"color: {Theme.TEXT_SECONDARY}; font-size: 11px;")
            self.tags_row.insertWidget(self.tags_row.count() - 1, placeholder)
            self._threat_tags.append(placeholder)

    def _populate_list(self, widget: QListWidget, rows: list[str], fallback: str) -> None:
        """Fill a list widget with rows or fallback text."""
        widget.clear()
        if not rows:
            item = QListWidgetItem(fallback)
            item.setForeground(QColor(Theme.TEXT_SECONDARY))
            widget.addItem(item)
            return

        for row in rows:
            widget.addItem(QListWidgetItem(row))

    def _format_size(self, size_bytes: int) -> str:
        """Render bytes into concise file-size units."""
        if size_bytes <= 0:
            return "0 B"

        value = float(size_bytes)
        units = ["B", "KB", "MB", "GB"]
        idx = 0
        while value >= 1024.0 and idx < len(units) - 1:
            value /= 1024.0
            idx += 1
        return f"{value:.1f} {units[idx]}"
