"""Autonomous Agent Report screen for HID Shield.

Displays the full structured threat report from the autonomous USB analysis
agent, including device summary, file structure, MITRE ATT&CK mapping,
criticality classification, and self-improvement recommendations.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QScrollArea,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from core.event_bus import event_bus
from ui.styles.theme import Theme
from ui.widgets.glass_card import GlassCard


class AutonomousReportScreen(QWidget):
    """Display the autonomous agent's full structured threat report."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._last_report: dict[str, Any] = {}
        self._build_ui()
        self._wire_signals()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(14)

        # Header
        header = QHBoxLayout()
        header.setSpacing(12)

        self.title = QLabel("HID Agent")
        self.title.setStyleSheet(
            f"font-size: 28px; font-weight: 800; color: {Theme.ACCENT_CYAN};"
        )

        self.status_badge = QLabel("IDLE")
        self.status_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_badge.setFixedSize(100, 32)
        self._set_badge_state("idle")

        header.addWidget(self.title)
        header.addWidget(self.status_badge)
        header.addStretch(1)

        self.subtitle = QLabel("Autonomous USB threat detection agent — Awaiting device insertion")
        self.subtitle.setStyleSheet(f"font-size: 14px; color: {Theme.TEXT_SECONDARY};")

        root.addLayout(header)
        root.addWidget(self.subtitle)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%p% — Idle")
        self.progress_bar.setFixedHeight(28)
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{
                background: {Theme.BG_TERTIARY};
                border: 1px solid {Theme.BORDER};
                border-radius: 6px;
                text-align: center;
                color: {Theme.TEXT_PRIMARY};
                font-size: 12px;
                font-weight: 700;
            }}
            QProgressBar::chunk {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {Theme.ACCENT_CYAN}, stop:1 {Theme.ACCENT_GREEN});
                border-radius: 5px;
            }}
        """)
        root.addWidget(self.progress_bar)

        # Summary cards row
        cards_row = QHBoxLayout()
        cards_row.setSpacing(14)

        # Classification card
        self.class_card = GlassCard(glow=True)
        class_layout = QVBoxLayout(self.class_card)
        class_layout.setContentsMargins(16, 14, 16, 14)
        class_layout.setSpacing(6)

        class_title = QLabel("THREAT LEVEL")
        class_title.setStyleSheet(
            f"font-size: 11px; font-weight: 800; letter-spacing: 2px; color: {Theme.TEXT_SECONDARY};"
        )
        self.class_level = QLabel("—")
        self.class_level.setStyleSheet(
            f"font-size: 36px; font-weight: 900; color: {Theme.ACCENT_GREEN};"
        )
        self.class_score = QLabel("Score: —")
        self.class_score.setStyleSheet(f"font-size: 13px; color: {Theme.TEXT_SECONDARY};")
        self.class_action = QLabel("Action: —")
        self.class_action.setStyleSheet(f"font-size: 13px; color: {Theme.TEXT_SECONDARY};")

        class_layout.addWidget(class_title)
        class_layout.addWidget(self.class_level, alignment=Qt.AlignmentFlag.AlignCenter)
        class_layout.addWidget(self.class_score, alignment=Qt.AlignmentFlag.AlignCenter)
        class_layout.addWidget(self.class_action, alignment=Qt.AlignmentFlag.AlignCenter)

        # MITRE card
        self.mitre_card = GlassCard(glow=False)
        mitre_layout = QVBoxLayout(self.mitre_card)
        mitre_layout.setContentsMargins(16, 14, 16, 14)
        mitre_layout.setSpacing(6)

        mitre_title = QLabel("MITRE ATT&CK")
        mitre_title.setStyleSheet(
            f"font-size: 11px; font-weight: 800; letter-spacing: 2px; color: {Theme.TEXT_SECONDARY};"
        )
        self.mitre_count = QLabel("0")
        self.mitre_count.setStyleSheet(
            f"font-size: 36px; font-weight: 900; color: {Theme.ACCENT_AMBER};"
        )
        self.mitre_sub = QLabel("Techniques Matched")
        self.mitre_sub.setStyleSheet(f"font-size: 13px; color: {Theme.TEXT_SECONDARY};")

        mitre_layout.addWidget(mitre_title)
        mitre_layout.addWidget(self.mitre_count, alignment=Qt.AlignmentFlag.AlignCenter)
        mitre_layout.addWidget(self.mitre_sub, alignment=Qt.AlignmentFlag.AlignCenter)

        # Files card
        self.files_card = GlassCard(glow=False)
        files_layout = QVBoxLayout(self.files_card)
        files_layout.setContentsMargins(16, 14, 16, 14)
        files_layout.setSpacing(6)

        files_title = QLabel("FILE ANALYSIS")
        files_title.setStyleSheet(
            f"font-size: 11px; font-weight: 800; letter-spacing: 2px; color: {Theme.TEXT_SECONDARY};"
        )
        self.files_count = QLabel("—")
        self.files_count.setStyleSheet(
            f"font-size: 36px; font-weight: 900; color: {Theme.ACCENT_CYAN};"
        )
        self.files_breakdown = QLabel("Safe: — | Med: — | High: —")
        self.files_breakdown.setStyleSheet(f"font-size: 13px; color: {Theme.TEXT_SECONDARY};")

        files_layout.addWidget(files_title)
        files_layout.addWidget(self.files_count, alignment=Qt.AlignmentFlag.AlignCenter)
        files_layout.addWidget(self.files_breakdown, alignment=Qt.AlignmentFlag.AlignCenter)

        # Duration card
        self.duration_card = GlassCard(glow=False)
        duration_layout = QVBoxLayout(self.duration_card)
        duration_layout.setContentsMargins(16, 14, 16, 14)
        duration_layout.setSpacing(6)

        dur_title = QLabel("PIPELINE")
        dur_title.setStyleSheet(
            f"font-size: 11px; font-weight: 800; letter-spacing: 2px; color: {Theme.TEXT_SECONDARY};"
        )
        self.duration_value = QLabel("—")
        self.duration_value.setStyleSheet(
            f"font-size: 36px; font-weight: 900; color: {Theme.ACCENT_GREEN};"
        )
        self.duration_sub = QLabel("Analysis Duration")
        self.duration_sub.setStyleSheet(f"font-size: 13px; color: {Theme.TEXT_SECONDARY};")

        duration_layout.addWidget(dur_title)
        duration_layout.addWidget(self.duration_value, alignment=Qt.AlignmentFlag.AlignCenter)
        duration_layout.addWidget(self.duration_sub, alignment=Qt.AlignmentFlag.AlignCenter)

        cards_row.addWidget(self.class_card)
        cards_row.addWidget(self.mitre_card)
        cards_row.addWidget(self.files_card)
        cards_row.addWidget(self.duration_card)
        root.addLayout(cards_row)

        # Full markdown report viewer
        report_card = GlassCard(glow=False)
        report_layout = QVBoxLayout(report_card)
        report_layout.setContentsMargins(16, 14, 16, 14)
        report_layout.setSpacing(8)

        report_header = QHBoxLayout()
        report_title = QLabel("Full Analysis Report")
        report_title.setStyleSheet(
            f"font-size: 16px; font-weight: 700; color: {Theme.TEXT_PRIMARY};"
        )
        self.report_paths = QLabel("")
        self.report_paths.setStyleSheet(f"font-size: 11px; color: {Theme.TEXT_DISABLED};")
        report_header.addWidget(report_title)
        report_header.addStretch(1)
        report_header.addWidget(self.report_paths)
        report_layout.addLayout(report_header)

        self.report_browser = QTextBrowser()
        self.report_browser.setOpenExternalLinks(True)
        self.report_browser.setStyleSheet(f"""
            QTextBrowser {{
                background: {Theme.BG_PRIMARY};
                color: {Theme.TEXT_PRIMARY};
                border: 1px solid {Theme.BORDER};
                border-radius: 8px;
                padding: 14px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                line-height: 1.5;
            }}
        """)
        self.report_browser.setPlaceholderText(
            "Autonomous analysis report will appear here when a USB device is analyzed.\n\n"
            "The HID Agent monitors USB insertions and runs a 7-stage pipeline:\n"
            "  1. Device Detection & Initialization\n"
            "  2. Deep Content Analysis\n"
            "  3. Behavioral Analysis (HID/Keystroke)\n"
            "  4. MITRE ATT&CK Correlation\n"
            "  5. Criticality Classification\n"
            "  6. Structured Report Generation\n"
            "  7. Self-Improvement Analysis"
        )
        report_layout.addWidget(self.report_browser, stretch=1)

        root.addWidget(report_card, stretch=1)

    def _wire_signals(self) -> None:
        event_bus.autonomous_report_ready.connect(self._on_report_ready)
        event_bus.autonomous_analysis_progress.connect(self._on_progress)

    def _on_progress(self, event_id: int, progress: int, stage: str) -> None:
        """Update progress bar during autonomous analysis."""
        self.progress_bar.setValue(progress)
        self.progress_bar.setFormat(f"%p% — {stage}")
        self._set_badge_state("analyzing")
        if progress == 0:
            self.subtitle.setText(f"Event #{event_id}: {stage}")

    def _on_report_ready(self, report: dict[str, Any]) -> None:
        """Display the full autonomous analysis report."""
        self._last_report = report
        self._set_badge_state("complete")
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("100% — Analysis Complete")

        # Classification summary
        classification = report.get("final_classification", report.get("classification", {}))
        level = str(classification.get("level", "UNKNOWN")).upper()
        score = float(classification.get("risk_score", 0))
        action = str(classification.get("policy_action", "N/A"))

        level_color = {
            "HIGH": Theme.ACCENT_MAGENTA,
            "MEDIUM": Theme.ACCENT_AMBER,
            "LOW": Theme.ACCENT_GREEN,
        }.get(level, Theme.TEXT_SECONDARY)

        self.class_level.setText(level)
        self.class_level.setStyleSheet(f"font-size: 36px; font-weight: 900; color: {level_color};")
        self.class_score.setText(f"Score: {score:.1f}/100")
        self.class_action.setText(f"Action: {action.upper()}")

        # MITRE count
        mitre = report.get("mitre_attack_mapping", {})
        technique_count = mitre.get("techniques_matched", 0)
        self.mitre_count.setText(str(technique_count))
        self.mitre_sub.setText(f"Technique{'s' if technique_count != 1 else ''} Matched")

        # File stats
        fs = report.get("file_structure_overview", {})
        total = fs.get("total_files", 0)
        safe = fs.get("safe_files", 0)
        med = fs.get("medium_risk_files", 0)
        high = fs.get("high_risk_files", 0)
        self.files_count.setText(str(total))
        self.files_breakdown.setText(f"Safe: {safe} | Med: {med} | High: {high}")

        # Duration
        duration = report.get("pipeline_duration_seconds", 0)
        self.duration_value.setText(f"{duration:.1f}s")

        # Device info
        dev = report.get("usb_device_summary", {})
        dev_name = dev.get("device_name", "Unknown Device")
        event_id = report.get("event_id", "N/A")
        self.subtitle.setText(f"Event #{event_id}: {dev_name} — {level} Threat Level")

        # Report paths
        json_path = report.get("report_json_path", "")
        pdf_path = report.get("report_pdf_path", "")
        path_parts: list[str] = []
        if json_path:
            path_parts.append(f"JSON: {json_path}")
        if pdf_path:
            path_parts.append(f"PDF: {pdf_path}")
        self.report_paths.setText(" | ".join(path_parts) if path_parts else "")

        # Render markdown report
        markdown = report.get("report_markdown", "")
        if markdown:
            self.report_browser.setMarkdown(markdown)
        else:
            self.report_browser.setPlainText("Report content unavailable.")

    def _set_badge_state(self, state: str) -> None:
        """Update the status badge appearance."""
        styles = {
            "idle": (
                "IDLE",
                f"background: {Theme.BG_TERTIARY}; color: {Theme.TEXT_DISABLED}; "
                f"border: 1px solid {Theme.BORDER};",
            ),
            "analyzing": (
                "ANALYZING",
                f"background: rgba(255, 184, 0, 0.15); color: {Theme.ACCENT_AMBER}; "
                f"border: 1px solid {Theme.ACCENT_AMBER};",
            ),
            "complete": (
                "COMPLETE",
                f"background: rgba(0, 255, 136, 0.15); color: {Theme.ACCENT_GREEN}; "
                f"border: 1px solid {Theme.ACCENT_GREEN};",
            ),
        }
        text, style = styles.get(state, styles["idle"])
        self.status_badge.setText(text)
        self.status_badge.setStyleSheet(
            f"font-size: 11px; font-weight: 800; letter-spacing: 1px; "
            f"border-radius: 6px; {style}"
        )
