"""
hid_shield.reports.pdf_exporter
==============================
Professional PDF report generation for HID Shield scan outcomes.

Design
------
* Uses ``reportlab`` to build polished multi-section threat reports.
* Supports automatic filename generation with serial + timestamp pattern.
* Produces:
  - Cover page
  - Device metadata summary
  - File-by-file analysis table
  - ML confidence and final user decision
"""

from __future__ import annotations

import importlib
from datetime import datetime
from pathlib import Path
from typing import Any


class PDFExporter:
    """Generate cyberpunk-styled HID Shield threat reports in PDF format."""

    def __init__(self, output_dir: Path | None = None) -> None:
        colors, _, styles, _, _ = self._reportlab_modules()
        paragraph_style_cls = styles.ParagraphStyle
        sample_styles = styles.getSampleStyleSheet()

        self.output_dir: Path = (output_dir or Path.cwd()).resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.style_title = paragraph_style_cls(
            "CyberTitle",
            parent=sample_styles["Heading1"],
            fontSize=24,
            leading=28,
            textColor=colors.HexColor("#00D4FF"),
            spaceAfter=10,
        )
        self.style_heading = paragraph_style_cls(
            "CyberHeading",
            parent=sample_styles["Heading2"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#00D4FF"),
            spaceBefore=6,
            spaceAfter=4,
        )
        self.style_body = paragraph_style_cls(
            "CyberBody",
            parent=sample_styles["BodyText"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#E2E8F0"),
        )
        self.style_muted = paragraph_style_cls(
            "CyberMuted",
            parent=sample_styles["BodyText"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#94A3B8"),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_auto_filename(self, serial: str | None = None, now: datetime | None = None) -> str:
        """Build the standardized HID Shield report filename."""
        timestamp = (now or datetime.now()).strftime("%Y%m%d_%H%M%S")
        serial_clean = (serial or "unknown").replace(" ", "_").replace("/", "-")
        return f"HIDShield_Report_{serial_clean}_{timestamp}.pdf"

    def export_report(
        self,
        *,
        device_metadata: dict[str, Any],
        file_rows: list[dict[str, Any]],
        ml_confidence: float,
        user_decision: str,
        output_path: Path | None = None,
    ) -> Path:
        """Generate and write a complete PDF report to disk.

        Parameters
        ----------
        device_metadata:
            Device-level metadata dictionary (name, serial, risk, etc).
        file_rows:
            File scan rows included in the report.
        ml_confidence:
            Classifier confidence value in range [0.0, 1.0].
        user_decision:
            Final operator/system decision text.
        output_path:
            Optional absolute/relative output path.

        Returns
        -------
        Path
            Final path of the generated PDF file.
        """
        serial = str(device_metadata.get("serial") or device_metadata.get("serial_number") or "unknown")
        _, pagesizes, _, units, platypus = self._reportlab_modules()

        if output_path is None:
            output_path = self.output_dir / self.build_auto_filename(serial=serial)
        else:
            output_path = Path(output_path).resolve()
            output_path.parent.mkdir(parents=True, exist_ok=True)

        doc = platypus.SimpleDocTemplate(
            str(output_path),
            pagesize=pagesizes.A4,
            leftMargin=16 * units.mm,
            rightMargin=16 * units.mm,
            topMargin=14 * units.mm,
            bottomMargin=14 * units.mm,
            title="HID Shield Threat Report",
            author="HID Shield",
        )

        story: list[Any] = []
        self._build_cover_page(story, device_metadata)
        self._build_metadata_section(story, device_metadata, ml_confidence, user_decision)
        self._build_file_table_section(story, file_rows)

        doc.build(story, onFirstPage=self._draw_page_frame, onLaterPages=self._draw_page_frame)
        return output_path

    # ------------------------------------------------------------------
    # Story builders
    # ------------------------------------------------------------------

    def _build_cover_page(self, story: list[Any], device_metadata: dict[str, Any]) -> None:
        """Append cover page content with title and key report context."""
        _, _, _, units, platypus = self._reportlab_modules()

        device_name = str(device_metadata.get("device_name") or "Unknown USB Device")
        serial = str(device_metadata.get("serial") or device_metadata.get("serial_number") or "N/A")

        story.append(platypus.Paragraph("HID SHIELD", self.style_title))
        story.append(platypus.Paragraph("Intelligent USB Security System", self.style_body))
        story.append(platypus.Spacer(1, 8 * units.mm))

        story.append(platypus.Paragraph("Threat Report", self.style_heading))
        story.append(platypus.Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.style_muted))
        story.append(platypus.Paragraph(f"Device: {device_name}", self.style_body))
        story.append(platypus.Paragraph(f"Serial: {serial}", self.style_body))
        story.append(platypus.Spacer(1, 14 * units.mm))

        intro = (
            "This report summarizes HID Shield threat analysis findings, including "
            "device posture, file-level detection outcomes, and operator decision logs."
        )
        story.append(platypus.Paragraph(intro, self.style_body))
        story.append(platypus.Spacer(1, 16 * units.mm))

    def _build_metadata_section(
        self,
        story: list[Any],
        device_metadata: dict[str, Any],
        ml_confidence: float,
        user_decision: str,
    ) -> None:
        """Append device metadata, confidence, and decision summary table."""
        colors, _, _, units, platypus = self._reportlab_modules()

        story.append(platypus.Paragraph("Device Intelligence Summary", self.style_heading))

        metadata_rows = [
            ["Device Name", str(device_metadata.get("device_name") or "Unknown")],
            ["Serial", str(device_metadata.get("serial") or device_metadata.get("serial_number") or "N/A")],
            ["Manufacturer", str(device_metadata.get("manufacturer") or "Unknown")],
            ["Risk Level", str(device_metadata.get("risk_level") or "low").upper()],
            ["ML Confidence", f"{max(0.0, min(1.0, ml_confidence)) * 100:.1f}%"],
            ["User Decision", user_decision],
        ]

        table = platypus.Table(metadata_rows, colWidths=[40 * units.mm, 130 * units.mm])
        table.setStyle(
            platypus.TableStyle(
                [
                    ("BACKGROUND", (0, 0), (1, 0), colors.HexColor("#111827")),
                    ("BACKGROUND", (0, 1), (1, -1), colors.HexColor("#0A0E17")),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#E2E8F0")),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("GRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#334155")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )

        story.append(table)
        story.append(platypus.Spacer(1, 10 * units.mm))

    def _build_file_table_section(self, story: list[Any], file_rows: list[dict[str, Any]]) -> None:
        """Append file-by-file analysis table with risk-aware row coloring."""
        colors, _, _, units, platypus = self._reportlab_modules()

        story.append(platypus.Paragraph("File Analysis", self.style_heading))

        headers = ["File", "Threat", "Entropy", "Size", "Explanation"]
        body_rows: list[list[str]] = [headers]

        for row in file_rows:
            body_rows.append(
                [
                    str(row.get("file_name") or "unknown.bin"),
                    str(row.get("risk_level") or "low").upper(),
                    f"{float(row.get('entropy') or 0.0):.2f}",
                    self._format_size(int(row.get("file_size_bytes") or 0)),
                    str(row.get("explanation") or row.get("threat_name") or "No significant indicators"),
                ]
            )

        if len(body_rows) == 1:
            body_rows.append(["No scan rows available", "-", "-", "-", "-"])

        table = platypus.Table(
            body_rows,
            colWidths=[40 * units.mm, 22 * units.mm, 18 * units.mm, 20 * units.mm, 84 * units.mm],
            repeatRows=1,
        )

        style_rules: list[tuple[Any, ...]] = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#00D4FF")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("ALIGN", (2, 1), (3, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#E2E8F0")),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.45, colors.HexColor("#334155")),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]

        for index, row in enumerate(file_rows, start=1):
            risk = str(row.get("risk_level") or "low").lower()
            if risk in ("critical", "high"):
                style_rules.append(("BACKGROUND", (0, index), (-1, index), colors.HexColor("#2B0E1B")))
            elif risk == "medium":
                style_rules.append(("BACKGROUND", (0, index), (-1, index), colors.HexColor("#2E220C")))
            else:
                style_rules.append(("BACKGROUND", (0, index), (-1, index), colors.HexColor("#0D2A21")))

        table.setStyle(platypus.TableStyle(style_rules))
        story.append(table)
        story.append(platypus.Spacer(1, 6 * units.mm))

        note = (
            "Confidence and classification values are generated by HID Shield policy and analysis "
            "subsystems. Manual analyst override is recorded through decision panel actions."
        )
        story.append(platypus.Paragraph(note, self.style_muted))

    # ------------------------------------------------------------------
    # Rendering helpers
    # ------------------------------------------------------------------

    def _draw_page_frame(self, canvas: Any, doc: Any) -> None:
        """Draw cyberpunk-inspired border and footer on every page."""
        colors, pagesizes, _, units, _ = self._reportlab_modules()

        width, height = pagesizes.A4
        margin = 8 * units.mm

        canvas.setStrokeColor(colors.HexColor("#00D4FF"))
        canvas.setLineWidth(1)
        canvas.rect(margin, margin, width - (2 * margin), height - (2 * margin), stroke=1, fill=0)

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#94A3B8"))
        canvas.drawString(margin + 4, margin - 2 + 4 * units.mm, "HID Shield - Confidential Threat Report")
        canvas.drawRightString(width - margin - 4, margin - 2 + 4 * units.mm, f"Page {doc.page}")

    def _reportlab_modules(self) -> tuple[Any, Any, Any, Any, Any]:
        """Dynamically import required reportlab modules.

        Returns
        -------
        tuple[Any, Any, Any, Any, Any]
            ``(colors, pagesizes, styles, units, platypus)`` modules.
        """
        colors = importlib.import_module("reportlab.lib.colors")
        pagesizes = importlib.import_module("reportlab.lib.pagesizes")
        styles = importlib.import_module("reportlab.lib.styles")
        units = importlib.import_module("reportlab.lib.units")
        platypus = importlib.import_module("reportlab.platypus")
        return colors, pagesizes, styles, units, platypus

    def _format_size(self, size_bytes: int) -> str:
        """Convert bytes to a compact, readable unit string."""
        if size_bytes <= 0:
            return "0 B"

        value = float(size_bytes)
        units = ["B", "KB", "MB", "GB"]
        unit_idx = 0
        while value >= 1024.0 and unit_idx < len(units) - 1:
            value /= 1024.0
            unit_idx += 1
        return f"{value:.1f} {units[unit_idx]}"
