"""Structured threat report generator for autonomous USB analysis.

Produces JSON, formatted markdown, and PDF reports from the autonomous
agent's full 7-stage analysis pipeline output.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ReportGenerator:
    """Generate structured threat reports in multiple formats.

    Supports JSON dict, formatted markdown string, and PDF file output
    (via reportlab when available).
    """

    def __init__(self, reports_dir: Path | None = None) -> None:
        self._reports_dir = reports_dir or (
            Path(__file__).resolve().parent.parent / "reports"
        )
        self._reports_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, analysis: dict[str, Any]) -> dict[str, Any]:
        """Build full structured report from autonomous agent analysis output.

        Parameters
        ----------
        analysis:
            The complete analysis dict from AutonomousUSBAgent containing
            device_summary, file_structure, suspicious_findings,
            behavioral_analysis, mitre_mapping, classification, and
            recommendations.

        Returns
        -------
        dict[str, Any]
            The report dict with added 'report_markdown', 'report_json_path',
            and 'report_pdf_path' keys.
        """
        report = self._build_report_dict(analysis)
        report["report_markdown"] = self._render_markdown(report)
        report["generated_at"] = datetime.now(timezone.utc).isoformat()

        # Save JSON report
        json_path = self._save_json(report)
        report["report_json_path"] = str(json_path) if json_path else None

        # Save PDF report
        pdf_path = self._save_pdf(report)
        report["report_pdf_path"] = str(pdf_path) if pdf_path else None

        return report

    def _build_report_dict(self, analysis: dict[str, Any]) -> dict[str, Any]:
        """Assemble structured report sections from raw analysis data."""
        device = analysis.get("device_summary", {})
        files = analysis.get("file_results", [])
        suspicious = analysis.get("suspicious_findings", [])
        behavioral = analysis.get("behavioral_analysis", {})
        mitre = analysis.get("mitre_mapping", [])
        classification = analysis.get("classification", {})
        recommendations = analysis.get("recommendations", [])
        self_improvement = analysis.get("self_improvement", {})
        event_id = analysis.get("event_id", 0)

        # File structure overview
        total_files = len(files)
        file_types: dict[str, int] = {}
        for f in files:
            ext = str(f.get("file_name", "")).rsplit(".", 1)[-1].lower() if "." in str(f.get("file_name", "")) else "unknown"
            file_types[ext] = file_types.get(ext, 0) + 1

        safe_count = sum(1 for f in files if str(f.get("risk_level", "")).lower() in {"safe", "low"})
        medium_count = sum(1 for f in files if str(f.get("risk_level", "")).lower() == "medium")
        high_count = sum(1 for f in files if str(f.get("risk_level", "")).lower() in {"high", "critical"})

        return {
            "report_title": "HID Shield — Autonomous USB Threat Analysis Report",
            "event_id": event_id,

            # Section 1: USB Device Summary
            "usb_device_summary": {
                "device_name": device.get("device_name", "Unknown Device"),
                "vendor_id": device.get("vendor_id", "N/A"),
                "product_id": device.get("product_id", "N/A"),
                "serial_number": device.get("serial_number", "N/A"),
                "manufacturer": device.get("manufacturer", "N/A"),
                "device_type": device.get("device_type", "unknown"),
                "is_hid_device": device.get("is_hid_device", False),
                "mount_point": device.get("mount_point", "N/A"),
                "hardware_id": device.get("hardware_id", "N/A"),
            },

            # Section 2: File Structure Overview
            "file_structure_overview": {
                "total_files": total_files,
                "file_type_distribution": file_types,
                "safe_files": safe_count,
                "medium_risk_files": medium_count,
                "high_risk_files": high_count,
            },

            # Section 3: Suspicious Findings
            "suspicious_findings": suspicious,

            # Section 4: Behavioral Analysis Results
            "behavioral_analysis": behavioral,

            # Section 5: Attack Mapping (MITRE ATT&CK)
            "mitre_attack_mapping": {
                "techniques_matched": len(mitre),
                "techniques": [m if isinstance(m, dict) else m.to_dict() for m in mitre],
                "tactics_summary": self._group_by_tactic(mitre),
            },

            # Section 6: Final Threat Classification
            "final_classification": classification,

            # Section 7: Recommended Actions
            "recommended_actions": recommendations,

            # Bonus: Self-Improvement Analysis
            "self_improvement": self_improvement,
        }

    def _render_markdown(self, report: dict[str, Any]) -> str:
        """Render the report dict as a formatted markdown string."""
        lines: list[str] = []
        lines.append(f"# {report.get('report_title', 'USB Threat Analysis Report')}")
        lines.append(f"\n**Event ID:** {report.get('event_id', 'N/A')}  ")
        lines.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
        lines.append(f"**Engine:** HID Shield Autonomous Agent v1.0")
        lines.append("")

        # Section 1
        lines.append("---")
        lines.append("## 1. USB Device Summary")
        lines.append("")
        dev = report.get("usb_device_summary", {})
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        for key, label in [
            ("device_name", "Device Name"),
            ("vendor_id", "Vendor ID"),
            ("product_id", "Product ID"),
            ("serial_number", "Serial Number"),
            ("manufacturer", "Manufacturer"),
            ("device_type", "Device Type"),
            ("is_hid_device", "HID Device"),
            ("mount_point", "Mount Point"),
            ("hardware_id", "Hardware ID"),
        ]:
            val = dev.get(key, "N/A")
            if isinstance(val, bool):
                val = "✅ Yes" if val else "❌ No"
            lines.append(f"| {label} | {val} |")
        lines.append("")

        # Section 2
        lines.append("---")
        lines.append("## 2. Detected File Structure Overview")
        lines.append("")
        fs = report.get("file_structure_overview", {})
        lines.append(f"**Total Files:** {fs.get('total_files', 0)}  ")
        lines.append(f"**Safe:** {fs.get('safe_files', 0)} | **Medium Risk:** {fs.get('medium_risk_files', 0)} | **High Risk:** {fs.get('high_risk_files', 0)}")
        lines.append("")
        dist = fs.get("file_type_distribution", {})
        if dist:
            lines.append("| Extension | Count |")
            lines.append("|-----------|-------|")
            for ext, count in sorted(dist.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"| .{ext} | {count} |")
            lines.append("")

        # Section 3
        lines.append("---")
        lines.append("## 3. Suspicious Findings")
        lines.append("")
        findings = report.get("suspicious_findings", [])
        if not findings:
            lines.append("✅ No suspicious findings detected.")
        else:
            for i, finding in enumerate(findings, 1):
                risk = str(finding.get("risk_level", "medium")).upper()
                emoji = "🔴" if risk in {"HIGH", "CRITICAL"} else "🟡"
                lines.append(f"{emoji} **{i}. {finding.get('file_name', 'Unknown')}**")
                lines.append(f"   - Risk: **{risk}**")
                lines.append(f"   - Threat: {finding.get('threat_name', 'N/A')}")
                lines.append(f"   - Reason: {finding.get('reason', 'N/A')}")
                lines.append(f"   - SHA256: `{finding.get('sha256', 'N/A')}`")
                lines.append("")
        lines.append("")

        # Section 4
        lines.append("---")
        lines.append("## 4. Behavioral Analysis Results")
        lines.append("")
        ba = report.get("behavioral_analysis", {})
        hid = ba.get("hid_analysis", {})
        if hid:
            lines.append(f"**HID Type:** {hid.get('hid_type', 'N/A')}  ")
            lines.append(f"**Keystroke Rate:** {hid.get('keystroke_rate', 0.0):.1f} KPS  ")
            lines.append(f"**Keystroke Label:** {hid.get('keystroke_label', 'SAFE')}  ")
            lines.append(f"**Is Anomalous:** {'⚠️ Yes' if hid.get('is_anomalous') else '✅ No'}  ")
            lines.append(f"**Is Composite:** {'⚠️ Yes' if hid.get('is_composite') else 'No'}  ")
            anomalies = hid.get("anomaly_reasons", [])
            if anomalies:
                lines.append("")
                lines.append("**Anomaly Reasons:**")
                for reason in anomalies:
                    lines.append(f"  - {reason}")
        else:
            lines.append("No HID behavioral data available.")
        lines.append("")

        # Section 5
        lines.append("---")
        lines.append("## 5. Attack Mapping (MITRE ATT&CK)")
        lines.append("")
        mitre = report.get("mitre_attack_mapping", {})
        techniques = mitre.get("techniques", [])
        if not techniques:
            lines.append("✅ No MITRE ATT&CK techniques matched.")
        else:
            lines.append(f"**Techniques Matched:** {mitre.get('techniques_matched', 0)}")
            lines.append("")
            lines.append("| Technique | Name | Tactic | Confidence |")
            lines.append("|-----------|------|--------|------------|")
            for t in techniques:
                conf = float(t.get("confidence", 0))
                conf_bar = "🔴" if conf >= 0.8 else "🟡" if conf >= 0.5 else "🟢"
                lines.append(
                    f"| {t.get('technique_id', 'N/A')} | {t.get('name', 'N/A')} | "
                    f"{t.get('tactic', 'N/A')} | {conf_bar} {conf:.0%} |"
                )
            lines.append("")

            # Evidence details
            for t in techniques:
                evidence = t.get("evidence", [])
                if evidence:
                    lines.append(f"**{t.get('technique_id')}** — {t.get('name')}:")
                    for ev in evidence[:5]:
                        lines.append(f"  - {ev}")
                    ai_exp = t.get("ai_explanation", "")
                    if ai_exp:
                        lines.append(f"  - 🤖 AI: {ai_exp}")
                    lines.append("")

        # Section 6
        lines.append("---")
        lines.append("## 6. Final Threat Classification")
        lines.append("")
        cls = report.get("final_classification", {})
        level = str(cls.get("level", "LOW")).upper()
        emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(level, "⚪")
        lines.append(f"### {emoji} Threat Level: **{level}**")
        lines.append("")
        lines.append(f"**Confidence:** {cls.get('confidence', 0):.0%}  ")
        lines.append(f"**Risk Score:** {cls.get('risk_score', 0):.1f}/100  ")
        lines.append(f"**Policy Action:** {cls.get('policy_action', 'N/A')}  ")
        lines.append(f"**Explanation:** {cls.get('explanation', 'N/A')}")
        lines.append("")

        # Section 7
        lines.append("---")
        lines.append("## 7. Recommended Actions")
        lines.append("")
        actions = report.get("recommended_actions", [])
        if not actions:
            lines.append("✅ Allow with standard monitoring.")
        else:
            for action in actions:
                priority = str(action.get("priority", "")).upper()
                icon = "🔴" if priority == "HIGH" else "🟡" if priority == "MEDIUM" else "🟢"
                lines.append(f"{icon} **{action.get('action', 'N/A')}**")
                lines.append(f"   - {action.get('description', '')}")
                lines.append("")

        # Self-improvement section
        si = report.get("self_improvement", {})
        if si:
            lines.append("---")
            lines.append("## 8. Self-Improvement Analysis")
            lines.append("")
            gaps = si.get("detection_gaps", [])
            if gaps:
                lines.append("### Detection Gaps Identified")
                for gap in gaps:
                    lines.append(f"- **{gap.get('area', 'Unknown')}**: {gap.get('description', '')}")
                lines.append("")

            vulns = si.get("vulnerability_status", [])
            if vulns:
                lines.append("### Vulnerability Remediation Status")
                lines.append("| VULN ID | Status | Description |")
                lines.append("|---------|--------|-------------|")
                for v in vulns:
                    status_icon = {"fixed": "✅", "partial": "🟡", "unfixed": "🔴"}.get(v.get("status", ""), "⚪")
                    lines.append(f"| {v.get('id', '')} | {status_icon} {v.get('status', '').title()} | {v.get('description', '')} |")
                lines.append("")

            recs = si.get("recommendations", [])
            if recs:
                lines.append("### Pipeline Enhancement Recommendations")
                for rec in recs:
                    lines.append(f"- {rec}")
                lines.append("")

        lines.append("---")
        lines.append(f"*Report generated by HID Shield Autonomous Agent v1.0 at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}*")

        return "\n".join(lines)

    def _save_json(self, report: dict[str, Any]) -> Path | None:
        """Save full report as JSON file."""
        try:
            event_id = report.get("event_id", 0)
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"autonomous_report_{event_id}_{timestamp}.json"
            path = self._reports_dir / filename

            serializable = self._make_serializable(report)
            with path.open("w", encoding="utf-8") as fh:
                json.dump(serializable, fh, indent=2, ensure_ascii=False)
            print(f"[REPORT] JSON report saved: {path}")
            return path
        except Exception as exc:
            print(f"[REPORT] Failed to save JSON report: {exc}")
            return None

    def _save_pdf(self, report: dict[str, Any]) -> Path | None:
        """Save report as PDF using reportlab."""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.units import mm
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.colors import HexColor
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            )
            from reportlab.lib import colors
        except ImportError:
            print("[REPORT] reportlab not available, skipping PDF generation.")
            return None

        try:
            event_id = report.get("event_id", 0)
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"autonomous_report_{event_id}_{timestamp}.pdf"
            path = self._reports_dir / filename

            doc = SimpleDocTemplate(str(path), pagesize=A4,
                                    leftMargin=20*mm, rightMargin=20*mm,
                                    topMargin=15*mm, bottomMargin=15*mm)

            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                "ReportTitle", parent=styles["Title"],
                fontSize=18, textColor=HexColor("#00d4ff"),
                spaceAfter=12,
            )
            heading_style = ParagraphStyle(
                "SectionHeading", parent=styles["Heading2"],
                fontSize=13, textColor=HexColor("#00d4ff"),
                spaceBefore=12, spaceAfter=6,
            )
            body_style = ParagraphStyle(
                "ReportBody", parent=styles["Normal"],
                fontSize=9, leading=13,
            )
            small_style = ParagraphStyle(
                "SmallText", parent=styles["Normal"],
                fontSize=8, leading=11, textColor=HexColor("#666666"),
            )

            elements: list[Any] = []

            # Title
            elements.append(Paragraph(report.get("report_title", "USB Threat Report"), title_style))
            elements.append(Paragraph(
                f"Event #{event_id} | Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
                small_style,
            ))
            elements.append(Spacer(1, 8*mm))

            # Section 1: Device Summary
            elements.append(Paragraph("1. USB Device Summary", heading_style))
            dev = report.get("usb_device_summary", {})
            dev_data = [["Field", "Value"]]
            for key, label in [
                ("device_name", "Device Name"), ("vendor_id", "Vendor ID"),
                ("product_id", "Product ID"), ("serial_number", "Serial"),
                ("device_type", "Type"), ("manufacturer", "Manufacturer"),
            ]:
                dev_data.append([label, str(dev.get(key, "N/A"))])
            dev_table = Table(dev_data, colWidths=[45*mm, 120*mm])
            dev_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1a1f2e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#333333")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#f8f9fa"), colors.white]),
            ]))
            elements.append(dev_table)
            elements.append(Spacer(1, 4*mm))

            # Section 6: Classification
            elements.append(Paragraph("6. Final Threat Classification", heading_style))
            cls = report.get("final_classification", {})
            level = str(cls.get("level", "LOW")).upper()
            level_color = {"HIGH": "#ff006e", "MEDIUM": "#ffb800", "LOW": "#00ff88"}.get(level, "#666")
            elements.append(Paragraph(
                f'<font color="{level_color}" size="14"><b>THREAT LEVEL: {level}</b></font>',
                body_style,
            ))
            elements.append(Paragraph(f"Confidence: {cls.get('confidence', 0):.0%} | Risk Score: {cls.get('risk_score', 0):.1f}/100", body_style))
            elements.append(Paragraph(f"Explanation: {cls.get('explanation', 'N/A')}", body_style))
            elements.append(Spacer(1, 4*mm))

            # Section 5: MITRE
            mitre = report.get("mitre_attack_mapping", {})
            techniques = mitre.get("techniques", [])
            if techniques:
                elements.append(Paragraph("5. MITRE ATT&CK Mapping", heading_style))
                mitre_data = [["Technique", "Name", "Tactic", "Confidence"]]
                for t in techniques[:15]:
                    mitre_data.append([
                        t.get("technique_id", ""), t.get("name", "")[:40],
                        t.get("tactic", ""), f"{float(t.get('confidence', 0)):.0%}",
                    ])
                mitre_table = Table(mitre_data, colWidths=[25*mm, 55*mm, 45*mm, 25*mm])
                mitre_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1a1f2e")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#333333")),
                ]))
                elements.append(mitre_table)
                elements.append(Spacer(1, 4*mm))

            # Section 7: Actions
            actions = report.get("recommended_actions", [])
            if actions:
                elements.append(Paragraph("7. Recommended Actions", heading_style))
                for action in actions:
                    elements.append(Paragraph(
                        f"• <b>{action.get('action', '')}</b>: {action.get('description', '')}",
                        body_style,
                    ))
                elements.append(Spacer(1, 4*mm))

            # Footer
            elements.append(Spacer(1, 8*mm))
            elements.append(Paragraph(
                "Generated by HID Shield Autonomous Agent v1.0 — Confidential",
                small_style,
            ))

            doc.build(elements)
            print(f"[REPORT] PDF report saved: {path}")
            return path

        except Exception as exc:
            print(f"[REPORT] PDF generation failed: {exc}")
            return None

    def _group_by_tactic(self, techniques: list[Any]) -> dict[str, int]:
        """Count matched techniques per tactic."""
        counts: dict[str, int] = {}
        for t in techniques:
            tactic = t.get("tactic", "Unknown") if isinstance(t, dict) else t.technique.tactic
            counts[tactic] = counts.get(tactic, 0) + 1
        return counts

    def _make_serializable(self, obj: Any) -> Any:
        """Recursively convert non-serializable objects for JSON."""
        if isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self._make_serializable(item) for item in obj]
        if isinstance(obj, Path):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, "to_dict"):
            return obj.to_dict()
        try:
            json.dumps(obj)
            return obj
        except (TypeError, ValueError):
            return str(obj)
