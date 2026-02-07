"""
Professional PDF report generator for threat summaries.
Creates well-formatted, branded PDF reports.
"""
from fpdf import FPDF
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
import os


# Colors (RGB)
COLORS = {
    "primary": (41, 128, 185),      # Blue
    "danger": (231, 76, 60),        # Red
    "warning": (243, 156, 18),      # Orange
    "success": (39, 174, 96),       # Green
    "dark": (44, 62, 80),           # Dark gray
    "light": (236, 240, 241),       # Light gray
    "white": (255, 255, 255),
}

SEVERITY_COLORS = {
    "Critical": COLORS["danger"],
    "High": (192, 57, 43),          # Dark red
    "Medium": COLORS["warning"],
    "Low": COLORS["success"],
    "Unknown": (149, 165, 166),     # Gray
}


class ThreatReportPDF(FPDF):
    """Professional threat intelligence report PDF."""
    
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=20)
        
    def header(self):
        # Header background
        self.set_fill_color(*COLORS["primary"])
        self.rect(0, 0, 210, 30, 'F')
        
        # Title
        self.set_font("Helvetica", "B", 18)
        self.set_text_color(*COLORS["white"])
        self.set_y(8)
        self.cell(0, 10, "AI Threat Intelligence Report", align="C")
        
        # Subtitle with timestamp
        self.set_font("Helvetica", "", 10)
        self.set_y(18)
        self.cell(0, 6, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", align="C")
        
        self.ln(25)
    
    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*COLORS["dark"])
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}} | AI Threat Intel Platform", align="C")
    
    def clean_text(self, text: str) -> str:
        """Clean text for PDF compatibility."""
        if not text:
            return ""
        # Replace problematic characters
        replacements = {
            "•": "-",
            "→": "->",
            "←": "<-",
            "✓": "[OK]",
            "✗": "[X]",
            "⚠": "[!]",
            "🔍": "",
            "📧": "",
            "🚨": "",
            "🛡": "",
        }
        for old, new in replacements.items():
            text = text.replace(old, new)
        return text.encode("latin-1", "ignore").decode("latin-1")
    
    def add_section_header(self, title: str):
        """Add a section header with styling."""
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(*COLORS["primary"])
        self.cell(0, 10, self.clean_text(title), ln=True)
        
        # Underline
        self.set_draw_color(*COLORS["primary"])
        self.set_line_width(0.5)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(5)
    
    def add_summary_stats(self, summaries: List[Dict[str, Any]]):
        """Add summary statistics section."""
        self.add_section_header("Executive Summary")
        
        total = len(summaries)
        severity_counts = {}
        for s in summaries:
            sev = s.get("severity", "Unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        # Stats box
        self.set_fill_color(*COLORS["light"])
        self.rect(10, self.get_y(), 190, 25, 'F')
        
        self.set_font("Helvetica", "", 11)
        self.set_text_color(*COLORS["dark"])
        
        y_start = self.get_y() + 5
        self.set_xy(15, y_start)
        self.cell(40, 6, f"Total Threats: {total}", ln=False)
        
        x_pos = 60
        for sev in ["Critical", "High", "Medium", "Low"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                self.set_xy(x_pos, y_start)
                self.set_text_color(*SEVERITY_COLORS.get(sev, COLORS["dark"]))
                self.cell(35, 6, f"{sev}: {count}", ln=False)
                x_pos += 35
        
        self.set_text_color(*COLORS["dark"])
        self.set_y(y_start + 20)
        self.ln(5)
    
    def add_threat(self, threat: Dict[str, Any], index: int):
        """Add a single threat entry with full formatting."""
        # Check if we need a new page
        if self.get_y() > 240:
            self.add_page()
        
        severity = threat.get("severity", "Unknown")
        severity_color = SEVERITY_COLORS.get(severity, COLORS["dark"])
        
        # Threat header box
        self.set_fill_color(*severity_color)
        self.rect(10, self.get_y(), 190, 10, 'F')
        
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*COLORS["white"])
        self.set_xy(12, self.get_y() + 2)
        
        ioc_display = self.clean_text(threat.get("input", "Unknown")[:60])
        self.cell(0, 6, f"#{index + 1} | {ioc_display}")
        
        self.ln(12)
        
        # Details section
        self.set_text_color(*COLORS["dark"])
        
        # Timestamp and severity
        self.set_font("Helvetica", "", 9)
        timestamp = threat.get("timestamp", "N/A")
        corrected = " (Corrected)" if threat.get("corrected") else ""
        self.cell(0, 5, f"Timestamp: {timestamp} | Severity: {severity}{corrected}", ln=True)
        
        # Enrichment data
        enrichment = threat.get("enrichment", "")
        if enrichment and enrichment != "No network enrichment available.":
            self.set_font("Helvetica", "I", 9)
            self.set_text_color(100, 100, 100)
            self.multi_cell(0, 4, f"Intel: {self.clean_text(enrichment[:150])}")
            self.ln(2)
        
        # MITRE ATT&CK Tactics (if available)
        tactics = threat.get("mitre_tactics")
        if tactics:
            self.set_font("Helvetica", "B", 9)
            self.set_text_color(*COLORS["primary"])
            self.cell(0, 5, f"MITRE ATT&CK: {', '.join(tactics)}", ln=True)
        
        # Summary
        self.set_font("Helvetica", "", 10)
        self.set_text_color(*COLORS["dark"])
        summary = self.clean_text(threat.get("summary", "No summary available."))
        
        # Truncate if too long
        if len(summary) > 800:
            summary = summary[:800] + "..."
        
        self.multi_cell(0, 5, summary)
        
        # Recommendations (if available)
        recommendations = threat.get("recommendations")
        if recommendations:
            self.set_font("Helvetica", "B", 9)
            self.set_text_color(*COLORS["success"])
            self.cell(0, 6, "Recommendations:", ln=True)
            self.set_font("Helvetica", "", 9)
            self.set_text_color(*COLORS["dark"])
            for i, rec in enumerate(recommendations[:3], 1):
                self.multi_cell(0, 4, f"  {i}. {self.clean_text(rec[:100])}")
        
        self.ln(8)
    
    def add_footer_notes(self):
        """Add footer notes section."""
        self.add_section_header("Notes")
        self.set_font("Helvetica", "I", 9)
        self.set_text_color(100, 100, 100)
        self.multi_cell(0, 4, 
            "This report was automatically generated by the AI Threat Intelligence Platform. "
            "All threat assessments are based on available intelligence and should be verified "
            "by security analysts before taking action. Severity levels are determined using "
            "LLM analysis and may require manual review."
        )


def generate_pdf(
    summaries: List[Dict[str, Any]], 
    output_path: str = "logs/threat_summary_report.pdf"
) -> str:
    """
    Generate a professional PDF report from threat summaries.
    
    Args:
        summaries: List of threat summary dictionaries.
        output_path: Path to save the PDF.
        
    Returns:
        Path to the generated PDF.
    """
    pdf = ThreatReportPDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    
    # Add summary statistics
    if summaries:
        pdf.add_summary_stats(summaries)
    
    # Add threats section
    pdf.add_section_header(f"Threat Analysis ({len(summaries)} items)")
    
    for i, threat in enumerate(summaries):
        pdf.add_threat(threat, i)
    
    # Add footer notes
    pdf.add_footer_notes()
    
    # Ensure output directory exists
    output_dir = Path(output_path).parent
    output_dir.mkdir(parents=True, exist_ok=True)
    
    pdf.output(output_path)
    return output_path


def generate_executive_summary_pdf(
    summaries: List[Dict[str, Any]],
    output_path: str = "logs/executive_summary.pdf"
) -> str:
    """
    Generate a brief executive summary PDF (1-2 pages).
    Shows only critical/high threats with key stats.
    """
    # Filter to critical/high only
    high_priority = [s for s in summaries if s.get("severity") in ("Critical", "High")]
    
    pdf = ThreatReportPDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    
    pdf.add_summary_stats(summaries)
    
    if high_priority:
        pdf.add_section_header(f"Critical & High Priority Threats ({len(high_priority)})")
        for i, threat in enumerate(high_priority[:10]):  # Limit to 10
            pdf.add_threat(threat, i)
    else:
        pdf.set_font("Helvetica", "I", 11)
        pdf.cell(0, 10, "No critical or high priority threats detected.", ln=True)
    
    pdf.add_footer_notes()
    
    output_dir = Path(output_path).parent
    output_dir.mkdir(parents=True, exist_ok=True)
    
    pdf.output(output_path)
    return output_path
