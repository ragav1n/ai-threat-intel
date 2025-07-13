from fpdf import FPDF
from datetime import datetime
import os

class PDFReport(FPDF):
    def header(self):
        self.set_font("Arial", "B", 14)
        self.cell(0, 10, "Threat Summary Report", ln=True, align="C")
        self.set_font("Arial", "", 10)
        self.cell(0, 10, f"Generated at: {datetime.utcnow().isoformat()}", ln=True, align="C")
        self.ln(5)

    def clean_text(self, text):
        # Replace or strip unsupported characters (e.g., bullets, emojis)
        return text.replace("•", "-").encode("ascii", "ignore").decode("ascii")

    def add_threat(self, threat):
        self.set_font("Arial", "B", 12)
        self.multi_cell(0, 8, self.clean_text(f"Input: {threat['input']}"))
        self.set_font("Arial", "", 11)
        self.cell(0, 8, f"Timestamp: {threat['timestamp']}", ln=True)
        self.cell(0, 8, f"Severity: {threat['severity']}" + (" (Corrected)" if threat.get("corrected") else ""), ln=True)
        self.set_font("Courier", "", 10)
        self.multi_cell(0, 6, self.clean_text(threat['summary']))
        self.ln(5)

def generate_pdf(summaries, output_path="logs/threat_summary_report.pdf"):
    pdf = PDFReport()
    pdf.add_page()

    for s in summaries:
        pdf.add_threat(s)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    pdf.output(output_path)
    return output_path
