import tkinter as tk
from tkinter import filedialog, messagebox
import os
import subprocess
import platform
from pe_analysis import analyze_pe
from scan_strings import extract_strings, analyze_strings
from virustotal_api import (
    get_file_hash, check_existing_report, upload_file, poll_analysis
)

# Global lists
selected_files = []
generated_reports = []

from reportlab.lib.pagesizes import LETTER
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

def safe_str(text):
    if not isinstance(text, str):
        text = str(text)
    return text

def generate_pdf(report, strings_summary, pe_results, filename="report.pdf"):
    try:
        doc = SimpleDocTemplate(filename, pagesize=LETTER,
                                rightMargin=72, leftMargin=72,
                                topMargin=72, bottomMargin=72)
        styles = getSampleStyleSheet()
        Story = []

        # Title
        Story.append(Paragraph("Malware Analysis Report", styles['Title']))
        Story.append(Spacer(1, 12))

        # VirusTotal Report
        Story.append(Paragraph("VirusTotal Report:", styles['Heading2']))

        # Highlight detection stats
        detection_keys = ["Harmless", "Malicious", "Suspicious", "Undetected", "Timeout"]
        for key in detection_keys:
            value = report.get(key, "N/A")
            color = "black"
            if key == "Malicious":
                color = "red"
            elif key == "Harmless":
                color = "green"
            elif key == "Suspicious":
                color = "orange"
            text = f'<font color="{color}"><b>{safe_str(key)}:</b> {safe_str(value)}</font>'
            Story.append(Paragraph(text, styles['Normal']))

        # Metadata and extra info
        other_keys = [k for k in report.keys() if k not in detection_keys]
        Story.append(Spacer(1, 12))
        Story.append(Paragraph("File Metadata:", styles['Heading3']))
        for key in other_keys:
            value = safe_str(report[key])
            text = f"<b>{safe_str(key)}:</b> {value}"
            Story.append(Paragraph(text, styles['Normal']))

        # Strings Analysis Summary
        Story.append(Paragraph("Strings Analysis Summary:", styles['Heading2']))
        for key, value in strings_summary.items():
            text = f"<b>{safe_str(key)}:</b> {safe_str(value)}"
            Story.append(Paragraph(text, styles['Normal']))
        Story.append(Spacer(1, 12))

        # PE Analysis
        Story.append(Paragraph("PE Analysis:", styles['Heading2']))
        for key, value in pe_results.items():
            if isinstance(value, list):
                Story.append(Paragraph(f"<b>{safe_str(key)}:</b>", styles['Normal']))
                for item in value:
                    Story.append(Paragraph(f"&nbsp;&nbsp;- {safe_str(item)}", styles['Normal']))
            elif isinstance(value, dict):
                Story.append(Paragraph(f"<b>{safe_str(key)}:</b>", styles['Normal']))
                for subkey, subval in value.items():
                    Story.append(Paragraph(f"&nbsp;&nbsp;{safe_str(subkey)}: {safe_str(subval)}", styles['Normal']))
            else:
                Story.append(Paragraph(f"<b>{safe_str(key)}:</b> {safe_str(value)}", styles['Normal']))
        Story.append(Spacer(1, 12))

        doc.build(Story)
        return os.path.abspath(filename)
    except Exception as e:
        messagebox.showerror("PDF Error", f"Failed to save PDF: {e}")
        return None


def get_vt_summary(report):
    try:
        attr = report.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})

        summary = {
            "Harmless": stats.get("harmless", 0),
            "Malicious": stats.get("malicious", 0),
            "Suspicious": stats.get("suspicious", 0),
            "Undetected": stats.get("undetected", 0),
            "Timeout": stats.get("timeout", 0),
            "File Type": attr.get("type_description", "N/A"),
            "SHA256": attr.get("sha256", "N/A"),
            "MD5": attr.get("md5", "N/A"),
            "SHA1": attr.get("sha1", "N/A"),
            "Reputation Score": attr.get("reputation", "N/A"),
            "Popular Threat Label": attr.get("popular_threat_classification", {}).get("suggested_threat_label", "N/A"),
            "First Submission Date": attr.get("first_submission_date", "N/A"),
            "Last Analysis Date": attr.get("last_analysis_date", "N/A"),
            "Total Votes": attr.get("total_votes", {}),
            "Signature Info": attr.get("signature_info", {}),
        }

        # Convert timestamps (if needed)
        from datetime import datetime
        def convert_timestamp(ts):
            try:
                return datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                return "N/A"

        summary["First Submission Date"] = convert_timestamp(summary["First Submission Date"])
        summary["Last Analysis Date"] = convert_timestamp(summary["Last Analysis Date"])

        # Format total_votes (dictionary with 'harmless' and 'malicious')
        votes = summary["Total Votes"]
        if isinstance(votes, dict):
            summary["Total Votes"] = f"Harmless: {votes.get('harmless', 0)}, Malicious: {votes.get('malicious', 0)}"
        else:
            summary["Total Votes"] = "N/A"

        # Format signature_info if it's a dict
        sig_info = summary["Signature Info"]
        if isinstance(sig_info, dict):
            summary["Signature Info"] = ", ".join(f"{k}: {v}" for k, v in sig_info.items())
        else:
            summary["Signature Info"] = "N/A"

        return summary

    except Exception as e:
        return {
            "Error": f"Failed to parse VirusTotal report: {str(e)}"
        }

def scan_file(file_path):
    """Integrated scanning function formerly in main.py"""
    if not os.path.exists(file_path):
        messagebox.showerror("Error", f"File not found: {file_path}")
        return None

    try:
        # VirusTotal Analysis
        file_hash = get_file_hash(file_path)
        report = check_existing_report(file_hash)
        if not report:
            response = upload_file(file_path)
            if response.status_code == 200:
                analysis_id = response.json()["data"]["id"]
                report = poll_analysis(analysis_id)
            else:
                messagebox.showerror("Error", "VirusTotal upload failed")
                return None

        # Simplify VirusTotal report for PDF
        vt_summary = get_vt_summary(report)

        # Strings Analysis
        strings_file = extract_strings(file_path)
        strings_summary = analyze_strings(strings_file) if strings_file else {}

        # PE Analysis
        pe_results = analyze_pe(file_path)

        # Generate Report
        safe_name = os.path.basename(file_path).replace(" ", "_") + "_report.pdf"
        report_path = generate_pdf(vt_summary, strings_summary, pe_results, safe_name)
        return report_path

    except Exception as e:
        messagebox.showerror("Error", f"Scan failed: {str(e)}")
        return None

# Select multiple files
def select_files():
    files = filedialog.askopenfilenames(
        title="Select Files to Scan",
        filetypes=[("Executable and DLL files", "*.exe *.dll *.txt *.bin *.scr *.com"), ("All files", "*.*")]
    )
    if files:
        selected_files.clear()
        selected_files.extend(files)
        file_list_text.delete("1.0", tk.END)
        for f in files:
            file_list_text.insert(tk.END, f"{f}\n")

# Scan each selected file and track the report paths
def start_scan():
    if not selected_files:
        messagebox.showwarning("Warning", "No files selected.")
        return

    log_text.delete("1.0", tk.END)
    generated_reports.clear()

    for file in selected_files:
        log_text.insert(tk.END, f"Scanning: {file}\n")
        report_path = scan_file(file)
        if report_path:
            generated_reports.append(report_path)
            log_text.insert(tk.END, f"Report saved: {report_path}\n\n")
        else:
            log_text.insert(tk.END, f"[!] Failed to scan: {file}\n\n")

    messagebox.showinfo("Completed", "Scanning complete. Reports generated.")

# Open each generated report with the system PDF viewer
def open_report():
    if not generated_reports:
        messagebox.showwarning("Warning", "No reports available yet.")
        return
    for report in generated_reports:
        try:
            if platform.system() == "Windows":
                os.startfile(report)
            elif platform.system() == "Darwin":  # macOS
                subprocess.call(["open", report])
            else:  # Linux
                subprocess.call(["xdg-open", report])
        except Exception as e:
            messagebox.showerror("Error", f"Could not open report: {e}")

# GUI Setup
app = tk.Tk()
app.title("Malware Analysis Tool")
app.geometry("700x550")

tk.Label(app, text="Select Target Files:").pack(pady=10)
tk.Button(app, text="Browse Files", command=select_files).pack(pady=5)

file_list_text = tk.Text(app, height=10, width=80)
file_list_text.pack(pady=5)

tk.Button(app, text="Start Scan", command=start_scan).pack(pady=10)

tk.Button(app, text="Open Reports", command=open_report).pack(pady=5)

log_text = tk.Text(app, height=12, width=80)
log_text.pack(pady=10)

pe_analysis_text = tk.Text(app, height=15, width=80, bg="#f9f9f9")
pe_analysis_text.pack(pady=10)

app.mainloop()
