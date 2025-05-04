# scan_virustotal.py
import os
import requests
import time
import hashlib
from dotenv import load_dotenv
from fpdf import FPDF
from scan_strings import extract_strings, analyze_strings

# Load API key
load_dotenv("VirusTotalAPIkey.env")
API_KEY = os.getenv("VT_API_KEY")
HEADERS = {"x-apikey": API_KEY}
MAX_FILE_SIZE = 650 * 1024 * 1024  # 650MB

# ----------------------------
# VirusTotal Functions
# ----------------------------
def get_file_hash(file_path):
    """Compute SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def check_existing_report(file_hash):
    """Check if a file hash already has a report on VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        return response.json()
    return None

def upload_file(file_path):
    """Upload a file to VirusTotal for analysis."""
    url = "https://www.virustotal.com/api/v3/files"
    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f.read())}
        response = requests.post(url, headers=HEADERS, files=files)
    return response

def poll_analysis(analysis_id):
    """Poll analysis endpoint until completion."""
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    while True:
        response = requests.get(url, headers=HEADERS)
        if response.status_code == 200:
            report = response.json()
            status = report["data"]["attributes"]["status"]
            if status == "completed":
                return report
            time.sleep(30)  # Check every 30 seconds
        else:
            return None

# ----------------------------
# PDF Report
# ----------------------------
def generate_pdf_report(report, strings_summary=None, filename="report.pdf"):
    """Generate a PDF report."""
    attributes = report["data"]["attributes"]
    
    # Extract stats
    stats = attributes.get("stats", attributes.get("last_analysis_stats", {}))
    results = attributes.get("results", attributes.get("last_analysis_results", {}))
    
    # Initialize PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # Title
    pdf.cell(200, 10, txt="VirusTotal Scan Report", ln=1, align="C")
    pdf.ln(10)

    # Stats Table
    pdf.set_fill_color(240, 240, 240)
    pdf.cell(90, 10, txt="Category", border=1, fill=True)
    pdf.cell(90, 10, txt="Count", border=1, fill=True, ln=1)
    
    pdf.cell(90, 10, txt="Malicious", border=1)
    pdf.cell(90, 10, txt=str(stats.get("malicious", 0)), border=1, ln=1)
    
    pdf.cell(90, 10, txt="Suspicious", border=1)
    pdf.cell(90, 10, txt=str(stats.get("suspicious", 0)), border=1, ln=1)
    
    pdf.cell(90, 10, txt="Undetected", border=1)
    pdf.cell(90, 10, txt=str(stats.get("undetected", 0)), border=1, ln=1)
    pdf.ln(15)

    # Strings Analysis Section
    if strings_summary:
        pdf.set_font("Arial", "B", 12)
        pdf.cell(200, 10, txt="Strings Analysis Summary:", ln=1)
        pdf.set_font("Arial", size=10)
        
        for category, count in strings_summary.items():
            pdf.cell(200, 10, txt=f"{category}: {count}", ln=1)
        pdf.ln(10)

    pdf.output(filename)
    print(f"[+] PDF report generated: {filename}")

# ----------------------------
# Main Workflow
# ----------------------------
def scan_file(file_path):
    """Full scanning workflow."""
    # Validate file
    if not os.path.exists(file_path):
        print(f"[-] File not found: {file_path}")
        return
    if os.path.getsize(file_path) > MAX_FILE_SIZE:
        print("[-] File exceeds 650MB limit.")
        return

    # Check existing report via hash
    file_hash = get_file_hash(file_path)
    if report := check_existing_report(file_hash):
        print("[+] Existing report found.")
    else:
        print("[+] Submitting file to VirusTotal...")
        response = upload_file(file_path)
        if response.status_code != 200:
            print(f"[-] Upload failed: {response.text}")
            return
        analysis_id = response.json()["data"]["id"]
        print(f"[+] Analysis ID: {analysis_id}")
        report = poll_analysis(analysis_id)
        if not report:
            print("[-] Analysis timed out.")
            return

    # Strings analysis
    strings_file = extract_strings(file_path)
    strings_summary = analyze_strings(strings_file) if strings_file else None

    # Generate report
    generate_pdf_report(report, strings_summary)
    return report, strings_summary

if __name__ == "__main__":
    file_path = "EICAR.txt"  # Test with EICAR file
    scan_file(file_path)