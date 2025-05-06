import os
import sys
from certutil_wrapper import get_certutil_hash, decode_base64
from pe_analysis import analyze_pe
from scan_strings import extract_strings, analyze_strings
from virustotal_api import (
    get_file_hash,
    check_existing_report,
    upload_file,
    poll_analysis,
)
from fpdf import FPDF

def generate_pdf(report, strings_summary, pe_results,filename="report.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Malware Analysis Report", ln=True, align="C")
    pdf.ln(10)

    # VirusTotal
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, txt="VirusTotal Report", ln=True)
    pdf.set_font("Arial", size=10)
    stats = report["data"]["attributes"].get("stats", report["data"]["attributes"].get("last_analysis_stats", {}))
    for key in ["malicious", "suspicious", "undetected"]:
        pdf.cell(200, 10, txt=f"{key.capitalize()}: {stats.get(key, 0)}", ln=True)

    pdf.ln(10)

    # Strings
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, txt="Strings Analysis", ln=True)
    pdf.set_font("Arial", size=10)
    for key, val in strings_summary.items():
        pdf.cell(200, 10, txt=f"{key}: {val}", ln=True)

    pdf.ln(10)

    # PE Analysis
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, txt="PE Analysis", ln=True)
    pdf.set_font("Arial", size=10)
    for key, val in pe_results.items():
        if isinstance(val, list):
            text = f"{key}: {', '.join(str(v) for v in val)}"
            pdf.multi_cell(0, 10, text)
        else:
            pdf.cell(200, 10, txt=f"{key}: {val}", ln=True)

    pdf.ln(10)

    

    pdf.output(filename)
    print(f"[+] PDF saved to {filename}")

def main(file_path):
    if not os.path.exists(file_path):
        print("[-] File not found.")
        return
    
    # --- VirusTotal ---
    print("[*] Scanning with VirusTotal...")
    file_hash = get_file_hash(file_path)
    report = check_existing_report(file_hash)
    if not report:
        response = upload_file(file_path)
        if response.status_code == 200:
            analysis_id = response.json()["data"]["id"]
            report = poll_analysis(analysis_id)
        else:
            print("[-] VirusTotal upload failed.")
            return

    # --- Strings ---
    print("[*] Extracting strings...")
    strings_file = extract_strings(file_path)
    strings_summary = analyze_strings(strings_file) if strings_file else {}

    # --- PEFile ---
    print("[*] Performing PE analysis...")
    pe_results = analyze_pe(file_path)

     # --- Generate Report ---
    safe_name = os.path.basename(file_path).replace(" ", "_") + "_report.pdf"
    generate_pdf(report, strings_summary, pe_results,filename=safe_name)

    return os.path.abspath(safe_name)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python main.py <path_to_file>")
    else:
        main(sys.argv[1])
