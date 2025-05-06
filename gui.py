import tkinter as tk
from tkinter import filedialog, messagebox
import os
import subprocess
import platform
from main import main as scan_file

# Global lists
selected_files = []
generated_reports = []

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

app.mainloop()
