# scan_strings.py
import os
import subprocess
import re

def extract_strings(file_path, output_dir="strings_output"):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    output_file = os.path.join(output_dir, f"{os.path.basename(file_path)}_strings.txt")
    
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            subprocess.run(
                ["strings", file_path],
                stdout=f,
                stderr=subprocess.PIPE,
                check=True
            )
        return output_file
    except subprocess.CalledProcessError as e:
        print(f"[-] Strings extraction failed: {e.stderr.decode()}")
        return None

def analyze_strings(strings_file):
    suspicious_patterns = {
        "IP Addresses": r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
        "URLs": r"https?://[^\s\"\'<>]+",
        "Executable Keywords": r"CreateFile|WriteFile|ShellExecute|cmd\.exe|powershell|regedit|CreateProcess|VirtualAlloc|GetProcAddress",
        "Hex Encoded": r"\\x[0-9a-fA-F]{2}",
        "Base64 Strings": r"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
        "Suspicious File Paths": r"(?:[a-zA-Z]:)?\\(?:Users|Windows|Temp|Program Files)[\\\w\.\-\s]*",
        "Registry Keys": r"HKEY_[A-Z_]+\\[^\s\"\'<>]+",
        "Email Addresses": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "Embedded Powershell": r"powershell\s+-[a-zA-Z]+\s+[^\s\"\'<>]+",
    }

    with open(strings_file, "r", encoding="utf-8") as f:
        content = f.read()

    results = {}
    for name, pattern in suspicious_patterns.items():
        matches = re.findall(pattern, content)
        results[name] = len(matches)

    return results