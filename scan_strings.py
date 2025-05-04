# scan_strings.py
import os
import subprocess
import re

def extract_strings(file_path, output_dir="strings_output"):
    """Extract printable strings from a file using the `strings` command."""
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
    """Analyze extracted strings for suspicious patterns."""
    suspicious_patterns = {
        "IP Addresses": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "URLs": r"https?://[^\s/$.?#].[^\s]*",
        "Executable Keywords": r"CreateFile|WriteFile|ShellExecute|regedit\.exe|cmd\.exe",
        "Hex Encoded": r"\\x[0-9a-fA-F]{2}",
    }

    with open(strings_file, "r", encoding="utf-8") as f:
        content = f.read()

    results = {}
    for name, pattern in suspicious_patterns.items():
        matches = re.findall(pattern, content)
        results[name] = len(matches)

    return results