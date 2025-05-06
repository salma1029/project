import subprocess
import os

def get_certutil_hash(file_path, hash_type="SHA256"):
    """Get the hash of the file using CertUtil (e.g., SHA256)."""
    try:
        result = subprocess.run(
            ["certutil", "-hashfile", file_path, hash_type],
            capture_output=True,
            text=True,
            check=True
        )
        # Extract the hash from the output
        output = result.stdout.strip().split("\n")[-1]
        return output
    except subprocess.CalledProcessError as e:
        print(f"[-] CertUtil failed: {e.stderr}")
        return None

def decode_base64(file_path, output_file="decoded_output.bin"):
    """Attempts to decode a Base64-encoded file using CertUtil."""
    if not os.path.exists(file_path):
        print(f"[-] File {file_path} not found.")
        return None

    try:
        result = subprocess.run(
            ["certutil", "-decode", file_path, output_file],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print(f"[-] Base64 decoding failed:\n{result.stderr.strip()}")
            return None

        print(f"[+] Base64 decoding successful. Output saved to {output_file}")
        return output_file

    except Exception as e:
        print(f"[-] Exception during decoding: {e}")
        return None
