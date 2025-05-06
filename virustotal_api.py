# virustotal_api.py
import os
import time
import requests
import hashlib
from dotenv import load_dotenv

# Load API Key
load_dotenv("VirusTotalAPIkey.env")
API_KEY = os.getenv("VT_API_KEY")
HEADERS = {"x-apikey": API_KEY}
MAX_FILE_SIZE = 650 * 1024 * 1024  # 650MB

def get_file_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def check_existing_report(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    response = requests.get(url, headers=HEADERS)
    return response.json() if response.status_code == 200 else None

def upload_file(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f.read())}
        response = requests.post(url, headers=HEADERS, files=files)
    return response

def poll_analysis(analysis_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    while True:
        response = requests.get(url, headers=HEADERS)
        if response.status_code == 200:
            data = response.json()
            if data["data"]["attributes"]["status"] == "completed":
                return data
            time.sleep(30)
        else:
            return None
