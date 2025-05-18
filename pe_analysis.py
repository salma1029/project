#pe_analysis.py
import pefile
import math
import os
import datetime

SUSPICIOUS_APIS = {
    "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "LoadLibrary",
    "GetProcAddress", "WinExec", "ShellExecute", "CreateProcess", "RegOpenKey",
    "OpenProcess", "TerminateProcess", "InternetOpen", "InternetConnect",
    "URLDownloadToFile", "WSAStartup", "send", "recv"
}

PACKER_SECTIONS = {
    '.UPX0', '.UPX1', 'UPX!', '.aspack', '.vmp',
    'ASPack', 'Themida', '.packed', '.rc4', 'y0da'
}

def calculate_entropy(data):
    if not data:
        return 0.0
    entropy = 0.0
    frequency = [0] * 256
    for byte in data:
        frequency[byte] += 1
    for count in frequency:
        if count == 0:
            continue
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy

def analyze_pe(file_path):
    if not os.path.exists(file_path):
        return {"Error": "File not found"}

    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        return {"Error": "Not a valid PE file"}

    result = {
        "Entry Point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "Image Base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "Compilation Time": datetime.datetime.utcfromtimestamp(
            pe.FILE_HEADER.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S'),
        "PE Header": {
            "Machine": hex(pe.FILE_HEADER.Machine),
            "Number of Sections": pe.FILE_HEADER.NumberOfSections,
            "Subsystem": hex(pe.OPTIONAL_HEADER.Subsystem),
            "DLL": bool(pe.FILE_HEADER.Characteristics & 0x2000)
        },
        "File Size": os.path.getsize(file_path),
        "Size of Image": pe.OPTIONAL_HEADER.SizeOfImage,
        "Sections": [],
        "Suspicious APIs": [],
        "Suspicious Sections": [],
        "Imports": [],
        "Exports": [],
        "Packer Indicators": {"detected": False, "reasons": []}
    }

    # Section analysis
    for section in pe.sections:
        name = section.Name.decode(errors='ignore').strip('\x00')
        entropy = calculate_entropy(section.get_data())
        flags = section.Characteristics
        exec_flag = flags & 0x20000000
        write_flag = flags & 0x80000000

        result["Sections"].append({
            "Name": name,
            "Entropy": round(entropy, 2),
            "Size": section.SizeOfRawData,
            "Executable": bool(exec_flag),
            "Writable": bool(write_flag),
            "Suspicious": entropy > 7.0
        })

        if name in PACKER_SECTIONS:
            result["Packer Indicators"]["detected"] = True
            result["Packer Indicators"]["reasons"].append(f"Known packer section: {name}")

        if exec_flag and write_flag:
            result["Suspicious Sections"].append(name)

    # Import analysis
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors='ignore')
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode(errors='ignore')
                    funcs.append(name)
                    if name in SUSPICIOUS_APIS:
                        result["Suspicious APIs"].append(name)
            result["Imports"].append({dll: funcs})

    # Export analysis
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            result["Exports"].append({
                "Name": exp.name.decode(errors='ignore') if exp.name else "Ordinal",
                "Ordinal": exp.ordinal,
                "Address": hex(exp.address),
                "Forwarded": bool(exp.forwarder)
            })

    # Heuristic: file size vs image size
    if result["File Size"] < result["Size of Image"] * 0.5:
        result["Packer Indicators"]["detected"] = True
        result["Packer Indicators"]["reasons"].append("Unusual file size vs image size")

    return result