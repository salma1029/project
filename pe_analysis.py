# pe_analysis.py
import pefile

def analyze_pe(file_path):
    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        return {"Error": "Not a valid PE file"}

    result = {
        "Entry Point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "Image Base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "Sections": [s.Name.decode().strip('\x00') for s in pe.sections],
        "Imports": [],
    }

    # Get imported DLLs and functions
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode()
            functions = [imp.name.decode() if imp.name else "None" for imp in entry.imports]
            result["Imports"].append({dll: functions})

    return result
