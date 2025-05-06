import pefile
pe = pefile.PE("C:\\Windows\\System32\\notepad.exe")
print(pe.OPTIONAL_HEADER.AddressOfEntryPoint)