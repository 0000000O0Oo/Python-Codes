import magic
import optparse
import hashlib 
import pefile 
import sys
import os
import urllib.request
import urllib.response
import urllib.parse
import json
from colorama import Fore, Style, Back
from capstone import *

class Hashes:
    def __init__(self, md5h, sha256h, sha1h):
        self.sha256h = sha256h
        self.sha1h = sha1h
        self.md5h = md5h

def banner():
    print(Fore.RED + """
███████╗███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
█████╗  ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔══╝  ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║     ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝""" + "\n" + "\tVersion 1.0 By TheGreenGremlin" + Fore.RESET + "\n")

def getPlatform():
    return os.name

def clearConsole(CurrentOs):
    if CurrentOs == "posix" or CurrentOs == "Linux" or CurrentOs == "linux2":
        os.system("clear")
    elif CurrentOs == "win32" or CurrentOs == "Windows" or CurrentOs == "nt":
        os.system("cls")
    else:
        print(Fore.RED + "[-] System not found...\n[-] Really weird things happening here...\n[-] Don't worry i'll just yeet it ;)" + Fore.RESET)

def getFile():
    parser = optparse.OptionParser()
    parser.add_option("-f", "--file", dest="filename", help="Enter the name of the file you want to scan")
    parser.add_option("-s", "--scan", dest="api", help="Use -s or --scan following by your VirusTotal apikey to scan the file for viruses")
    (options, arguments) = parser.parse_args()
    if not options.filename:
        parser.error(Fore.RED + "Please enter a filename using the -f or --file arguments !" + Fore.RESET)
    if options.api == "":
        return options.filename
    else:
        return options

def determineType(file):
    m = magic.Magic(mime=False, uncompress=True if file.endswith('.gz') or file.endswith('.zip') or file.endswith('gzip') or file.endswith('.tar') or file.endswith('.tar.gz') else None)
    ftype = m.from_file(file)
    print(Fore.GREEN + Style.BRIGHT + "[+] File type : " + Fore.RED + ftype + Fore.RESET)
    return ftype

def getHashValue(file):
    content = open(file, 'rb').read()
    md5hash = hashlib.md5(content).hexdigest()
    sha256hash = hashlib.sha256(content).hexdigest()
    sha1hash = hashlib.sha1(content).hexdigest()
    print(Fore.GREEN + "[+] MD5 Hash : " + Fore.RED + md5hash + Fore.RESET)
    print(Fore.GREEN + "[+] SHA256 Hash : " + Fore.RED + sha256hash + Fore.RESET)
    print(Fore.GREEN + "[+] SHA1 Hash : " + Fore.RED + sha1hash + Style.RESET_ALL + Fore.RESET)
    hashes = Hashes(md5hash, sha256hash, sha1hash)
    return hashes

def getImportTable(file):
    print(Fore.RED + "[-]"+ ("-" * 64) + "[-]" + Fore.RESET)
    print(Fore.GREEN + Style.BRIGHT + "[+] PE Analysis :" + Style.RESET_ALL + Fore.RESET)
    pe = pefile.PE(file)
    for section in pe.sections:
        print(Fore.GREEN + Style.BRIGHT + "\t[+] Section", ((section.Name).decode("utf-8")), " : ", Fore.RED, hex(section.VirtualAddress), hex(section.Misc_VirtualSize), section.SizeOfRawData, Style.RESET_ALL, Fore.RESET)
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(Fore.GREEN + Style.BRIGHT + "[+] Imported DLLs : " + (entry.dll).decode("utf-8") + Style.RESET_ALL + Fore.GREEN)
        for function in entry.imports:
            print(Fore.GREEN + Style.BRIGHT + "\t[+] " + (Fore.YELLOW if (function.name).decode("utf-8").startswith("?") or (function.name).decode("utf-8").startswith("_") or (function.name).decode("utf-8").startswith("__") else Fore.RED) + (function.name).decode("utf-8") + Style.RESET_ALL + Fore.RESET) 

def getDisassembly(file):
    print(Fore.RED + "[-]"+ ("-" * 64) + "[-]")
    print(Fore.GREEN + Style.BRIGHT + "[+] Basic Disassembly : " + Style.RESET_ALL + Fore.RESET)
    PEFile = pefile.PE(file)
    #Get Address of the program entrypoint
    entrypoint = PEFile.OPTIONAL_HEADER.AddressOfEntryPoint
    #Computer memory address where the entry code will be loaded into memory
    entrypoint_address = entrypoint + PEFile.OPTIONAL_HEADER.ImageBase
    #get the binary code from the PE file object
    binary_code = PEFile.get_memory_mapped_image()[entrypoint:entrypoint+100]
    #initialize the disassembler to disassemble 32bit x64 Binary Code
    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    #disassemble the code
    for instruction in disassembler.disasm(binary_code, entrypoint_address):
        print(Fore.GREEN + Style.BRIGHT + "\t[+] " + Fore.RED + "{0}\t{1}".format(instruction.mnemonic, instruction.op_str) + Style.RESET_ALL + Fore.RESET)

def AVScan(hashVal, apikey):
    print(Fore.RED + "[-]"+ ("-" * 64) + "[-]" + Fore.RESET)
    print(Fore.GREEN + "[+] Virus Total Scan :" + Fore.RESET)
    VirusTotalURL = "https://www.virustotal.com/vtapi/v2/file/report"
    parameters = {'apikey': apikey, 'resource': hashVal}
    encodedParams = urllib.parse.urlencode(parameters)
    req = VirusTotalURL + "?" + encodedParams
    try:
        response = urllib.request.urlopen(req)
    except urllib.error.HTTPError:
        print(Fore.RED + "[-] Invalid API Key, Please provide a valid key !" + Fore.RESET)
        return
    jsonresponse = json.loads(response.read())
    if jsonresponse['response_code']:
        detections = jsonresponse['positives']
        total = jsonresponse['total']
        scan_results = jsonresponse['scans']
        print(Fore.GREEN + "Detections: " + Fore.RED + "{0}".format(detections) + Fore.GREEN + "/" + Fore.RED + "{0}".format(total) + Fore.RESET)
        print(Fore.GREEN + "VirusTotal Results : " + Fore.RESET)
        for avname, avdata in scan_results.items():
            print((Fore.GREEN if avdata['result'] is not None else Fore.RED) + "\t{0} ===>".format(avname) + (Fore.GREEN if avdata['result'] is not None else Fore.RED) + " {0}".format(avdata['result']) + Fore.RESET)
    else:
        print(Fore.GREEN + "[-] No AV Detections For : {0}".format(hashVal) + Fore.RESET)

def main():
    CurrentOs = getPlatform()
    clearConsole(CurrentOs)
    banner()
    fOption = getFile()
    #if you want to skip the -s argument and automatically scan
    apikey = "" #***You can also replace this by your API Key and automatically scan without providing -s argument***
    #if the -s option argument is provided
    if fOption.api:
        apikey = fOption.api
    file = fOption.filename
    fileType = determineType(file)
    Hash = getHashValue(file)

    #If the file is a PE32 Executable analyze it else do nothing
    if file.endswith(".exe") and "PE" in fileType:
            getImportTable(file)
            getDisassembly(file)
    else:
        print(Fore.RED + "[-] Skipping PE Analysis since the file is not a valid PE file !" + Fore.RESET)

    if fOption.api:
        AVScan(Hash.md5h, apikey)
    elif apikey != "":
        AVScan(Hash.md5h, apikey)
    else:
        print(Fore.RED + "[-] No API Key provided skipping VirusTotal Scan !" + Fore.RESET)

main()
