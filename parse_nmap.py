'''

Parse nmap scans


check namp scan for robots.txt

'''

import os
from argparse import ArgumentParser
import xml.etree.ElementTree as ET
# import parse_nmap
import www_scan

def main():
    parser = ArgumentParser()
    parser.add_argument("-f",   dest="nmap_file", required=True, help="Nmap XML File to parse" )
    arguments = parser.parse_args()
    f = open(arguments.nmap_file,"r")
    parse_nmap(f.read())
    f.close()

def parse_nmap(results_file):

    nmap_dict = {}

    root = ET.fromstring(results_file)

    for host in root.iter('host'):
        ip_address = host[1].get('addr')
    #     for osmatch in host.iter('osmatch'):
    #         host_os = osmatch.get('name')
    #
    # print ip_address, host_os

    for port in root.iter('port'):
        ports=[]
        nmap_port = port.get('portid')
        for state in port.iter('state'):
            nmap_state = state.get('state')
        for service in port.iter('service'):
            nmap_service = service.get('name')
            if service.get('version'):
                nmap_version = service.get('version')

        if nmap_service in nmap_dict:
            ports = nmap_dict[nmap_service]

        ports.append(nmap_port)
        nmap_dict[nmap_service] = ports

    # print nmap_dict

    for serv in nmap_dict:
        ports = nmap_dict[serv]
        if ("ftp" in serv):
            for port in ports:
                print("   [>] Found FTP service on %s:%s" % (ip_address, port))
        elif (serv == "http") or (serv == "ssl/http") or ("https" in serv) or ("http" in serv):
            for port in ports:
                print("   [>] Found HTTP service on %s:%s" % (ip_address, port))
                nikto_scan(ip_address, port)
                # print("nikto scan of %s on port %s to directory %s" % (ip_address, port, "test"))
        elif "mysql" in serv:
            for port in ports:
                print("   [>] Found mysql service on %s:%s" % (ip_address, port))
        elif "telnet" in serv:
            for port in ports:
                print("   [>] Found telnet service on %s:%s" % (ip_address, port))
        elif "microsoft-ds" in serv:
            for port in ports:
                # enum4linux
                print("   [>] Found MS SMB service on %s:%s" % (ip_address, port))
        elif "ms-sql" in serv:
            for port in ports:
                print("   [>] Found MS SQL service on %s:%s" % (ip_address, port))
        elif ("msdrdp" in serv) or ("ms-wbt-server" in serv):
            for port in ports:
                print("   [>] Found RDP service on %s:%s" % (ip_address, port))
                # nmap -A -sV -Pn -T5 --script=rdp-* -p 3389 $TARGET
        elif "smtp" in serv:
            for port in ports:
                print("   [>] Found SMTP service on %s:%s" % (ip_address, port))
        elif "snmp" in serv:
            for port in ports:
                print("   [>] Found SNMP service on %s:%s" % (ip_address, port))
        elif "ssh" in serv:
            for port in ports:
                print("   [>] Found SSH service on %s:%s" % (ip_address, port))
        elif "unknown" in serv:
            for port in ports:
                print("   [>] Found Unknown service on %s:%s" % (ip_address, port))


if __name__ == "__main__":
    main()
