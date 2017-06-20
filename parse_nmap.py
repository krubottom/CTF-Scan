'''

Parse nmap scans

'''

import os
from argparse import ArgumentParser
import xml.etree.ElementTree as ET
# import parse_nmap

def main():
    parser = ArgumentParser()
    parser.add_argument("-f",   dest="nmap_file", required=True, help="Nmap XML File to parse" )
    arguments = parser.parse_args()
    f = open(arguments.nmap_file,"r")
    # print f.read()
    parse_nmap(f.read())
    f.close()

def parse_nmap(results_file):

    root = ET.fromstring(results_file)

    for child in root:
        print child.tag

    serv_dict = {}
    ip_address = "test"

    lines = results_file.split("\n")
    for line in lines:
        ports = []
        line = line.strip()
        if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
            while "  " in line:
                line = line.replace("  ", " ");
            service = line.split(" ")[2]
            port = line.split(" ")[0]

            if service in serv_dict:
                ports = serv_dict[service]

            ports.append(port)
            serv_dict[service] = ports

    for serv in serv_dict:
        ports = serv_dict[serv]
        if ("ftp" in serv):
            for port in ports:
                port = port.split("/")[0]
                print("   [>] Found FTP service on %s:%s" % (ip_address, port))
        elif (serv == "http") or (serv == "ssl/http") or ("https" in serv) or ("http" in serv):
            for port in ports:
                port = port.split("/")[0]
                print("   [>] Found HTTP service on %s:%s" % (ip_address, port))
        elif "mysql" in serv:
            for port in ports:
                port = port.split("/")[0]
                print("   [>] Found mysql service on %s:%s" % (ip_address, port))
        elif "telnet" in serv:
            for port in ports:
                port = port.split("/")[0]
                print("   [>] Found telnet service on %s:%s" % (ip_address, port))
        elif "microsoft-ds" in serv:
            for port in ports:
                port = port.split("/")[0]
                print("   [>] Found MS SMB service on %s:%s" % (ip_address, port))
        elif "ms-sql" in serv:
            for port in ports:
                port = port.split("/")[0]
                print("   [>] Found MS SQL service on %s:%s" % (ip_address, port))
        elif ("msdrdp" in serv) or ("ms-wbt-server" in serv):
            for port in ports:
                port = port.split("/")[0]
                print("   [>] Found RDP service on %s:%s" % (ip_address, port))
        elif "smtp" in serv:
            for port in ports:
                port = port.split("/")[0]
                print("   [>] Found SMTP service on %s:%s" % (ip_address, port))
        elif "snmp" in serv:
            for port in ports:
                port = port.split("/")[0]
                print("   [>] Found SNMP service on %s:%s" % (ip_address, port))
        elif "ssh" in serv:
            for port in ports:
                port = port.split("/")[0]
                print("   [>] Found SSH service on %s:%s" % (ip_address, port))


if __name__ == "__main__":
    main()
