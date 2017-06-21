#!/usr/bin/python
import sys
from argparse import ArgumentParser

from ping_sweeper import ping_sweeper
from find_dns import find_dns
from service_scan import service_scan
from hostname_scan import hostname_scan
# from snmp_walk import snmp_walk


'''

Code and influences taken from:

https://github.com/codingo/Reconnoitre
https://github.com/1N3/Sn1per

searchsploit --nmap $LOOT_DIR/nmap/nmap-$TARGET.xml

nmap -A -sV -T5 -Pn -p 513 --script=rlogin* $TARGET
nmap -A -sV -Pn -T5 -p 512 --script=rexec* $TARGET

enum4linux

nmap -A -sV -Pn -T5 --script=ms-sql* -p 1433 $TARGET

nmap -A -sV -Pn --script=mysql* -p 3306 $TARGET
mysql -u root -h $TARGET -e 'SHOW DATABASES; SELECT Host,User,Password FROM mysql.user;'

nmap -A -sV  -T5 --script=vnc* -p 5900 $TARGET

nmap -A -sV -Pn -T5 --script=irc* -p 6667 $TARGET

Scan 8443 as ssl



'''

def print_banner():
    print("~~~Banner~~~\n")


def main():
    parser = ArgumentParser()
    parser.add_argument("-t",           dest="target_hosts", required=True, help="Set a target range of addresses to target. Ex 10.11.1.1-255" )
    parser.add_argument("-o",           dest="output_directory", required=True, help="Set the output directory. Ex /root/Documents/labs/")
    parser.add_argument("-w",           dest="wordlist", required=False, help="Set the wordlist to use for generated commands. Ex /usr/share/wordlist.txt")
    parser.add_argument("--pingsweep",  dest="ping_sweep", action="store_true", help="Write a new target.txt by performing a ping sweep and discovering live hosts.", default=False)
    parser.add_argument("--dns",        dest="find_dns_servers", action="store_true", help="Find DNS servers from a list of targets.", default=False)
    parser.add_argument("--services",   dest="perform_service_scan", action="store_true", help="Perform service scan over targets.", default=False)
    parser.add_argument("--hostnames",  dest="hostname_scan", action="store_true", help="Attempt to discover target hostnames and write to 0-name.txt and hostnames.txt.", default=False)
    parser.add_argument("--quick",      dest="quick",   action="store_true", required=False, help="Move to the next target after performing a quick scan and writing first-round recommendations.", default=False)
    parser.add_argument("--quiet",      dest="quiet",   action="store_true", help="Supress banner and headers to limit to comma dilimeted results only.", default=False)
    parser.add_argument("--stealth",    dest="stealth", action="store_true", help="Only run non-intrusive scans to avoid tripping IDS", default=False)
    parser.add_argument("--use-msf",    dest="use-msf", action="store_true", help="Check common Metasploit exploits.", default=False)
    parser.add_argument("--pdf-report", dest="pdf-report", action="store_true", help="Generate host report in PDF format", default=False)
    parser.add_argument("--md-report",  dest="md-report", action="store_true", help="Generate host report in MD format for GIT.", default=False)
    parser.add_argument("--brute-force",dest="brute-force", action="store_true", help="Attempt a brute force login attack on services using the Kali fasttrack.txt.  Caution!  This will drastily increase script run time.")
    arguments = parser.parse_args()

    if len(sys.argv) == 1:
        print_banner()
        parser.error("No arguments given.")
        parser.print_usage
        sys.exit()

    if arguments.output_directory.endswith('/' or '\\'):
        arguments.output_directory = arguments.output_directory[:-1]
    if arguments.target_hosts.endswith('/' or '\\'):
        arguments.target_hosts = arguments.target_hosts[:-1]

    if arguments.quiet is not True:
        print_banner()
    if arguments.ping_sweep is True:
        print("[#] Performing ping sweep")
        ping_sweeper(arguments.target_hosts, arguments.output_directory, arguments.quiet)
    if arguments.hostname_scan is True:
        print("[#] Identifying hostnames")
        hostname_scan(arguments.target_hosts, arguments.output_directory, arguments.quiet)
    if arguments.find_dns_servers is True:
        print("[#] Identifying DNS Servers")
        find_dns(arguments.target_hosts, arguments.output_directory, arguments.quiet)
    if arguments.perform_service_scan is True:
        print("[#] Performing service scans")
        if arguments.find_dns_servers is True:
            service_scan(arguments.target_hosts, arguments.output_directory, arguments.find_dns_servers, arguments.quiet, arguments.quick)
        else:
            service_scan(arguments.target_hosts, arguments.output_directory, '', arguments.quiet, arguments.quick)
    # if arguments.perform_snmp_walk is True:
    #     print("[#] Performing SNMP walks")
    #     snmp_walk(arguments.target_hosts, arguments.output_directory, arguments.quiet)

if __name__ == "__main__":
    main()
