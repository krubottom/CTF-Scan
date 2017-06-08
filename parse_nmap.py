'''

Parse nmap scans

'''

import os
import parse_nmap

def parse_nmap(results, ip_address, output_directory):
   recommendations_file = output_directory + "/" + ip_address + "_findings.txt"
   serv_dict = {}
   lines = results.split("\n")
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

   print("[+] Writing findings for %s" % (ip_address))
   f = open(recommendations_file, 'w')
   for serv in serv_dict:
       ports = serv_dict[serv]
       if ("ftp" in serv):
           for port in ports:
               port = port.split("/")[0]
               f.write("[*] Found FTP service on %s:%s\n" % (ip_address, port))
               print("   [>] Found FTP service on %s:%s" % (ip_address, port))
               f.write("      [=] nmap -sV -Pn -vv -p%s --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN '%s/%s_ftp.nmap' -oX '%s/%s_ftp_nmap_scan_import.xml' %s\n" % (port, output_directory, ip_address, output_directory, ip_address, ip_address))
               f.write("      [=] hydra -L /usr/share/wordlists/webslayer/others/names.txt -P /usr/share/wordlists/webslayer/others/common_pass.txt -f -o %s/%s_ftphydra.txt -u %s -s %s ftp\n" % (output_directory, ip_address, ip_address, port))
       elif (serv == "http") or (serv == "ssl/http") or ("https" in serv) or ("http" in serv):
           for port in ports:
               port = port.split("/")[0]
               print("   [>] Found HTTP service on %s:%s" % (ip_address, port))
               nikto_scan(ip_address, output_directory, port)

               f.write("   [>] Use nikto & dirb / dirbuster for service enumeration, e.g\n")
               f.write("      [=] nikto -h %s -p %s > %s/%s_nikto.txt\n" % (ip_address, port, output_directory, ip_address))
               f.write("      [=] dirb http://%s:%s/ -o %s/%s_dirb.txt -r -S -x ./dirb-extensions/php.ext\n" % (ip_address, port, output_directory, ip_address))
               f.write("      [=] java -jar /usr/share/dirbuster/DirBuster-1.0-RC1.jar -H -l /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -r %s/%s_dirbuster.txt -u http://%s:%s/\n" % (output_directory, ip_address, ip_address, port))
               f.write("      [=] gobuster -w /usr/share/seclists/Discovery/Web_Content/common.txt -u http://%s:%s/ -s '200,204,301,302,307,403,500' -e > %s/%s_gobuster_common.txt -t 50 \n" % (ip_address, port, output_directory, ip_address))
               f.write("      [=] gobuster -w /usr/share/seclists/Discovery/Web_Content/cgis.txt -u http://%s:%s/ -s '200,204,301,307,403,500' -e > %s/%s_gobuster_cgis.txt -t 50 \n" % (ip_address, port, output_directory, ip_address))
               f.write("   [>] Use curl to retreive web headers and find host information, e.g\n")
               f.write("      [=] curl -i %s\n" % (ip_address))
               f.write("      [=] curl -i %s/robots.txt -s | html2text\n" % (ip_address))
       elif "mysql" in serv:
           for port in ports:
               port = port.split("/")[0]
               f.write("[*] Found mysql service on %s:%s\n" % (ip_address, port))
               print("   [>] Found mysql service on %s:%s" % (ip_address, port))
               f.write("   [>] Check out the server for web applications with sqli vulnerabilities\n")
       elif "telnet" in serv:
           for port in ports:
               port = port.split("/")[0]
               f.write("[*] Found telnet service on %s:%s\n" % (ip_address, port))
               print("   [>] Found telnet service on %s:%s" % (ip_address, port))
               f.write("   [>] Check out the server headers to enumerate further\n")
               f.write("      [=] nc -nv %s %s\n" % (ip_address, port))
       elif "microsoft-ds" in serv:
           for port in ports:
               port = port.split("/")[0]
               f.write("[*] Found MS SMB service on %s:%s\n" % (ip_address, port))
               print("   [>] Found MS SMB service on %s:%s" % (ip_address, port))
               f.write("   [>] Use nmap scripts or enum4linux for further enumeration, e.g\n")
               f.write("      [=] nmap -sV -Pn -vv -p 139,%s --script=smb-vuln* --script-args=unsafe=1 -oN '%s/%s_smb.nmap' -oX '%s/%s_smb_nmap_scan_import.xml' %s\n" % (port, output_directory, ip_address, output_directory, ip_address, ip_address))
               f.write("      [=] enum4linux %s > %s/%s_enum4linux.txt\n" % (ip_address, output_directory, ip_address))
               f.write("      [=] nmap -sV -Pn -vv -p %s --script=smb-enum-users -oN '%s/%s_smb_smb-enum-users.nmap' %s\n" % (port, output_directory, ip_address, ip_address))
       elif "ms-sql" in serv:
           for port in ports:
               port = port.split("/")[0]
               f.write("[*] Found MS SQL service on %s:%s\n" % (ip_address, port))
               print("   [>] Found MS SQL service on %s:%s" % (ip_address, port))
               f.write("   [>] Use nmap scripts for further enumeration, e.g\n")
               f.write("      [=] nmap -vv -sV -Pn -p %s --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=%s,smsql.username-sa,mssql.password-sa -oX %s/%s_mssql_nmap_scan_import.xml %s" % (port, port, output_directory, ip_address, ip_address))
       elif ("msdrdp" in serv) or ("ms-wbt-server" in serv):
           for port in ports:
               port = port.split("/")[0]
               f.write("[*] Found RDP service on %s:%s\n" % (ip_address, port))
               print("   [>] Found RDP service on %s:%s" % (ip_address, port))
               f.write("   [>] Use ncrackpassword cracking, e.g\n")
               f.write("      [=] ncrack -vv --user administrator -P /root/rockyou.txt rdp://%s\n" % (ip_address))
       elif "smtp" in serv:
           for port in ports:
               port = port.split("/")[0]
               f.write("[*] Found SMTP service on %s:%s\n" % (ip_address, port))
               print("   [>] Found SMTP service on %s:%s" % (ip_address, port))
               f.write("   [>] Use smtp-user-enum to find users, e.g\n")
               f.write("      [=] smtp-user-enum -M VRFY -U /usr/share/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/names/namelist.txt -t %s -p %s\n" % (ip_address, port))
       elif "snmp" in serv:
           for port in ports:
               port = port.split("/")[0]
               f.write("[*] Found SNMP service on %s:%s\n" % (ip_address, port))
               print("   [>] Found SNMP service on %s:%s" % (ip_address, port))
               f.write("   [>] Use nmap scripts, onesixtyone or snmwalk for further enumeration, e.g\n")
               f.write("      [=] nmap -sV -Pn -vv -p%s --script=snmp-netstat,snmp-processes -oN '%s/%s_snmp.nmap' -oX '%s/%s_snmp_nmap_scan_import.xml' %s\n" % (port, output_directory, ip_address, output_directory, ip_address, ip_address))
               f.write("      [=] onesixtyone %s\n" % (ip_address))
               f.write("      [=] snmpwalk -c public -v1 %s > %s/%s_snmpwalk.txt\n" % (ip_address, output_directory, ip_address))
       elif "ssh" in serv:
           for port in ports:
               port = port.split("/")[0]
               f.write("[*] Found SSH service on %s:%s\n" % (ip_address, port))
               print("   [>] Found SSH service on %s:%s" % (ip_address, port))
               f.write("   [>] Use medusa or hydra (unreliable) for password cracking, e.g\n")
               f.write("      [=] medusa -u root -P /root/rockyou.txt -e ns -h %s - %s -M ssh\n" % (ip_address, port))
               f.write("      [=] hydra -f -V -t 1 -l root -P /root/rockyou.txt -s %s %s ssh\n" % (port, ip_address))
               f.write("   [>] Use nmap to automate banner grabbing and key fingerprints, e.g.\n")
               f.write("      [=] nmap %s -p %s -sV --script=ssh-hostkey -oN '%s/%s_ssh-hostkey.nmap' \n" % (ip_address, port, output_directory, ip_address))

   f.close()
