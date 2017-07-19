'''



All scans realted to http and https.

curl http://192.168.118.187/robots.txt

nmap --script http-methods -p 80 192.168.118.187

nmap --script http-methods -p 443 192.168.118.187

xsstracer

wafw00f

whatweb



'''

def nikto_scan(ip_address, output_directory, port):
    ip_address = ip_address.strip()

    print("[+] Starting nikto scan for %s" % (ip_address))
    NIKTOSCAN = "nikto -host %s -port %s -Tuning x 6 -evasion 2 -nointeractive -Format txt -o %s/%s_nikto.txt" % (ip_address, port, outputdir, ip_address)
    niktoresults = subprocess.check_output(NIKTOSCAN, shell=True)
    print("[+] Nikto scan completed for %s" % (ip_address))

def wordpress_scan(ip_address, output_directory, port, path):
    ip_address = ip_address.strip()

    print("[+] Starting wpscan scan for %s" % (ip_address))
    WPSCAN = "wpscan --username admin --wordlist /usr/share/wordlists/fasttrack.txt --url http://%s/%s -e u vp vt > %s/%s_wpscan.txt" % (ip_address, path)
    wpscanresults = subprocess.check_output(WPSCAN, shell=True)
    print("[+] Wpscan scan completed for %s" % (ip_address))
