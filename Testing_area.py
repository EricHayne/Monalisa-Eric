#!/usr/bin/env python3
import sys
import nmap3    # using pip python3-nmap module
import os
import json

# #!/usr/bin/env python3
# import nmap3
 

def test(i):           
    nmap = nmap3.NmapScanTechniques()
    results = nmap.nmap_tcp_scan(i, args="-p- -sV -O -sT -sU")   
    print(results)         

def main():
    test("192.168.56.104")

if __name__ == '__main__':
    main()