#!/usr/bin/env python3
import sys
import nmap3
import os
import json
nmap = nmap3.Nmap() 

def run_nmap(subnet):
    #results = []
    nmap = nmap3.NmapHostDiscovery()
    results = nmap.nmap_no_portscan(subnet[0])
    return results

def find_ip(ip_dump):
    ip_list = list (ip_dump.keys())
    ip_list.pop(-1)
    ip_list.pop(-1)  
    return ip_list

def select_ip(ip_list,subnet):
    your_pc = subnet[1]
    print(your_pc)
    print('We have found the following IP address:')
    count = 0
    ip = []
    for x in ip_list:
        count += 1
        if x == your_pc:
            print(str(count)+". ",ip_list[count-1],"This PC")
        else:
            print(str(count)+". ",ip_list[count-1])
    print (str(count+1) + ".  all IP address above")
    print (str(count+2)+ ".  exit")
    selection = input ("pleas select a IP address from the list above to run a scan on: ")
    selection = int(selection)
    
    while selection > count+2 or selection <1 :
        print("ERROR not a vailed slection")
        selection = input ("pleas select a IP address from the list above to run a scan on: ")
        selection = int(selection)
    
    if selection == count+2:
        ip = 0
    elif selection == count+1:
        ip = ip_list,subnet
    else:
        ip = ip_list [selection-1]
    print(ip)
    return  ip

def run_nmap_two(ip_address):
    nmap = nmap3.NmapScanTechniques()
    results = nmap.nmap_tcp_scan(ip_address)
    return results

def main():
    subnet = ["192.168.56.1/24","192.168.56.107"]
    ip_list = run_nmap(subnet)
    ip_select = find_ip(ip_list)
    ip_address=select_ip(ip_select, subnet)
    print_resalts(ip_address)

if __name__ == '__main__':    
    main()
    