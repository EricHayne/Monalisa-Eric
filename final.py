#!/usr/bin/env python3
import sys
import nmap3
import os
import json
import ifcfg

nmap = nmap3.Nmap()

def subnet(network):
    net = network.rpartition(".")
    net = net[0]+".1/24"
    return net

def ifscan():
    ip=[]
    network=[]
    for name, interface in ifcfg.interfaces().items():
        ip.append(interface['device'])
        network.append(interface['inet']) 
    ip.pop(-1)
    network.pop(-1)
    return network, ip 

def pick_subnet(ip, network):
    print("we have found the following networks")
    count=0
    for i in ip:
        net= subnet(network[count])
        net = net.rpartition(".")
        net = net[0]+".1/24"
        print(str(count+1)+".",i,net)
        count+=1
    print(str(count+1)+".","exit" )
    x=input('pleas select the subnet you would like to scan: ')
    x=int(x)
    if x == count+1:
        print("\n"+"good-by")
        exit()
    subnet_addres = subnet(network[x-1])
    my_pc = network[x-1]
    return subnet_addres, my_pc

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
    print('\n We have found the following IP address:')
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
        print("ERROR not a veiled selection")
        selection = input ("pleas select a IP address from the list above to run a scan on: ")
        selection = int(selection)

    if selection == count+2:
        ip.append(0)
    elif selection == count+1:
        ip =ip_list
    else:
        ip.append(ip_list[selection-1])
    print("you selectied:",ip)
    if ip[0] == 0:
        print("good_by")
        exit()
    return  ip

def run_nmap_two(ip_address):
    results = []
    nmap = nmap3.NmapScanTechniques()
    for i in ip_address:
        results.append(nmap.nmap_tcp_scan(i))
    return results

def print_resalts(text, ip_select):
    print(json.dumps(text, indent=2))
    print("\n \n resalts are also save to this directory, file name:  ", ip_select[0]+"_port_scan.txt" )

def main():
    network, ip = ifscan()
    subnet_ip = pick_subnet(ip, network)
    #print(subnet_ip)
    #subnet_ip= ["192.168.56.1/24","192.168.56.107"]
    ip_list = run_nmap(subnet_ip)
    ip_select = find_ip(ip_list)
    ip_address = select_ip(ip_select,subnet_ip)
    text = run_nmap_two(ip_address)
    print_resalts(text, ip_address)

if __name__ == '__main__':
    main()