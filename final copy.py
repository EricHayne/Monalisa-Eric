#!/usr/bin/env python3
import sys
import nmap3    # using pip python3-nmap module
import os
import json
import ifcfg    # using pip ifcfg module

nmap = nmap3.Nmap()
def ip_checker(this_thing):
    net= this_thing
    net = net.rpartition(".")
    if net[2] == "1/24":
        this_thing = net[0] + ".111"

    a = this_thing.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True

def input_checker(selection):
    try:
        val = int(selection)
        return val
    except ValueError:
        return selection

def subnet(network):
    net = network.rpartition(".")
    net = net[0]+".1/24"
    return net

# The ifscan function calls ifcfg module, which parses ifconfig output, such as Ethernet interface names and IPv4 addresses. The output values are added into a list and excludes the last item -being the loopback address info.
def ifscan():
    ip=[]
    network=[]
    for name, interface in ifcfg.interfaces().items():
        ip.append(interface['device'])      # Pulls Ethernet interfaces names
        network.append(interface['inet'])   # Pulls IPv4 addresses
    ip.pop(-1)      
    network.pop(-1)
    return network, ip

# The pick_subnet function lists the subnet(s) on the associated network interface. The user is then prompted to enter a numeric value corresponding to the listed subnet(s) (or "exit") from displayed list.
def pick_subnet(ip, network):
    print("We have found the following networks:")
    count=0
    for i in ip:
        net = subnet(network[count])
        net = net.rpartition(".")
        net = net[0]+".1/24"        # DEBUG: #1 ".1/24" is a placeholder. We need to reassess this line/function since we are assuming the subnet mask is "/24". For example, the subnet mask can be anywhere from 8 bits to 31 bits. We need to dynamically determine the subnet mask.
        print(str(count+1)+".",i,net)
        count+=1
    print(str(count+1)+".","enter another subnet or IP: ")
    print(str(count+2)+".","exit" )
    x=input('Please select the subnet you would like to scan: ')
    x=input_checker(x)
    
    while x not in range(1,(count+3)):   #DEBUG: #2 Need to ERROR on alphabet (a-z, A-Z) and on special characters (e.g. @, $, *, etc.)
        print("ERROR: not a valid selection")
        x = input ("Please select an IP address from the list above to run a scan on: ")
        x=input_checker(x)

    if x == count+2:
        print("\n"+"good-bye")
        exit()
    
    elif x == count+1:
        scan_ip=input("Pleas enter ip port or subnet to scan:  ")
        while ip_checker(scan_ip) == False:
            scan_ip=input("pleas input a valid IP:  ")
        my_pc= "0.0.0.0"
        subnet_addres = scan_ip
        return subnet_addres, my_pc

    else:
        subnet_addres = subnet(network[x-1])
        my_pc = network[x-1]        # Identifies the local host
    return subnet_addres, my_pc

# The run_nmap function calls nmap3 module, which runs scan type, Host Discovery and omits port scan.
def run_nmap(subnet):
    #results = []
    nmap = nmap3.NmapHostDiscovery()
    results = nmap.nmap_no_portscan(subnet[0])
    return results

# The find_ip function extracts the discovered IPv4 addresses.
def find_ip(ip_dump):
    ip_list = list (ip_dump.keys())
    ip_list.pop(-1)
    ip_list.pop(-1)  
    return ip_list

# The select_ip function lists the IPv4 addresses from the previously user selected subnet on the associated network interface. The user is then prompted to enter a numeric value corresponding to the listed IPv4 addresses (or "all IP addresses above" or "exit") from displayed list.
def select_ip(ip_list,subnet):
    your_pc = subnet[1]
    print('\n We have found the following IP addresses:')
    count = 0
    ip = []
    for x in ip_list:
        count += 1
        if x == your_pc:
            print(str(count)+". ",ip_list[count-1],"This PC")
        else:
            print(str(count)+". ",ip_list[count-1])
    print (str(count+1) + ".  all IP addresses above")
    print (str(count+2)+ ".  exit")
    selection = input ("Please select an IP address from the list above to run a scan on: ")
    
    selection=input_checker(selection)
    
    while selection not in range(1,(count+3)):   #DEBUG: #2 Need to ERROR on alphabet (a-z, A-Z) and on special characters (e.g. @, $, *, etc.)
        print("ERROR: not a valid selection")
        selection = input ("Please select an IP address from the list above to run a scan on: ")
        selection=input_checker(selection)

    if selection == count+2:
        ip.append(0)
    elif selection == count+1:
        ip =ip_list
    else:
        ip.append(ip_list[selection-1])
    print("You selected:",ip)
    if ip[0] == 0:
        print("good-bye")
        exit()
    return  ip

# The run_nmap_two function calls nmap3 module, which runs Nmap scan techniques, more specifically TCP scan on the previously user selected IP address(es).
def run_nmap_two(ip_address):
    results = []
    nmap = nmap3.NmapScanTechniques()
    for i in ip_address:
        #results.append(nmap.nmap_tcp_scan(i)) #this line is only for testing with a faster scan
        results.append(nmap.nmap_tcp_scan(i, args="-p- -sV -O -sT"))
    return results

def raw_to_human(raw,ip):
    list_1 = []
    list_2 = []
    list_3 = []
    list_4 = []
    list_5 = []
    list_6 = []
    list_7 = []
    list_8 = []
    print()
    count = 0
    for x in ip:
        if x in raw[count]:
            n=len(raw[count][x]['ports'])
            if n != 0:
                file = open(ip_select[x]+"_port_scan.txt", "w")
                for i in range(len(raw[count][x]['ports'])):
                    list_1.append(raw[count][x]['ports'][i].get('portid','none'))
                    list_2.append(raw[count][x]['ports'][i]['service'].get('name',"none"))
                    list_3.append(raw[count][x]['ports'][i]['service'].get('product',"none"))
                    list_4.append(raw[count][x]['ports'][i]['service'].get('name',"none"))
                    list_5.append(raw[count][x]['ports'][i]['service'].get('version',"none"))
                    list_6.append(raw[count][x]['ports'][i]['service'].get('extrainfo',"none"))
                    list_7.append(raw[count][x]['ports'][i]['service'].get('hostname',"none"))
                    list_8.append(raw[count][x]['ports'][i]['service'].get('conf',"none"))

                space_1 = len(max(list_1, key = len))+4
                space_2 = len(max(list_2, key = len))+4
                space_3 = len(max(list_3, key = len))+4
                space_4 = len(max(list_4, key = len))+4
                space_5 = len(max(list_5, key = len))+4
                space_6 = len(max(list_6, key = len))+10
                space_7 = len(max(list_7, key = len))+8
                space_8 = len(max(list_8, key = len))+10
                print('For IP: ',x)
                print('This computer is running: ',raw[0][x]['osmatch'][0].get('name','none'), 'accuracy: ',raw[0][x]['osmatch'][0].get('accuracy','none'),'\n')
                print("port #".ljust(space_1),"port ID".ljust(space_2),"Serves".ljust(space_3),"product".ljust(space_4),"version".ljust(space_5),"More Info".ljust(space_6),"Host Name".ljust(space_7),"Confidants".ljust(space_8),"\n")
                for i in range(len(raw[count][x]['ports'])):
                    print(list_1[i].ljust(space_1),
                        list_2[i].ljust(space_2),
                        list_3[i].ljust(space_3),
                        list_4[i].ljust(space_4),
                        list_5[i].ljust(space_5),
                        list_6[i].ljust(space_6),
                        list_7[i].ljust(space_7),
                        list_8[i].ljust(space_8))
                    file.write(list_1[i].ljust(space_1),
                        list_2[i].ljust(space_2),
                        list_3[i].ljust(space_3),
                        list_4[i].ljust(space_4),
                        list_5[i].ljust(space_5),
                        list_6[i].ljust(space_6),
                        list_7[i].ljust(space_7),
                        list_8[i].ljust(space_8))

                print("\n")
                count+=1
                file.close()
            else:i
                print(x, "has no open ports")
                file.write(x, "has no open ports")
                file.close()
        else:
            print(x, "has no open ports")
            file.write(x, "has no open ports")
            file.close()

        def print_resalts(text, ip_select):
    f = open("full_scan", "w")    
    f.write(json.dumps(text, indent=2))
    f.close()        
    return 

#The main function sequentially calls the list of functions to determine the network interfaces and the IP addresses from the associated network. Once the user defines the scan parameters, the tool scans accordingly. For more details on how each function works, please read the comments posted right above the functions. 
def main():
    network, ip = ifscan()
    subnet_ip = pick_subnet(ip, network)
    ip_list = run_nmap(subnet_ip)
    ip_select = find_ip(ip_list)
    ip_address = select_ip(ip_select,subnet_ip)
    text = run_nmap_two(ip_address)
    raw_to_human(text,ip_address)

if __name__ == '__main__':
    main()