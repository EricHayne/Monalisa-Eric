#!/usr/bin/env python3
import ifcfg
import json

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

def main():
    network, ip = ifscan()
    subnet_ip = pick_subnet(ip, network)
    print(subnet_ip)
if __name__ == '__main__':
    main()