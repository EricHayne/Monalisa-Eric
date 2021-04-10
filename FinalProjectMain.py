#!/usr/bin/env python3
import sys
import nmap3
import os
import ifconfig

nmap = nmap3.Nmap() 

def RunNmap1(PassInSubnet):
    #this is first run throw of nmap to get all IP on the submask
    return IpAdressList
def PresentIPs(IpAddressList):
    #alows the user to choes wich IP/IPS they wish to get more information on.
def RunNmap2(PassInIP):
    #NMAP port and serves scan and OS
    return AllPortInformation
def PresentFinalResalts(AllPortInformation):
    #formats the information to be presented to screan and saved to file in user frindly format
    return FormatedResalts
def RunIfconfig():
    #runs IFCONFIG as when program starts
    return RawIFData
def SortIfconfig(RawIFData):
    #sorts the information from the IFconfig scan
    return SumnetList
def PresentOptions(SumnetList):
    #presents the finding of IF scan and asks wich ssubnet to address (1. eth 0 IP:xxx.xxx.xxx.xxx ) press 1 gives this IP, last option is alwas enter a manual IP address
    return PassInSubnet
def main():
    
    


if __name__ == '__main__':    
    main()