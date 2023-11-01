from scapy.all import sniff, get_working_ifaces, Ether, ARP, srp, TCP, sr1
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from socket import gethostbyaddr, herror, gethostbyname_ex, gethostname
import threading
from SnifferDisplay import DisplayBoard
from utils import *

NETWORK_IFACE=''

#Get all the local IPs
all_ip_addresses = [ip for ip in gethostbyname_ex(gethostname())[2] if not ip.startswith("127.")]
IP_ADDR = all_ip_addresses[0] if all_ip_addresses else None

class Sniffer():
    """
    Sniffer class, for all network purposes.
    """
    def __init__(self, network_iface: str=None, display: DisplayBoard=None, filter=None) -> None:
        self.network_interfaces=[]
        for iface in get_working_ifaces():
            self.network_interfaces.append(iface.name)
        self.packets=[]
        self.stop=True
        if network_iface:
            self.NETWORK_IFACE=network_iface
        if display:
            self.display=display
        if filter:
            self.filter=filter
        self.index=1
        self.display=display
        self.filter=filter
        self.sniffing_has_stopped=True
    
    @staticmethod
    def _format_str(string: str):
        if len(string)>18:
            string=string[:18]
        return string
    @staticmethod
    def get_machine_ip():
        return IP_ADDR

    def set_network_iface(self, network_iface: str):
        self.NETWORK_IFACE=network_iface
    def set_display(self, display: DisplayBoard):
        self.display=display
    def set_filter(self, filter):
        self.filter=filter        

    #Sniffing function, sniffs 1 packet then adds it to the list to be disected in another function, starts only by threading.
    def _sniff(self):
        sniff(iface=self.NETWORK_IFACE, prn=self._display_packet, stop_filter=self._stop_thread, filter=self.filter)
        self.sniffing_has_stopped=True
    
    def _stop_thread(self, _):
        return self.stop
    
    def packet_display_handler(self, packet):
        src=''
        dst=''
        protocol='Unknown'
        protocol_num=0
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            protocol_num=packet[IP].proto
        elif IPv6 in packet:
            src = packet[IPv6].src
            dst = packet[IPv6].dst
            protocol_num=packet[IPv6].nh
        
        if protocol_num in protocol_table:
            protocol=protocol_table[protocol_num]
    
        return self._format_str(src), self._format_str(dst), protocol
        
    def _display_packet(self, packet):
        self.packets.append(packet)
        src, dst, protocol=self.packet_display_handler(packet)
        
        self.display.print_results(self.index, src, dst, protocol)
        
        self.index+=1
            
    #Threads the _sniff function.
    def start_sniffing_thread(self):
        self.stop=False
        self.sniffing_has_stopped=False
        self.packets=[]
        self.display.set_packetList(self.packets)
        sniff_thread=threading.Thread(target=self._sniff)
        sniff_thread.start()
    
    def stop_sniffing(self):
        self.stop=True
        self.index=1
           
    def get_network_entities(self):
        target_ip = "192.168.1.0/24"
        # Create an ARP request packet
        arp = ARP(pdst=target_ip)
        # Create an Ethernet frame to contain the ARP request
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address
        # Combine the Ethernet frame and ARP request
        packet = ether/arp
        # Send the packet and capture responses
        result = srp(packet, timeout=3, verbose=0, iface=NETWORK_IFACE)
        # Initialize a dictionary to store device information
        devices = []
        # Parse the received responses and resolve hostnames
        for received in result[0]:
            ip = received[1].psrc
            mac = received[1].hwsrc
            try:
                hostname, _, _ = gethostbyaddr(ip)
            except herror:
                hostname = "N/A"  # Hostname not found
            devices.append({'ip': ip, 'mac': mac, 'hostname': hostname})
    
        return devices
    
    def port_syn_scan(self, startport: int, endport: int, textbox: Text, ip_addr: str):
        self.stop=False
        self.sniffing_has_stopped=False
        scan_thread=threading.Thread(target=lambda: self._port_scan_thread(startport, endport, ip_addr, textbox))
        scan_thread.start()
    
    def _port_scan_thread(self, startport: int, endport: int, ip_addr, textbox: Text):
        print(IP_ADDR)
        for port in range(startport, endport):
            if not self.stop:
                packet=IP(dst=IP_ADDR)/TCP(dport=port, flags='S')
                response=sr1(packet, timeout=1, verbose=0)
                if response:
                    if TCP in response and response[TCP].flags == 'SA':
                        write_to_textbox(textbox, f'Port {port} open\n')
                    else:
                        write_to_textbox(textbox, f'Port {port} closed\n')
                else:
                    write_to_textbox(textbox, f'Port {port} filtered\n')
            else:
                break
        self.sniffing_has_stopped=True
    
    