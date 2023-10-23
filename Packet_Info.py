from scapy.all import packet, IP, IPv6, Ether, TCP, UDP, DNS, ICMP
from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest

class Packet_Info():
    def __init__(self, packet: packet) -> None:
        self.packet=packet
        self.layer_index={
            'DATA_LINK': 0,
            'NETWORK': 1,
            'ICMP': 2,
            'TRANSPORT': 3,
            'APPLICATION': 4
        }
        self.layer_info=[self.data_link_layer_info(), self.network_layer_info(), self.ICMP_info(), self.transport_layer_info(), self.application_layer_info()]
        self.packet.show()
    
    def data_link_layer_info(self):
        if Ether in self.packet:
            layer=self.packet[Ether]
            src=layer.src
            dst=layer.dst
            version=layer.type
            return f'Src: {src}\nDst: {dst}\nType: {version}'
        return None
    
    def network_layer_info(self):
        if IP in self.packet:
            layer=self.packet[IP]
            src= layer.src
            dst= layer.dst
            version= layer.version
            header_len= layer.ihl
            tos= layer.tos
            length= layer.len
            ID= layer.id
            flags= layer.flags
            ttl= layer.ttl
            protocol= layer.proto
            if not protocol:
                protocol='Unknown'
            checksum= layer.chksum
            
            return f'Src: {src}\nDst: {dst}\nVersion: {version}\nHeader length: {header_len}\nType of service: {tos}\nLength: {length}\nID: {ID}\nFlags: {flags}\nTTL: {ttl}\nprotocol: {protocol}\nChecksum: {checksum}'
        elif IPv6 in self.packet:
            layer=self.packet[IPv6]
            src=layer.src
            dst=layer.dst
            version=layer.version
            tc=layer.tc
            fl=layer.fl
            pl=layer.plen
            protocol=layer.nh
            if not protocol:
                protocol='Unknown'
            ttl=layer.hlim
            
            return f'Src: {src}\nDst: {dst}\nVersion: {version}\nTraffic class: {tc}\nFlow level: {fl}\nPayload length: {pl}\nProtocol: {protocol}\nTTL: {ttl}'
        return None
    
    def transport_layer_info(self):
        if TCP in self.packet:
            layer=self.packet[TCP]
            sport=layer.sport
            dport=layer.dport
            seq=layer.seq
            ack=layer.ack
            dataofs=layer.dataofs
            reserved=layer.reserved
            flags=layer.flags
            window=layer.window
            urgptr=layer.urgptr
            options=layer.options
            
            return f'Src port: {sport}\nDst port: {dport}\nSequance number: {seq}\nAck: {ack}\n Data offset: {dataofs}\nReserved: {reserved}\nFlags: {flags}\nWindow: {window}\nUrgent pointer: {urgptr}\nOptions: {options}'
            
        elif UDP in self.packet:
            layer=self.packet[UDP]
            sport= layer.sport
            dport= layer.dport
            length= layer.len
            checksum= layer.chksum
            
            return f'Src port: {sport}\nDst port: {dport}\nLength: {length}\nChecksum: {checksum}'
        
        return None    

    def application_layer_info(self):
        if DNS in self.packet:
            dns_layer = self.packet[DNS]
            qname = dns_layer.qd.qname.decode('utf-8')
            return f'DNS Query: {qname}'
        return None
    
    def ICMP_info(self):
        if ICMP in self.packet:
            icmp_layer = self.packet[ICMP]
            icmp_type = icmp_layer.type
            icmp_code = icmp_layer.code
            
            if icmp_type == 128:
                return 'ICMP Echo Request'
            elif icmp_type == 129:
                return 'ICMP Echo Reply'
            else:
                return f'ICMP Type: {icmp_type}\nICMP Code: {icmp_code}'
        elif IPv6 in self.packet:
            if ICMPv6EchoRequest in self.packet:
                return 'ICMPv6 Echo Request'
            elif ICMPv6EchoReply in self.packet:
                return 'ICMPv6 Echo Reply'
        return None





