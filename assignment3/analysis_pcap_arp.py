import dpkt
import sys
import struct

pcap_file_path = str(sys.argv[1])
pcap_file = open(pcap_file_path, 'rb')
pcap = dpkt.pcap.Reader(pcap_file)

class arp_header:
    def __init__(self, hardware_type, protocol_type, hardware_size, protocol_size, opcode, sender_MAC, sender_IP, target_MAC, target_IP):
        self.hardware_type = hardware_type
        self.protocol_type = protocol_type
        self.hardware_size = hardware_size
        self.protocol_size = protocol_size
        self.opcode = opcode
        self.sender_MAC = sender_MAC
        self.sender_IP = sender_IP
        self.target_MAC = target_MAC
        self.target_IP = target_IP

arp_request = []
arp_response = []
arp_count = 0

for ts, buf in pcap: 
    if(buf[12:14] == b'\x08\x06') :
        arp_count = arp_count + 1 # count number of ARP messages
        # ARP header element = sender MAC address, target MAC address, protocol type, etc...
        header = arp_header(buf[14:16], buf[16:18], buf[18], buf[19], buf[20:22], buf[22:28], buf[28:32], buf[32:38], buf[38:42])
        if(header.opcode == b'\x00\x01') :
            arp_request.append(header)
        if(header.opcode == b'\x00\x02') :
            arp_response.append(header)

response = arp_response[1]
for req in arp_request :
    if req.target_IP == arp_response[1].sender_IP and req.sender_IP == arp_response[1].target_IP:
        request = req

def bytes_to_ip(ip):
    return '.'.join(map(str, struct.unpack(">BBBB", ip)))

def bytes_to_mac(mac):
    return "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", mac)

# print entire ARP request and response for one ARP packet exchange
print("Number of ARP exchanges :", arp_count)
print("First ARP exchange :", )
print("ARP request :")
print("Who has", bytes_to_ip(request.sender_IP), end="")
print("? Tell", bytes_to_ip(request.target_IP))
print("Header")
print("Hardware type : ", int.from_bytes(request.hardware_type, 'big'))
print("Protocol type :", int.from_bytes(request.protocol_type, 'big'))
print("Hardware size", request.hardware_size)
print("Protocol size :", request.protocol_size)
print("Opcode :", int.from_bytes(request.opcode, 'big'))
print("Sender MAC address :",  bytes_to_mac(request.sender_MAC))
print("Sender IP address :", bytes_to_ip(request.sender_IP))
print("Target MAC address",  bytes_to_mac(request.target_MAC))
print("Target IP address", bytes_to_ip(request.target_IP))
print() 
print("ARP reply :")
print(bytes_to_ip(response.sender_IP), end="")
print(" is at", bytes_to_mac(response.target_MAC))
print("Header")
print("Hardware type : ", int.from_bytes(response.hardware_type, 'big'))
print("Protocol type :", int.from_bytes(response.protocol_type, 'big'))
print("Hardware size", response.hardware_size)
print("Protocol size :", response.protocol_size)
print("Opcode :", int.from_bytes(response.opcode, 'big'))
print("Sender MAC address :",  bytes_to_mac(response.sender_MAC))
print("Sender IP address :", bytes_to_ip(response.sender_IP))
print("Target MAC address",  bytes_to_mac(response.target_MAC))
print("Target IP address", bytes_to_ip(response.target_IP))
