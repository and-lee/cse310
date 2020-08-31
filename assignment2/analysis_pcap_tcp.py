import dpkt
import sys
from functools import reduce

pcap_file_path = str(sys.argv[1])
pcap_file = open(pcap_file_path, 'rb')
pcap = dpkt.pcap.Reader(pcap_file)
sender = str(sys.argv[2])
receiver = str(sys.argv[3])

def ip_to_bytes(ip: str):
    return reduce(lambda x, y:x+y, list(map(lambda x: int(x).to_bytes(1, 'big'), list(ip.split('.')))))

sender = ip_to_bytes(sender)
receiver = ip_to_bytes(receiver)

class packet:
    def __init__(self, seq, ack, r_win, byte_size, sport, dport):
        self.seq = seq
        self.ack = ack
        self.r_win = r_win
        self.byte_size = byte_size
        self.sport = sport
        self.dport = dport

class tcp_flow:
    def __init__(self, sport, acks, rec, scaling_factor, time, total_bytes, retransmissions, seq, receiver_ack, count, triple, congestion_windows, p_flight):
        self.sport = sport
        self.acks = acks
        self.rec = rec
        self.scaling_factor = scaling_factor
        self.time = time
        self.total_bytes = total_bytes
        self.retransmissions = retransmissions
        self.seq = seq
        self.receiver_ack = receiver_ack
        self.count = count
        self.triple = triple
        self.congestion_windows = congestion_windows
        self.p_flight = p_flight

num = 2 # first n transmissions to print
tcp_flows = []
for ts, buf in pcap:
    ethernet = dpkt.ethernet.Ethernet(buf)
    ip = ethernet.data
    source_ip = ip.src
    #dest_ip = ip.dst
    tcp = ip.data

    if(source_ip == sender):
        # TCP flows initiated from the sender
        if (((tcp.flags & 0x02) !=0) and (source_ip == sender)): # SYN
            options = dpkt.tcp.parse_opts(tcp.opts)
            for o in options :
                if o[0] == 3 :
                    scaling_factor = 1 << int.from_bytes(o[1],"big")
            tcp_flows.append(tcp_flow(tcp.sport, [], [], scaling_factor, ts, 0, 0, tcp.seq, None, 0, 0, [0], 0))

        # each TCP flow
        for i in tcp_flows:
            if(i.sport == tcp.sport):
                # total number of bytes per packet
                # header length + data length
                num_bytes = tcp.__hdr_len__ + len(tcp.data)
                
                if ((tcp.flags & 0x10) !=0): # ACK
                    i.congestion_windows[-1] += 1 # cwd = # of packets sent without acknowledgement

                    if((tcp.flags & 0x08) ==0): # exclude PUSH, ACK
                        packy = packet(tcp.seq, tcp.ack, tcp.win*i.scaling_factor, num_bytes, tcp.sport, tcp.dport)
                        i.acks.append(packy)
                    
                if ((tcp.flags & 0x01) == 1): # FIN
                    i.time = ts - i.time

                if(tcp.seq < i.seq): # ack out of order = retransmission
                    i.retransmissions += 1
                else:
                    i.seq = tcp.seq
                
                if(i.count >= 2): # triple duplicate ack
                    if(i.receiver_ack == tcp.seq): # sender sent
                        i.triple += 1
                
                i.total_bytes = i.total_bytes + num_bytes
    
    if(source_ip == receiver):
        for i in tcp_flows:
            if(tcp.dport == i.sport):
                if (((tcp.flags & 0x10) !=0) and ((tcp.flags & 0x02) ==0)): # ACK, exclude SYN ACK
                    
                    if(i.p_flight==0):
                        i.p_flight = i.congestion_windows[-1] # packets in flight = cwnd
                        i.congestion_windows.append(0) # new cwnd
                    
                    i.p_flight -= 1

                    packy = packet(tcp.seq, tcp.ack, tcp.win*i.scaling_factor, num_bytes, tcp.sport, tcp.dport)
                    i.rec.append(packy)

                    if(i.receiver_ack == tcp.ack):
                        i.count += 1
                    else:
                        i.receiver_ack = tcp.ack
                        i.count = 0


def flow_sender_throughput(flow: tcp_flow):
    return flow.total_bytes/flow.time
    #return reduce(lambda x, y:x+y, list(map(lambda p:p.byte_size, flow.acks)))/flow.time

# number of TCP flows initiated from the sender
print("TCP flows:", len(tcp_flows))

j=1
for i in tcp_flows:
    print("Flow %d: port: %d" %(j, i.sport))
    j+=1
    for x in range(num): # first 2 packets after TCP connection is setup
        print("Packet %d: Sequence number: %d | Ack number: %d | Receive Window size: %d " %((x+1), i.acks[x].seq, i.acks[x].ack, i.acks[x].r_win))
        print("Ack %d: Sequence number: %d | Ack number: %d | Receive Window size: %d " %((x+1), i.rec[x].seq, i.rec[x].ack, i.rec[x].r_win))
    print("Sender throughput: %f bytes/sec" %(flow_sender_throughput(i)))
    print("First 5 Congestion window sizes:", i.congestion_windows[0:5])
    print("Retransmissions: triple duplicate ack: %d | timeout: %d" %(i.triple, i.retransmissions-i.triple))
    print()
