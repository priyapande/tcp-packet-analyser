import dpkt.pcap
import collections
from datetime import datetime
import math


class TcpHeader:
    def __init__(self, source_port, dest_port, seq_number, ack_number, fin, syn, ack, win_size, mss, timestamp,
                 packet_size, win_scale):
        self.source_port = source_port
        self.dest_port = dest_port
        self.seq_number = seq_number
        self.ack_number = ack_number
        self.fin = fin
        self.syn = syn
        self.ack = ack
        self.win_size = win_size
        self.mss = mss
        self.timestamp = timestamp
        self.packet_size = packet_size
        self.win_scale = win_scale

    def __str__(self):
        return str(self.source_port) + " " + str(self.dest_port) + " " + str(self.seq_number) \
               + " " + str(self.ack_number) + " " + str(self.fin) + " " + str(self.syn) + " " + str(self.ack) + " " \
               + str(self.win_size) + " " + str(self.mss) + " " + str(self.timestamp) + " " + str(self.win_scale) \
               + " " + str(self.packet_size)


def bit_set(n, k):
    # left shift 1 by k-1 to get 1 as at correct position to and with the kth position in n
    if (1 << (k - 1)) & n:
        return 1
    else:
        return 0


def parse_header():
    # create a dict that stores all flows along with list of packets
    tcp_flow = collections.defaultdict(list)
    stream = open('assignment2.pcap', 'rb')
    pcap_list = list(dpkt.pcap.Reader(stream))
    # parse the header using the bytes according to the TCP header format in slides
    for ts, pcap in pcap_list:
        packet_size = len(pcap)
        # remove the ethernet and ip header from processing(14 & 20 bytes respectively)
        tcp_h = pcap[34:]
        source_port = int.from_bytes(tcp_h[0:2], 'big')
        dest_port = int.from_bytes(tcp_h[2:4], 'big')
        seq_number = int.from_bytes(tcp_h[4:8], 'big')
        ack_number = int.from_bytes(tcp_h[8:12], 'big')
        flags = int.from_bytes(tcp_h[13:14], 'big')
        fin = bit_set(flags, 1)
        syn = bit_set(flags, 2)
        ack = bit_set(flags, 4)
        win_size = int.from_bytes(tcp_h[14:16], 'big')
        mss = int.from_bytes(tcp_h[22:24], 'big')
        win_scale = 2 ** int.from_bytes(tcp_h[39:40], 'big')
        head_obj = TcpHeader(source_port, dest_port, seq_number, ack_number, fin, syn, ack, win_size, mss, ts,
                             packet_size, win_scale)
        # store in our dict of flows with key as source and dest uniquely
        temp = [source_port, dest_port]
        temp.sort()
        key = str(temp[1]) + "_" + str(temp[0])
        tcp_flow[key].append(head_obj)
    return tcp_flow


# part A.2.a
def print_first_n_transactions(tcp_flow, n):
    for key, flows in tcp_flow.items():
        temp = key.split("_")
        sender = collections.defaultdict(list)
        receiver = collections.defaultdict(list)
        print("===========================================================")
        print("Transaction for flow initiated from port {}".format(temp[0]))
        mul = 1
        # traverse on the sorted flow acc to timestamp and get the packets from sen-rec and rec-sen in respective list
        for flow in sorted(flows, key=lambda x: x.timestamp):
            # get window scaling parameter agreed while syn was sent
            if flow.syn == 1 and flow.ack == 0 and mul == 1:
                mul = flow.win_scale
                continue
            if flow.fin == 1 or flow.syn == 1:
                continue
            if flow.source_port > flow.dest_port:
                sender[flow.seq_number].append(flow)
            else:
                receiver[flow.ack_number].append(flow)
            if len(receiver) == n:
                break

        t = 0
        # the sorted pairing of sender and receiver transaction
        for seq, rec in zip(sender.values(), receiver.values()):
            print("Sender Transaction {}".format(t + 1))
            for tran in sorted(seq, key=lambda x: x.timestamp):
                win = tran.win_size * mul
                print("SEQ NUMBER = {}, ACK NUMBER = {}, RECV WINDOW SIZE = {} bytes".format(tran.seq_number,
                                                                                             tran.ack_number,
                                                                                             win))
            print("Corresponding Receiver Transaction {}".format(t + 1))
            for tran in sorted(rec, key=lambda x: x.timestamp):
                win = tran.win_size * mul
                print("SEQ NUMBER = {}, ACK NUMBER = {}, RECV WINDOW SIZE = {} bytes".format(tran.seq_number,
                                                                                             tran.ack_number,
                                                                                             win))
            t += 1
            # break out of loop after printing n transactions
            if t == n:
                break
        print("===========================================================")
        print()


# part A.2.b
# throughput = (total bytes of packets sent from sender to receiver) / (total time taken)
# any packet from sender be it for establishing a connection, exchanging data or
# closing connection is considered in total bytes
def calculate_throughput(tcp_flow):
    ans = []
    for key, flows in tcp_flow.items():
        total_bytes = 0
        seq_dict = {}
        flows = sorted(flows, key=lambda x: x.timestamp)
        port = key.split('_')[0]
        lost = 0
        for flow in flows:
            if flow.source_port > flow.dest_port:
                if flow.seq_number in seq_dict:
                    lost += 1
                seq_dict[flow.seq_number] = flow.packet_size
                total_bytes += flow.packet_size
        total_time = (datetime.fromtimestamp(flows[-1].timestamp) - datetime.fromtimestamp(flows[0].timestamp)) \
            .total_seconds()
        throughput = (total_bytes * 8 / total_time) * (10 ** -6)
        ans.append({'unique_bytes': total_bytes, 'port': port, 'throughput': throughput, 'key': key, 'num_lost': lost})
    for val in ans:
        print("Throughput for Source Port {} is {} Mbps".format(val['port'], val['throughput']))
    return ans


# part A.2.c
def loss_rate(ans, tcp_flow):
    for l in ans:
        flows = tcp_flow[l['key']]
        tot_b = 0
        for f in flows:
            if f.source_port > f.dest_port:
                tot_b += 1
        loss = l['num_lost'] / tot_b
        l['loss_rate'] = loss
        print("Loss for Sender with Port {} is {}".format(l['port'], l['loss_rate']))


# part A.2.d
def avg_rtt(tcp_flow, unique_packets):
    ans = []
    # loop to calculate avg RTT of each flow
    for key, flows in tcp_flow.items():
        sender_tran = collections.OrderedDict()
        receiver_tran = collections.OrderedDict()
        mss = None
        flows = sorted(flows, key=lambda x: x.timestamp)
        port = key.split('_')[0]
        # get the last timestamp of packet sent and first acknowledgment received
        for flow in flows:
            if flow.source_port > flow.dest_port:
                if mss is None:
                    mss = flow.mss
                sender_tran[flow.seq_number] = flow.timestamp
            else:
                if flow.ack_number not in receiver_tran:
                    receiver_tran[flow.ack_number] = flow.timestamp
        avg_time = 0
        sen_keys = list(sender_tran.keys())
        # get pair for sender-rec ack and calculate time
        for k, rec in receiver_tran.items():
            index = sen_keys.index(k)
            sen = sender_tran[sen_keys[index - 1]]
            avg_time += ((datetime.fromtimestamp(rec) - datetime.fromtimestamp(sen)).total_seconds())
        ans.append({'port': port, 'key': key, 'avg_rtt': avg_time / len(receiver_tran), 'mss': mss})

    for pack, rtt in zip(unique_packets, ans):
        t_throughput = (math.sqrt(1.5) * rtt['mss'] * 8) / (rtt['avg_rtt'] * math.sqrt(pack['loss_rate']) * 1000000)
        rtt['t_throughput'] = t_throughput
        print("Sender Port {} avg RTT is {} secs. For this flow theoretical throughput is {} Mbps "
              "vs estimated throughput {} Mbps"
              .format(pack['port'], rtt['avg_rtt'], t_throughput, pack['throughput']))
    return ans


def main():
    # parse header and get unique list of flows in the pcap as a dictionary
    tcp_flow = parse_header()
    print("========================================")
    print("Part A: 1. Unique TCP Flows initiated from sender {}".format(len(tcp_flow)))
    print("========================================")
    print()
    print("Part A: 2.a ")
    print_first_n_transactions(tcp_flow, 2)
    print("Part A: 2.b ")
    print("========================================")
    unique_packets = calculate_throughput(tcp_flow)
    print("========================================")
    print()
    print("Part A: 2.c")
    print("========================================")
    loss_rate(unique_packets, tcp_flow)
    print("========================================")
    print()
    print("Part A: 2.d")
    print("========================================")
    avg_rtt(tcp_flow, unique_packets)
    print("========================================")
    print()


if __name__ == '__main__':
    main()
