import dpkt
from datetime import datetime
from prettytable import PrettyTable


class Header:
    def __init__(self, source_port, dest_port, seq_number, ack_number, fin, syn, ack, timestamp, packet_size, payload):
        self.source_port = source_port
        self.dest_port = dest_port
        self.seq_number = seq_number
        self.ack_number = ack_number
        self.fin = fin
        self.syn = syn
        self.ack = ack
        self.timestamp = timestamp
        self.packet_size = packet_size
        self.payload = payload


def bit_set(n, k):
    if (1 << (k - 1)) & n:
        return 1
    else:
        return 0


def parse_header(filename):
    try:
        packets = []
        stream = open(filename, 'rb')
        pcap_list = list(dpkt.pcap.Reader(stream))
        for ts, pcap in pcap_list:
            packet_size = len(pcap)
            tcp_h = pcap[34:]
            source_port = int.from_bytes(tcp_h[0:2], 'big')
            dest_port = int.from_bytes(tcp_h[2:4], 'big')
            seq_number = int.from_bytes(tcp_h[4:8], 'big')
            ack_number = int.from_bytes(tcp_h[8:12], 'big')
            flags = int.from_bytes(tcp_h[13:14], 'big')
            fin = bit_set(flags, 1)
            syn = bit_set(flags, 2)
            ack = bit_set(flags, 4)
            header_len = 4 * (int.from_bytes(tcp_h[12:13], 'big') >> 4)
            payload = tcp_h[header_len:]
            header = Header(source_port, dest_port, seq_number, ack_number, fin, syn, ack, ts, packet_size, payload)
            packets.append(header)
        return packets
    except:
        return []


# part C.1
def segregate_req_resp(packets):
    requests = []
    seq_number_dict = {}
    for p in sorted(packets, key=lambda x: x.timestamp):
        if "GET" in str(p.payload):
            requests.append(p)
        seq_number_dict[p.seq_number] = p
    pairs = []
    for req in requests:
        next_seq = req.ack_number
        next_pack = seq_number_dict.get(next_seq, None)
        responses = []
        while next_pack is not None:
            res = {'src_port': next_pack.source_port, 'dest_port': next_pack.dest_port,
                   'ack_num': next_pack.ack_number, 'seq_num': next_pack.seq_number}
            responses.append(res)
            next_seq += len(next_pack.payload)
            next_pack = seq_number_dict.get(next_seq, None)
            if not next_pack or next_pack.fin == 1:
                break
        r = {'src_port': req.source_port, 'dest_port': req.dest_port,
             'ack_num': req.ack_number, 'seq_num': req.seq_number}
        pairs.append({'Request': r, 'Response': responses})
    return pairs


def analyse_http_protocol(packets, port):
    tot_raw_bytes = 0
    s = set()
    tot_packs = 0
    packets = sorted(packets, key=lambda x: x.timestamp)
    for packet in packets:
        if int(port) == packet.source_port:
            tot_packs += 1
            tot_raw_bytes += len(packet.payload)
            s.add(packet.dest_port)
    time = (datetime.fromtimestamp(packets[-1].timestamp) - datetime.fromtimestamp(packets[0].timestamp)) \
        .total_seconds()
    return {'num_conn': len(s), 'raw_bytes': tot_raw_bytes, 'load_time': time, 'num_packets': tot_packs, 'port': port}


def main():
    http_dict = {}
    packets = parse_header('http_1080.pcap')
    http_dict['1080'] = packets
    # get req and resp
    pairs = segregate_req_resp(packets)
    print(" ================ Part C.1 ================ ")
    for p in pairs:
        req = p['Request']
        print("===========================================================")
        print("Request (Source Port: {}, Destination Port: {}, Acknowledgment Number: {}, Sequence Number: {})"
              .format(req['src_port'], req['dest_port'], req['ack_num'], req['seq_num']))
        print()
        for res in p['Response']:
            print("Response (Source Port: {}, Destination Port: {}, Acknowledgment Number: {}, Sequence Number: {})"
                  .format(res['src_port'], res['dest_port'], res['ack_num'], res['seq_num']))
        print("===========================================================")
        print()

    pack_81 = parse_header('http_1081_3.pcap')
    http_dict['1081'] = pack_81
    pack_82 = parse_header('http_1082 2.pcap')
    http_dict['1082'] = pack_82

    # analyse packet stats for each port
    packet_info = []
    for key, val in http_dict.items():
        packet_info.append(analyse_http_protocol(val, key))

    print(" ================ Part C.2 ================ ")
    protocols = ['HTTP/1.0', 'HTTP/1.1', 'HTTP/2.0']
    packet_info.sort(key=lambda x: x['num_conn'], reverse=True)
    for i, p in enumerate(packet_info):
        p['protocol'] = protocols[i]
        print("Number of Connections = {} on port {} ==> {} protocol".format(p['num_conn'], p['port'], p['protocol']))

    print()
    print(" ================ Part C.3 ================ ")
    t = PrettyTable(['Protocol', 'Connections', 'Num_Packets', 'Raw_Bytes_Sent', 'Page_Load_Time'])
    for i, p in enumerate(packet_info):
        t.add_row([p['protocol'], p['num_conn'], p['num_packets'], p['raw_bytes'], p['load_time']])
    print(t)


if __name__ == '__main__':
    main()
