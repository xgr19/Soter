#Used for preliminary statistics of the number of each stream packet
import numpy as np
import dpkt
import csv
import json
import random
import pickle

attack_cat = ['Fuzzers', 'Analysis', 'Backdoor', 'DoS', 'Generic',
             'Reconnaissance', 'Shellcode', 'Worms', 'Exploits', 'benign']

def gen_flows(pcap, dic):

    if pcap.datalink() != dpkt.pcap.DLT_EN10MB:
        print('unknow data link!')
        return

    total_num = 0
    for num, buff in pcap:
        eth = dpkt.ethernet.Ethernet(buff)
        total_num += 1
        if total_num % 500000 == 0:
            print('The %dth pkt!' % total_num)

        if isinstance(eth.data, dpkt.ip.IP) and (
            isinstance(eth.data.data, dpkt.udp.UDP)
            or isinstance(eth.data.data, dpkt.tcp.TCP)):
            ip = eth.data
            transf_data = ip.data
            if not len(transf_data.data):
                continue
            key = '.'.join(map(str, map(int, ip.src))) + \
                  '.' + '.'.join(map(str, map(int, ip.dst))) + \
                  '.' + '.'.join(map(str, [ip.p, ip.data.sport, ip.data.dport]))
            if key not in dic:
                dic[key] = 1
            elif dic[key] < 3:
                dic[key] = dic[key] + 1
    return dic,a,b


if __name__ == '__main__':
    dic = {}
    for i in range(1, 28):
        pcap = dpkt.pcap.Reader(open('/data/UNSW-NB15/pcaps/17-2-2015/out/out-%d.pcap' % i, 'rb'))
        dic,a,b = gen_flows(pcap, dic)
    with open('pkt_num.pkl', 'wb') as f:
        pickle.dump(dic, f)
