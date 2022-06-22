# -*- coding: utf-8 -*-
# @Author: cuicp
# @Date:   2022-06-20 15:58:51
# @Last Modified by:   cuicp
# @Last Modified time: 2022-06-21 14:22:48

import pickle
import dpkt
import numpy as np
from tqdm import trange
import csv

max_byte_len = 252

attack_cat = ['Fuzzers', 'Analysis', 'Backdoor', 'DoS', 'Generic',
             'Reconnaissance', 'Shellcode', 'Worms', 'Exploits', 'benign']

def mask(p):
    p.src = b'\x00\x00\x00\x00'
    p.dst = b'\x00\x00\x00\x00'
    p.sum = 1
    p.id = 0
    p.offset = 0

    if isinstance(p.data, dpkt.tcp.TCP):
        p.data.sport = 0
        p.data.dport = 0
        p.data.seq = 0
        p.data.ack = 0
        p.data.sum = 1

    elif isinstance(p.data, dpkt.udp.UDP):
        p.data.sport = 0
        p.data.dport = 0
        p.data.sum = 1

    return p


def pkt2feature(data,app,k):
    with open('DTree_pre_train_%d_test.csv' % k, 'w', encoding='UTF-8') as f1:
        csv_writer1 = csv.writer(f1)
        csv_writer1.writerow(
            ["PacketSize", "HeaderLength", "IPProtocol", "TOS", "TTL", "TCPflags", "Flags", "Attack", "ID"])
        with open('DTree_pre_test_%d_test.csv' % k, 'w', encoding='UTF-8') as f2:
            csv_writer2 = csv.writer(f2)
            csv_writer2.writerow(
                ["PacketSize", "HeaderLength", "IPProtocol", "TOS", "TTL", "TCPflags", "Flags", "Attack", "ID"])

            flow_dict = {'train': {}, 'test': {}}
            flow_ccp = {}

            now_nump = 0
            now_numf = 0
            now_numb = 0
            m = 0
            cccccp = 0
            for p in attack_cat:
                if p != 'benign':
                    m = m + len(list(data[p].keys()))
            for p in attack_cat:
                flow_dict['train'][p] = []
                flow_dict['test'][p] = []
                flow_ccp[p] = 0
                p_keys = list(data[p].keys())
                now_num = -1

                for flow in p_keys:
                    now_num = now_num + 1
                    now_numf = now_numf + 1
                    all_pkts = []
                    pkts = data[p][flow]
                    all_pkts.extend(pkts)
                    byte = []
                    for idx in range(min(len(all_pkts), 3)):
                        if len(byte) <= max_byte_len:
                            now_nump = now_nump + 1
                            pkt = mask(all_pkts[idx][0])
                            if idx == 0:
                                raw_byte = pkt.pack()
                            else:
                                raw_byte = pkt.data.pack()
                            for x in range(len(raw_byte)):
                                now_numb = now_numb + 1
                                byte.append(int(raw_byte[x]))
                        else:
                            break
                    byte.extend([0] * (max_byte_len - len(byte)))
                    byte = byte[0:int(max_byte_len)]
                    app_now = app[p][flow]
                    for x in range(len(app_now)):
                        byte.append(int(app_now[x]))
                    # 5-fold
                    if now_num in range(k * int(len(data[p]) * 0.2), (k + 1) * int(len(data[p]) * 0.2)):
                        for idd in range(len(all_pkts)):
                            att = p
                            ip = all_pkts[idd][0]
                            id = all_pkts[idd][1]
                            if str(id) == '1':
                                print('intest')
                            if isinstance(pkt.data, dpkt.tcp.TCP):
                                flow_ccp[p] = flow_ccp[p] + 1
                                csv_writer2.writerow(
                                    [str(ip.len), str(ip.hl), str(ip.p), str(ip.tos), str(ip.ttl), str(ip.data.flags),
                                     str(int(ip.df)*2+int(ip.mf)), str(att), id])
                            else:
                                flow_ccp[p] = flow_ccp[p] + 1
                                csv_writer2.writerow(
                                    [str(ip.len), str(ip.hl), str(ip.p), str(ip.tos), str(ip.ttl), str('0'),
                                     str(int(ip.df)*2+int(ip.mf)), str(att), id])
                        flow_dict['test'][p].append((byte))
                    else:
                        for idd in range(len(all_pkts)):
                            att = p
                            ip = all_pkts[idd][0]
                            id = all_pkts[idd][1]
                            if str(id) == '1':
                                print('intrain')
                            if isinstance(pkt.data, dpkt.tcp.TCP):
                                csv_writer1.writerow(
                                    [str(ip.len), str(ip.hl), str(ip.p), str(ip.tos), str(ip.ttl), str(ip.data.flags),
                                     str(int(ip.df)*2+int(ip.mf)), str(att), id])
                            else:
                                csv_writer1.writerow(
                                    [str(ip.len), str(ip.hl), str(ip.p), str(ip.tos), str(ip.ttl), str('0'),
                                     str(int(ip.df)*2+int(ip.mf)), str(att), id])
                        flow_dict['train'][p].append((byte))
            print('now_numf: ', now_numf)
            print('now_nump: ', now_nump)
            print('now_numb: ', now_numb)
            print(flow_ccp)
            print(cccccp)
            return flow_dict


def load_epoch_data(flow_dict, train='train'):
    flow_dict = flow_dict[train]
    x, label = [], []

    for p in attack_cat:
        pkts = flow_dict[p]
        for byte in pkts:
            x.append(byte)
            label.append(attack_cat.index(p))

    return np.array(x), np.array(label)[:, np.newaxis]


if __name__ == '__main__':

    with open('pro_flows_1_28.pkl', 'rb') as f:
        data = pickle.load(f)
    with open('pro_flows_1_28_app.pkl', 'rb') as f:
        app = pickle.load(f)

    for i in trange(5, mininterval=5, \
                    desc='  - (Building fold dataset)   ', leave=False):
        flow_dict = pkt2feature(data,app,i)
        with open('pro_flows_10_0.5_%d_noip_fold.pkl' % i, 'wb') as f:
            pickle.dump(flow_dict, f)
