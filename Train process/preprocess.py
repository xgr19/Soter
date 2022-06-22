# -*- coding: utf-8 -*-
# @Author: cuicp
# @Date:   2022-06-20 15:58:51
# @Last Modified by:   cuicp
# @Last Modified time: 2022-06-21 14:22:48

import dpkt
import csv
import json
import pickle
import math

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

def gen_flows(pcap,flows,dic1,dic2,dic3,dic4,dic5,dic6,dic7,dic8,csv_writer,id,prenum,flows_app,app,app1,app3,appt1,appn,appt3,appt4,pktn):

    if pcap.datalink() != dpkt.pcap.DLT_EN10MB:
        print('unknow data link!')
        return

    pktnum = 0
    for num, buff in pcap:

        eth = dpkt.ethernet.Ethernet(buff)
        pktnum += 1
        if pktnum % 500000 == 0:
            print('The %dth pkt!' % pktnum)
        # break

        if isinstance(eth.data, dpkt.ip.IP) and (
            isinstance(eth.data.data, dpkt.udp.UDP)
            or isinstance(eth.data.data, dpkt.tcp.TCP)):
            # tcp or udp packet
            ip = eth.data
            transf_data = ip.data
            # no payload
            if not len(transf_data.data):
                continue
            key = '.'.join(map(str, map(int, ip.src))) + \
                  '.' + '.'.join(map(str, map(int, ip.dst))) + \
                  '.' + '.'.join(map(str, [ip.p, ip.data.sport, ip.data.dport]))
            if key in dic1:
                id = id + 1
                now_att = dic2[key]
                index = attack_cat.index(now_att)
                if key not in appn:
                    appn[key] = 1
                    a = int(ip.len)
                    app[key] = [a]
                    app[key].append(int(a/3))
                    app[key].append(int(0))
                    app[key].append(a)
                    app[key].append(int(0))
                    app[key].append(int(0))
                    if pktn[key] == 1:
                        app[key][2] = int(math.sqrt(((app[key][3]-app[key][1])*(app[key][3]-app[key][1])+(app[key][4]-app[key][1])*(app[key][4]-app[key][1])+(app[key][5]-app[key][1])*(app[key][5]-app[key][1]))/2))/10
                        if app[key][2] > 255:
                            app[key][2] = 255
                        app[key][0] = app[key][0]/10
                        if app[key][0] > 255:
                            app[key][0] = 255
                        app[key][1] = app[key][1]/10
                        if app[key][1] > 255:
                            app[key][1] = 255
                        app[key][3] = app[key][3]/10
                        if app[key][3] > 255:
                            app[key][3] = 255
                elif appn[key] == 1:
                    # current pkt num
                    appn[key] = appn[key] + 1
                    a = int(ip.len)
                    app[key][0] = app[key][0] + a
                    app[key][1] = int(app[key][0]/3)
                    app[key][4] = a
                    if pktn[key] == 2:
                        app[key][2] = int(math.sqrt(((app[key][3]-app[key][1])*(app[key][3]-app[key][1])+(app[key][4]-app[key][1])*(app[key][4]-app[key][1])+(app[key][5]-app[key][1])*(app[key][5]-app[key][1]))/2))/10
                        if app[key][2] > 255:
                            app[key][2] = 255
                        app[key][0] = app[key][0]/10
                        if app[key][0] > 255:
                            app[key][0] = 255
                        app[key][1] = app[key][1]/10
                        if app[key][1] > 255:
                            app[key][1] = 255
                        app[key][3] = app[key][3] / 10
                        if app[key][3] > 255:
                            app[key][3] = 255
                        app[key][4] = app[key][4]/10
                        if app[key][4] > 255:
                            app[key][4] = 255
                elif appn[key] == 2:
                    appn[key] = appn[key] + 1
                    a = int(ip.len)
                    app[key][0] = app[key][0] + a
                    app[key][1] = int(app[key][0]/3)
                    app[key][5] = a
                    if pktn[key] == 3:
                        app[key][2] = int(math.sqrt(((app[key][3]-app[key][1])*(app[key][3]-app[key][1])+(app[key][4]-app[key][1])*(app[key][4]-app[key][1])+(app[key][5]-app[key][1])*(app[key][5]-app[key][1]))/2))/10
                        if app[key][2] > 255:
                            app[key][2] = 255
                        app[key][0] = app[key][0]/10
                        if app[key][0] > 255:
                            app[key][0] = 255
                        app[key][1] = app[key][1]/10
                        if app[key][1] > 255:
                            app[key][1] = 255
                        app[key][3] = app[key][3] / 10
                        if app[key][3] > 255:
                            app[key][3] = 255
                        app[key][4] = app[key][4] / 10
                        if app[key][4] > 255:
                            app[key][4] = 255
                        app[key][5] = app[key][5]/10
                        if app[key][5] > 255:
                            app[key][5] = 255
                flows_app[index][key] = app[key]
                if key not in flows[index]:
                    flows[index][key] = [(ip, id)]
                elif len(flows[index][key]) < 20:
                    flows[index][key].append((ip, id))
                if key not in prenum:
                    prenum[key] = num
                    now_time = float(0)
                else:
                    now_time = num - prenum[key]
                    prenum[key] = num
                byte = []
                if isinstance(ip.data, dpkt.tcp.TCP):
                    t = str(ip.data.sport)
                    for _ in range(5 - len(t)):
                        byte.append(0)
                    for i in range(len(t)):
                        byte.append(int(t[i]))
                    t = str(ip.data.dport)
                    for _ in range(5 - len(t)):
                        byte.append(0)
                    for i in range(len(t)):
                        byte.append(int(t[i]))
                    t = str(ip.len - 20)
                    for _ in range(5 - len(t)):
                        byte.append(0)
                    for i in range(len(t)):
                        byte.append(int(t[i]))
                    t = str(ip.data.win)
                    for _ in range(5 - len(t)):
                        byte.append(0)
                    for i in range(len(t)):
                        byte.append(int(t[i]))
                    t = str(now_time)
                    for i in range(min(len(t), 11)):
                        if t[i] != '.':
                            if t[i] == '-':
                                a = 0
                            byte.append(int(t[i]))
                    byte.extend([0] * (11 - len(t)))
                elif isinstance(ip.data, dpkt.udp.UDP):
                    t = str(ip.data.sport)
                    for _ in range(5 - len(t)):
                        byte.append(0)
                    for i in range(len(t)):
                        byte.append(int(t[i]))
                    t = str(ip.data.dport)
                    for _ in range(5 - len(t)):
                        byte.append(0)
                    for i in range(len(t)):
                        byte.append(int(t[i]))
                    t = str(ip.data.ulen)
                    for _ in range(5 - len(t)):
                        byte.append(0)
                    for i in range(len(t)):
                        byte.append(int(t[i]))
                    for i in range(5):
                        byte.append(0)
                    t = str(now_time)
                    for i in range(min(len(t), 11)):
                        if t[i] != '.':
                            byte.append(int(t[i]))
                    byte.extend([0] * (11 - len(t)))
                ip = mask(ip)
                now_att = dic1[key]
                ratt = dic2[key]
                ipbyte = []
                dabyte = []
                rawbyte1 = ip.pack()
                rawbyte2 = ip.data.pack()
                for x in range(len(rawbyte1)):
                    ipbyte.append(int(rawbyte1[x]))
                for x in range(len(rawbyte2)):
                    dabyte.append(int(rawbyte2[x]))
                if isinstance(eth.data.data, dpkt.tcp.TCP):
                    csv_writer.writerow([str(ip.len),str(ip.hl),str(ip.p),str(ip.tos),str(ip.ttl),str(ip.data.flags),str(int(ip.df)*2+int(ip.mf)),str(now_att),id])
                    dic3[id] = ipbyte
                    dic4[id] = dabyte
                    dic5[id] = key
                    dic6[id] = ratt
                    dic7[id] = byte
                else:
                    csv_writer.writerow([str(ip.len),str(ip.hl),str(ip.p),str(ip.tos),str(ip.ttl),str('0'),str(int(ip.df)*2+int(ip.mf)),str(now_att),id])
                    dic3[id] = ipbyte
                    dic4[id] = dabyte
                    dic5[id] = key
                    dic6[id] = ratt
                    dic7[id] = byte

    return app,app1,app3,appt1,appn,appt3,appt4,dic3,dic4,dic5,dic6,dic7,dic8,flows,id,flows_app

def closure(flows):
    flow_dict = {}
    for name in attack_cat:
        index = attack_cat.index(name)
        flow_dict[name] = flows[index]
        print('============================')
        print('Generate flows for %s' % name)
        print('Total flows: ', len(flows[index]))
        cnt = 0
        for k, v in flows[index].items():
            cnt += len(v)
        print('Total pkts: ', cnt)

    with open('pro_flows_1_28.pkl', 'wb') as f:
        pickle.dump(flow_dict, f)

def closure_app(flows_app):
    flow_dict = {}
    for name in attack_cat:
        index = attack_cat.index(name)
        flow_dict[name] = flows_app[index]
        print('============================')
        print('Generate flows for %s' % name)
        # 流数量
        print('Total flows: ', len(flows[index]))

    with open('pro_flows_1_28_app.pkl', 'wb') as f:
        pickle.dump(flow_dict, f)

if __name__ == '__main__':
    dic1 = {}
    dic2 = {}
    dic3 = {}
    dic4 = {}
    dic5 = {}
    dic6 = {}
    dic7 = {}
    dic8 = {}
    appn = {}
    app1 = {}
    app3 = {}
    appt1 = {}
    app = {}
    appt3 = {}
    appt4 = {}
    dic_flow = {}
    prenum = {}
    for i in range(1,5) :
        with open('UNSW_NB15_CSV_Files/UNSW-NB15_%d.csv' %i,'r',encoding = 'UTF-8') as f:
            reader = csv.reader(f)
            for row in reader:
                if row[4] == 'udp' :
                    proto = '17'
                elif row[4] == 'tcp' :
                    proto = '6'
                else :
                    continue
                srcip = row[0]
                sport = row[1]
                dstip = row[2]
                dport = row[3]
                attack = row[47].strip()
                key = srcip + '.' + dstip + \
                      '.' + proto + '.' + sport + '.'+ dport

                if attack == '' :
                    dic1[key] = 'benign'
                    dic2[key] = 'benign'
                else :
                    dic1[key] = 'attack'
                    dic2[key] = attack
    flows = [{} for _ in range(len(attack_cat))]
    flows_app = [{} for _ in range(len(attack_cat))]
    with open('DTree_pre.csv', 'w', encoding='UTF-8') as f:
        id = 0
        csv_writer = csv.writer(f)
        csv_writer.writerow(["PacketSize", "HeaderLength", "IPProtocol", "TOS", "TTL", "TCPflags", "Flags", "Attack", "ID"])
        # pcap = dpkt.pcap.Reader(open('./out-0.pcap', 'rb'))
        with open('pkt_num.pkl', 'rb') as f:
            pktn = pickle.load(f)
            for i in range(1,28):
                pcap = dpkt.pcap.Reader(open('/data/UNSW-NB15/pcaps/17-2-2015/out/out-%d.pcap' % i, 'rb'))
                app, app1, app3, appt1, appn, appt3, appt4, dic3, dic4, dic5, dic6, dic7, dic8, flows, id, flows_app = gen_flows(pcap, flows, dic1, dic2,
                                                                                 dic3, dic4, dic5, dic6, dic7, dic8, csv_writer, id, prenum, dic_flow, flows_app,
                                                                                 app, app1, app3, appt1, appn, appt3, appt4, pktn)
        f = open('temp1.txt', 'w')
        f.write(json.dumps(dic3))
        f.close()
        f = open('temp2.txt', 'w')
        f.write(json.dumps(dic4))
        f.close()
        f = open('temp3.txt', 'w')
        f.write(json.dumps(dic5))
        f.close()
        f = open('temp4.txt', 'w')
        f.write(json.dumps(dic6))
        f.close()
        f = open('temp5.txt', 'w')
        f.write(json.dumps(dic7))
        f.close()
        f = open('temp6.txt', 'w')
        f.write(json.dumps(app))
        f.close()
        closure(flows)
        closure_app(flows_app)
        print(id)

