# -*- coding: utf-8 -*-
# @Author: cuicp
# @Date:   2022-06-20 15:58:51
# @Last Modified by:   cuicp
# @Last Modified time: 2022-06-21 14:22:48

import pandas as pd
from sklearn.feature_extraction import DictVectorizer
from sklearn import tree
import numpy as np
import json
import pickle
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix,accuracy_score
import joblib
import csv

eps = 1e-6
max_byte_len1 = 252
max_byte_len2 = 784

attack_cat = ['Fuzzers', 'Analysis', 'Backdoor', 'DoS', 'Generic',
             'Reconnaissance', 'Shellcode', 'Worms', 'Exploits', 'benign']

def main(counts, dic1, dic2, dic3, dic4, dic5, app):
    # load data
    data1 = pd.read_csv('DTree_pre_train_%d_test.csv' % counts, usecols=[1, 2, 3, 4, 5, 6, 7, 8])
    data2 = pd.read_csv('DTree_pre_test_%d_test.csv' % counts, usecols=[1, 2, 3, 4, 5, 6, 7, 8])
    data1.columns = ['HeaderLength', 'IPProtocol', 'TOS', 'TTL', 'TCPflags', 'Flags', 'Attack', 'ID']
    data2.columns = ['HeaderLength', 'IPProtocol', 'TOS', 'TTL', 'TCPflags', 'Flags', 'Attack', 'ID']

    vec = DictVectorizer(sparse=False)
    feature1 = data1[['HeaderLength', 'IPProtocol', 'TOS', 'TTL', 'TCPflags', 'Flags', 'ID']]
    train_x = vec.fit_transform(feature1.to_dict(orient='record'))
    feature2 = data1[['Attack']]
    train_y = vec.fit_transform(feature2.to_dict(orient='record'))
    feature3 = data2[['HeaderLength', 'IPProtocol', 'TOS', 'TTL', 'TCPflags', 'Flags', 'ID']]
    test_x = vec.fit_transform(feature3.to_dict(orient='record'))
    feature4 = data2[['Attack']]
    test_y = vec.fit_transform(feature4.to_dict(orient='record'))

    test_g_x = []
    test_g_y = []
    for i in range(test_y.shape[0]):
        now = list(test_x[i][0:2])
        now2 = list(test_x[i][3:8])
        now.extend(now2)
        test_g_x.append(now)
        test_g_y.append(test_y[i])
    train_g_x = []
    train_g_y = []
    b = 1
    a = 1
    for i in range(train_y.shape[0]):
        if abs((train_y[i][1] - 1.0)) < eps and b <= 5 * a:
            b = b + 1
            now = list(train_x[i][0:2])
            now2 = list(train_x[i][3:8])
            now.extend(now2)
            train_g_x.append(now)
            train_g_y.append(train_y[i])
        elif abs((train_y[i][0] - 1.0)) < eps:
            a = a + 1
            now = list(train_x[i][0:2])
            now2 = list(train_x[i][3:8])
            now.extend(now2)
            train_g_x.append(now)
            train_g_y.append(train_y[i])
    train_g_x = np.array(train_g_x)
    train_g_y = np.array(train_g_y)
    test_g_x = np.array(test_g_x)
    test_g_y = np.array(test_g_y)
    # train DT
    clf = tree.DecisionTreeClassifier(criterion='entropy', max_depth=8, random_state=0)
    clf.fit(train_g_x, train_g_y)
    y_predicted = clf.predict(test_g_x)
    for i in range(y_predicted.shape[0]):
        if abs(y_predicted[i][0] - 0) < eps and abs(y_predicted[i][1] - 0) < eps:
            y_predicted[i][0] = 1.0
        elif abs(y_predicted[i][0] - 1) < eps and abs(y_predicted[i][1] - 1) < eps:
            y_predicted[i][1] = 0.0
    joblib.dump(clf,  "Tree_%d.pkl" %counts)
    score = clf.score(test_g_x, test_g_y)
    print("Score : ", score)
    score = accuracy_score(test_g_y, y_predicted)
    print("ACC : ", score)
    score = recall_score(test_g_y, y_predicted, average='weighted')
    print("Recall_macro : ", score)
    score = recall_score(test_g_y, y_predicted, average='micro')
    print("Recall_micro : ", score)
    score = precision_score(test_g_y, y_predicted, average='weighted')
    print("Pre_macro : ", score)
    score = precision_score(test_g_y, y_predicted, average='micro')
    print("Pre_micro : ", score)
    score = f1_score(test_g_y, y_predicted, average='weighted')
    print("F1_macro : ", score)
    score = f1_score(test_g_y, y_predicted, average='micro')
    print("F1_micro : ", score)
    score = confusion_matrix(test_g_y.argmax(axis=1), y_predicted.argmax(axis=1))
    print("Confusion_matrix : ")
    print(score)
    with open('cpu_test.csv', 'w', encoding='UTF-8') as f3:
        csv_writer3 = csv.writer(f3)
        csv_writer3.writerow(["5_tuple", "258_byte"])
        flows1 = [{} for _ in range(len(attack_cat))]
        flows2 = [{} for _ in range(len(attack_cat))]
        flow_dict1 = {}
        flow_dict2 = {}
        flow_dict3 = {}
        flow_dict4 = {}
        data1 = {}
        data2 = {}
        data3 = {}
        num = {}
        ccp = 0
        for i in range(y_predicted.shape[0]):
            if abs(y_predicted[i][0] - 1.0) < eps:
                a = test_x[i][2]
                a = str(int(a))
                ip = dic1[a]
                ipd = dic2[a]
                key = dic3[a]
                now_att = dic4[a]
                if now_att != 'benign':
                    ccp = ccp + 1
                RNN_data = dic5[a]
                index = attack_cat.index(now_att)
                if key not in flows1[index]:
                    flows1[index][key] = [ip]
                    flows2[index][key] = [RNN_data]
                elif len(flows1[index][key]) < 21:
                    flows1[index][key].append(ipd)
                    flows2[index][key].append(RNN_data)

        for name in attack_cat:
            index = attack_cat.index(name)
            data1[name] = flows1[index]
            data2[name] = flows2[index]
            data3[name] = flows1[index]
        for p in attack_cat:
            num[p] = 0
            flow_dict1[p] = []
            flow_dict2[p] = []
            flow_dict3[p] = []
            flow_dict4[p] = []
            p_keys = list(data1[p].keys())

            for flow in p_keys:
                all_pkts1 = []
                all_pkts2 = []
                pkts1 = data1[p][flow]
                pkts2 = data2[p][flow]
                now_app = app[p][flow]
                all_pkts1.extend(pkts1)
                all_pkts2.extend(pkts2)
                byte1 = []
                byte2 = []
                byte3 = []
                pos = []
                ppp = 0
                for idx in range(min(len(all_pkts1), 3)):
                    if len(byte1) <= max_byte_len1:
                        raw_byte1 = all_pkts1[idx]
                        for x in range(len(raw_byte1)):
                            pos.append(int(ppp))
                            ppp = ppp + 1
                            byte1.append(int(raw_byte1[x]))
                    else:
                        break
                byte1.extend([0] * (max_byte_len1 - len(byte1)))
                byte1 = byte1[0:int(max_byte_len1)]
                pos.extend([0] * (max_byte_len1 - len(pos)))
                pos = pos[0:int(max_byte_len1)]
                for x in range(len(now_app)):
                    byte1.append(int(now_app[x]))
                num[p] = num[p] + 1
                pos.append(int(252))
                pos.append(int(253))
                pos.append(int(254))
                pos.append(int(255))
                pos.append(int(256))
                pos.append(int(257))
                flow_dict1[p].append((byte1))
                flow_dict4[p].append((byte1,pos))
                csv_writer3.writerow([str(flow),str(byte1)])
                for idx in range(min(len(all_pkts1), 3)):
                    if len(byte3) <= max_byte_len2:
                        raw_byte3 = all_pkts1[idx]
                        for x in range(len(raw_byte3)):
                            byte3.append(int(raw_byte3[x]))
                    else:
                        break
                byte3.extend([0] * (max_byte_len2 - len(byte3)))
                byte3 = byte3[0:int(max_byte_len2)]
                flow_dict3[p].append((byte3))
                for idx in range(min(len(all_pkts2), 20)):
                    raw_byte2 = all_pkts2[idx]
                    for x in range(len(raw_byte2)):
                        byte2.append(int(raw_byte2[x]))
                byte2.extend([0] * (600 - len(byte2)))
                byte2 = byte2[0:600]
                flow_dict2[p].append((byte2))
    with open('DecTree_flows_%d.pkl' % counts, 'wb') as f:
        pickle.dump(flow_dict1, f)
    with open('DecTree_flows_600_%d.pkl' % counts, 'wb') as f:
        pickle.dump(flow_dict2, f)
    with open('DecTree_flows_784_%d.pkl' % counts, 'wb') as f:
        pickle.dump(flow_dict3, f)
    with open('DecTree_SAM_256_%d.pkl' % counts, 'wb') as f:
        pickle.dump(flow_dict4, f)
    print(num)
    print('ccp',ccp)
if __name__ == '__main__':
    with open('temp1.txt', 'r') as f:
        dic1 = json.load(f)
    # no pkt head
    with open('temp2.txt', 'r') as f:
        dic2 = json.load(f)
    # key
    with open('temp3.txt', 'r') as f:
        dic3 = json.load(f)
    # class
    with open('temp4.txt', 'r') as f:
        dic4 = json.load(f)
    # CNN+RNN test
    with open('temp5.txt', 'r') as f:
        dic5 = json.load(f)
    with open('pro_flows_1_28_app.pkl', 'rb') as f:
        app = pickle.load(f)
    for count in range(1):
        main(count, dic1, dic2, dic3, dic4, dic5, app)