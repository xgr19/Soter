# -*- coding: utf-8 -*-
# @Author: cuicp
# @Date:   2022-06-20 15:58:51
# @Last Modified by:   cuicp
# @Last Modified time: 2022-06-21 14:22:48

import torch
import torch.nn.functional as F
import torch.utils.data
import torch.optim as optim
import time
from tqdm import tqdm, trange
from BCN import BCN
from tool import attack_cat, load_epoch_data, max_byte_len
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix,accuracy_score
import pickle

attack_cat = ['Fuzzers', 'Analysis', 'Backdoor', 'DoS', 'Generic',
             'Reconnaissance', 'Shellcode', 'Worms', 'Exploits', 'benign']

class Dataset(torch.utils.data.Dataset):
    """docstring for Dataset"""

    def __init__(self, x, label):
        super(Dataset, self).__init__()
        self.x = x
        self.label = label

    def __len__(self):
        return len(self.x)

    def __getitem__(self, idx):
        return self.x[idx], self.label[idx]


def paired_collate_fn(insts):
    x, label = list(zip(*insts))
    return torch.LongTensor(x), torch.LongTensor(label)


def cal_loss(pred, gold, cls_ratio=None):
    gold = gold.contiguous().view(-1)
    # By default, the losses are averaged over each loss element in the batch.
    loss = F.cross_entropy(pred, gold)

    pred = F.softmax(pred, dim=-1).max(1)[1]
    n_correct = pred.eq(gold)
    acc = n_correct.sum().item() / n_correct.shape[0]

    return loss, acc * 100


def test_epoch(model, test_data):
    ''' Epoch operation in training phase'''
    model.eval()

    total_acc = []
    total_pred = []
    total_time = []
    for batch in tqdm(
            test_data, mininterval=2,
            desc='  - (Testing)   ', leave=False):
        # prepare data
        src_seq, gold = batch
        src_seq, gold = src_seq.cuda(), gold.cuda()
        gold = gold.contiguous().view(-1)

        # forward
        torch.cuda.synchronize()
        start = time.time()
        pred = model(src_seq)
        torch.cuda.synchronize()
        end = time.time()
        n_correct = pred.eq(gold)
        acc = n_correct.sum().item() * 100 / n_correct.shape[0]
        total_acc.append(acc)
        total_pred.extend(pred.long().tolist())
        total_time.append(end - start)

    return sum(total_acc) / len(total_acc), \
           total_pred, sum(total_time) / len(total_time)


def train_epoch(model, training_data, optimizer):
    ''' Epoch operation in training phase'''
    model.train()

    total_loss = []
    total_acc = []
    for batch in tqdm(
            training_data, mininterval=2,
            desc='  - (Training)   ', leave=False):
        # prepare data
        src_seq, gold = batch
        src_seq, gold = src_seq.cuda(), gold.cuda()

        optimizer.zero_grad()
        # forward
        pred = model(src_seq)
        loss_per_batch, acc_per_batch = cal_loss(pred, gold)
        # update parameters
        loss_per_batch.backward()
        optimizer.step()

        total_loss.append(loss_per_batch.item())
        total_acc.append(acc_per_batch)

    return sum(total_loss) / len(total_loss), sum(total_acc) / len(total_acc)


def main(i, flow_dict):
    log_dir = ('./results_train/para_model_%d.pth' % i)
    f = open('results_train/results_%d.txt' % i, 'w')
    f.write('Train Loss Time Test\n')
    f.flush()
    total_acc1 = 0
    total_loss = 0
    total_time = 0
    total_acc2 = 0

    model = BCN(num_classes=len(attack_cat), max_byte_len=max_byte_len).cuda()
    optimizer = optim.Adam(filter(lambda x: x.requires_grad, model.parameters()))
    loss_list = []
    # default epoch is 3
    for epoch_i in trange(5, mininterval=2, \
                          desc='  - (Training Epochs)   ', leave=False):

        train_x, train_label = load_epoch_data(flow_dict, 'train')
        training_data = torch.utils.data.DataLoader(
            Dataset(x=train_x, label=train_label),
            num_workers=0,
            collate_fn=paired_collate_fn,
            batch_size=128,
            shuffle=True
        )
        train_loss, train_acc = train_epoch(model, training_data, optimizer)

        test_x, test_label = load_epoch_data(flow_dict, 'test')
        test_data = torch.utils.data.DataLoader(
            Dataset(x=test_x, label=test_label),
            num_workers=0,
            collate_fn=paired_collate_fn,
            batch_size=128,
            shuffle=False
        )
        test_acc, pred, test_time = test_epoch(model, test_data)

        # write F1, PRECISION, RECALL
        with open('results_train/metric_%d.txt' % i, 'w') as f3:
            f3.write('PRE REC F1\n')
            p, r, fscore, num = precision_recall_fscore_support(test_label, pred)
            for a, b, c, d in zip(p, r, fscore, num):
                # for every cls
                f3.write('%.5f %.5f %.5f\n' % (a, b, c))
                f3.flush()
            if len(fscore) != len(attack_cat):
                a = set(pred)
                b = set(test_label[:, 0])
                f3.write('%s\n%s' % (str(a), str(b)))
            p, r, fscore, num = precision_recall_fscore_support(test_label, pred, average = 'weighted')
            f3.write('PRE REC F1 micro\n')
            f3.write('%.5f %.5f %.5f\n' % (p, r, fscore))
            p, r, fscore, num = precision_recall_fscore_support(test_label, pred, average = 'macro')
            f3.write('PRE REC F1 macro\n')
            f3.write('%.5f %.5f %.5f\n' % (p, r, fscore))

        # write Confusion Matrix
        with open('results_train/cm_%d.pkl' % i, 'wb') as f4:
            pickle.dump(confusion_matrix(test_label, pred), f4)

        # write ACC
        total_acc1 = total_acc1 + train_acc
        total_loss = total_loss + train_loss
        total_time = total_time + test_time
        total_acc2 = total_acc2 + test_acc
        f.write('%.2f %.4f %.6f %.2f\n' % (train_acc, train_loss, test_time, test_acc))
        f.flush()
    state = {'model':model.state_dict(), 'optimizer':optimizer.state_dict()}
    torch.save(state, log_dir)
    f.write('%.2f %.4f %.6f %.2f\n' % (total_acc1/5, total_loss/5, total_time/5, total_acc2/5))

    f.close()


if __name__ == '__main__':
    for i in range(5):
        with open('pro_flows_10_0.5_%d_noip_fold.pkl' % i, 'rb') as f:
            flow_dict = pickle.load(f)
        print('====', i, ' fold validation ====')
        main(i, flow_dict)
