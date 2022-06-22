# -*- coding: utf-8 -*-
# @Author: cuicp
# @Date:   2022-06-20 15:58:51
# @Last Modified by:   cuicp
# @Last Modified time: 2022-06-21 14:22:48

from torch import Tensor
import torch.nn.functional as F
import numpy as np
import random
import torch
import torch.nn as nn

torch.manual_seed(2021)
torch.cuda.manual_seed_all(2021)
np.random.seed(2021)
random.seed(2021)
torch.backends.cudnn.deterministic = True

class HardSwish(nn.Module):
    def __init__(self, inplace=True):
        super(HardSwish, self).__init__()
        self.relu6 = nn.ReLU6(inplace)

    def forward(self, x):
        return x*self.relu6(x+3)/6


def channel_shuffle(x: Tensor, groups: int) -> Tensor:

    batch_size, num_channels, width = x.size()
    channels_per_group = num_channels // groups

    # reshape
    # [batch_size, num_channels, height, width] -> [batch_size, groups, channels_per_group, height, width]
    x = x.view(batch_size, groups, channels_per_group, width)

    x = torch.transpose(x, 1, 2).contiguous()

    # flatten
    x = x.view(batch_size, -1, width)

    return x
class BCN(nn.Module):

    def __init__(self, max_byte_len,num_classes, d_dim=16, stages_out_channels=64):
        super(BCN, self).__init__()
        self._stage_out_channels = stages_out_channels
        self.byteembedding = nn.Embedding(num_embeddings=300, embedding_dim=d_dim)
        output_channels = self._stage_out_channels
        self.conv1 = nn.Sequential(
            nn.Conv1d(in_channels=d_dim, out_channels=output_channels, kernel_size=8,
                      stride=5, padding=2, bias=False, groups=d_dim),
            nn.BatchNorm1d(output_channels),
            HardSwish(inplace=True)
        )
        self.maxpool1 = nn.MaxPool1d(kernel_size=3, stride=3, padding=1)
        input_channels = output_channels
        self.conv2 = nn.Sequential(
            nn.Conv1d(in_channels=input_channels, out_channels=output_channels, kernel_size=8,
                      stride=5, padding=2, bias=False, groups=1),
            nn.BatchNorm1d(output_channels),
            HardSwish(inplace=True)
        )
        self.maxpool2 = nn.MaxPool1d(kernel_size=4, stride=3, padding=1)
        self.fc2 = nn.Linear(output_channels, num_classes)


    def forward(self, x):
        out = self.byteembedding(x)
        out = out.transpose(-2,-1)
        out = self.conv1(out)
        out = channel_shuffle(out, 4)
        out = self.maxpool1(out)
        out = self.conv2(out)
        out = self.maxpool2(out)
        out = out.mean([2])
        out = self.fc2(out)
        if not self.training:
            return F.softmax(out, dim=-1).max(1)[1]
        return out


if __name__ == '__main__':
    x = np.random.randint(0, 255, (10, 20))
    y = np.random.randint(0, 20, (10, 20))
    sam = BCN(num_classes=5, max_byte_len=20)
    out = sam(torch.from_numpy(x).long())
    print(out[0])

    sam.eval()
    out = sam(torch.from_numpy(x).long())
    print(out[0])