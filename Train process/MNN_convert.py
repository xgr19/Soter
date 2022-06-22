# -*- coding: utf-8 -*-
# @Author: cuicp
# @Date:   2022-06-20 15:58:51
# @Last Modified by:   cuicp
# @Last Modified time: 2022-06-21 14:22:48

import torch.onnx
import numpy as np
from BCN import BCN

log_dir = './results_train/para_model.pth'

model = BCN(10, 10)
model.eval()
input = np.random.randint(0, 255, (1,40))
temp_data = torch.from_numpy(input).float()
input_names = ["input"]
output_names = ["output"]
torch.onnx.export(model, temp_data, "our_model.onnx", verbose=True,
                  input_names=input_names, output_names=output_names)
print("ok")