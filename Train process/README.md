## Dataset
The dataset we use is unsw-nb15-pcap files(pcaps 17-2-2015),
You can download it at You can download it at https://cloudstor.aarnet.edu.au/plus/index.php/s/2DhnLGDdEECo4ys

## Preprocess
Preprocess the dataset after downloading it:
```
python preprocess.py
python tool.py

```
## Run DT
Training the DT model, this script outputs the results of DT:
```
python DT_train.py

```
## Convert DT to P4
Convert DT to P4 format:
```
python install_process.py

```
## Run BCN
Training the BCN model, this script outputs the results of BCN:
```
python BCN_train.py

```
## Convert MNN
```
python MNN_convert.py
./MNNConvert -f ONNX --modelFile our_model.onnx --MNNModel our_model.mnn --bizCode biz

```

