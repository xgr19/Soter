# Soter/Soterv2 of DL Enhanced In-Network Attack Detection in SRDS22 and TDSC24
#### More information about us https://xgr19.github.io  

## Abstract:
Though several deep learning (DL) detectors have been proposed for the network attack detection and achieved high accuracy, they are computationally expensive and struggle to satisfy the real-time detection for high-speed networks. We present Soter, a DL enhanced in-network framework for the accurate real-time detection. Soter consists of two phases. One is filtering packets by a rule-based decision tree running on the Tofino ASIC with P4. The other is executing a well-designed lightweight neural network for the thorough inspection of the suspicious packets on the CPU. Experiments on the commodity switch demonstrate that Soter behaves stably in ten network scenarios of different traffic rates and fulfills per-flow detection in 0.03s.


## Code Architecture (detailed readme is in the corresponding subfolders)

```
-- Train process
	-- code of BCN and DT training
		
-- Detection process
	-- code of P4 program (Pre-screening Module) and CPU Intensive Detection Module

```
