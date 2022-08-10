# Soter of DL Enhanced In-Network Attack Detection in IEEE SRDS22 
#### More information about us https://xgr19.github.io  

## Abstract:
Though several deep learning (DL) detectors have been proposed for the network attack detection and achieved high accuracy, they are computationally expensive and struggle to satisfy the real-time detection for high-speed networks. Recently, programmable switches exhibit a remarkable throughput efficiency on production networks, indicating a possible deployment of the timely detector. Therefore, we present Soter, a DL enhanced in-network framework for the accurate real-time detection. Soter consists of two phases. One is filtering packets by a rule-based decision tree running on the Tofino ASIC. The other is executing a well-designed lightweight neural network for the thorough inspection of the suspicious packets on the CPU. Experiments on the commodity switch demonstrate that Soter behaves stably in ten network scenarios of different traffic rates and fulfills per-flow detection in 0.03s. Moreover, Soter naturally adapts to the distributed deployment among multiple switches, guaranteeing a higher total throughput for large data centers and cloud networks.


## Code Architecture (detailed readme is in the corresponding subfolders)

```
-- Train process
	-- code of BCN and DT training
		
-- Detection process
	-- code of P4 program (Pre-screening Module) and CPU Intensive Detection Module

```
