# Used to modify the header format of the PCAP link layer to Ethernet
import os

if __name__ == '__main__':
    num
    for i in range(1, num + 1):  # Count from one
        infile_ = str(i) + '.pcap'
        root = 'out/'  # Folder where files are saved
        outfile_ = root + 'out-' + str(i) + '.pcap'
        tcprewrite_ = 'tcprewrite --dlt=enet --infile=' + infile_ + ' --outfile=' + outfile_
        print(tcprewrite_)
        os.system(tcprewrite_)
