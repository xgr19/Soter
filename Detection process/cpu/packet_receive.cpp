#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>  
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>  
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h> 
#include <netinet/in.h>
#include <netinet/ether.h>
#include <sys/ioctl.h> 
#include <netpacket/packet.h>
#include <signal.h>
#include <pthread.h>
#include "bloomfilter.h"
#include "packet_process.h"
#include "ringbuffer.h"
#include "packet_receive.h"
#include "common_data.h"

extern struct RingBuffer *gMemoryBuffer;
extern int g_flag;

BaseBloomFilter gBloomFilter = {0};
struct hash_bucket_node gHashBucket[HASH_BUCKET_SIZE];
uint64_t gPacketRcvCount = 0;
uint64_t gRingBufferFull = 0;
bool 	 gBufferFullRev  = false;

bool initPacketBloomFilter(){
	int iRet = InitBloomFilter(&gBloomFilter, 0, BF_MAX_STREAMS, BF_CONFLICT_RATE);
	if(iRet < 0){
		return false;
	}
	return true;
}

bool freePacketBuffer(){
	FreeBloomFilter(&gBloomFilter);

	return true;
}

/****************
 从cpu收包，
 1、建立raw_socket ，绑定对应的从p4虚拟出的cpu端口
 2、收包
 *****************/
void* packetRecv(void *arg) {
	int rcvLen;
	int iRet = 0;
	char *dev = NULL;
	int sock = 0;
	struct ifreq ifr;
	struct sockaddr_ll sll;
#ifdef SET_SOCKET_BUFFER_LEN
	unsigned int optlen;
	int err;
	int rcv_size = 0; 
#endif
	dev = (char*) arg;

	cpu_set_t mask;
	CPU_ZERO( &mask );
	CPU_SET(0, &mask );
	if (sched_setaffinity(0, sizeof(mask), &mask) == -1) {
		printf("WARNING: Could not set CPU Affinity %d for thread %s, continuing...\n", 0, "packet_receive");
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	ifr.ifr_ifindex = if_nametoindex(dev);
	if (!ifr.ifr_ifindex) {
		perror("ifindex error\n");
		exit(1);
	}

	if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		perror("raw socket create error\n");
		exit(1);
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = ifr.ifr_ifindex;

	iRet = bind(sock, (struct sockaddr*) &sll, sizeof(sll));
	if (iRet) {
		DEBUGPRINTF("bind is error\n");
		exit(1);
	}

#ifdef SET_SOCKET_BUFFER_LEN
	optlen = sizeof(rcv_size);
	err = getsockopt(sock, SOL_SOCKET, SO_RCVBUF,&rcv_size, &optlen);
	if(err<0){
		DEBUGPRINTF("SO_RCVBUF info error\n");
	}   
	
	rcv_size = 1024*1024*256;    /*Modify kernel param  sysctl -w net.core.rmem_max=*/
	optlen = sizeof(rcv_size);
	err = setsockopt(sock,SOL_SOCKET,SO_RCVBUF, (char *)&rcv_size, optlen);	
	if(err<0){
		DEBUGPRINTF("SO_RCVBUF set is error\n");
	}

	err = getsockopt(sock, SOL_SOCKET, SO_RCVBUF,&rcv_size, &optlen);
	if(err<0){
		DEBUGPRINTF("SO_RCVBUF info error\n");
	}
	printf("SO_RCVBUF:%d\n", rcv_size);
#endif

//	clock_t startClock;
	uint64_t totalLen = 0;
	while (g_flag) {
		if (isRingBufferFull()){
//			DEBUGPRINTF("ring buffer is full\n");
			if(false == gBufferFullRev){
				gBufferFullRev = true;
				gRingBufferFull++;
			}
			continue;
		}
		gBufferFullRev = false;
		uint8_t *dataBuffer = gMemoryBuffer->nodes[gMemoryBuffer->writePos].pData;
		struct timespec *currentClock = (struct timespec *)(dataBuffer + MAX_RCV_PKT_LENGTH);
		clock_gettime(CLOCK_MONOTONIC_RAW, currentClock);
		rcvLen = recvfrom(sock, dataBuffer, CUR_RCV_PKT_LENGTH, 0, NULL, NULL);
		if (rcvLen < 0) {
			printf("the recive buffer is error\n");
			continue;
		}
		DEBUGPRINTF("Receive packet from socket, clock:%ld.%ld len:%d, saved in %ld\n", currentClock->tv_sec, currentClock->tv_nsec, rcvLen, gMemoryBuffer->writePos);
		advenceBufferNode(rcvLen);

		gPacketRcvCount++;
		totalLen += rcvLen;
	}
	close(sock);

	exit(0);
}

