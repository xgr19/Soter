#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <math.h>
#include <iostream>
#include <cmath>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <signal.h>
#include <pthread.h>
#include "common_data.h"
#include "packet_process.h"
#include "bloomfilter.h"
#include "ringbuffer.h"
#include "thread_pool.h"
#include "MNN_process.h"

using namespace std;

extern struct hash_bucket_node gHashBucket[HASH_BUCKET_SIZE];
extern struct RingBuffer *gMemoryBuffer;
extern int g_flag;

uint32_t gPacketRemainCount = 0;
uint64_t gPacketProcCount = 0;
uint64_t gPacketSendToMnnCount = 0;
std::mutex g_CountMutex;

ThreadPool threadPool(MNN_THREAD_COUNT);
uint8_t *g_MnnBuffer = NULL;	// Also need a buffer pool here
uint32_t g_MnnBufferLen = 0;
std::mutex g_MnnBufferMutex;

uint8_t *g_MnnTimerBuffer = NULL;	// Also need a buffer pool here
uint32_t g_MnnTimerBufferLen = 0;

void getSystemTime(time_t *sys_time) {
	if (!sys_time) {
		return;
	}
	*sys_time = time(NULL);
}

inline int getFiveKeyLength(){
	return (int)&(((struct packet_info*)0)->ttl);
}

uint8_t* ipHeaderPos(uint8_t *packet) {
	uint16_t vlan_type;
	vlan_type = *(packet + MAC_LENGTH);
	if (vlan_type == VLAN_TYPE) {
		return packet + MAC_LENGTH + 6;
	} else {
		return packet + MAC_LENGTH + 2;
	}

}

static inline struct iphdr* getIpHeader(uint8_t *packet) {
	return (struct iphdr*) ipHeaderPos(packet);
}

bool initDHashBucket(){
	uint32_t index = 0;
	for(index = 0; index < HASH_BUCKET_SIZE; index++){
		gHashBucket[index].minimumTime = 0x7FFFFFFF;	// Year 2038
		gHashBucket[index].next = malloc(HASH_BUCKET_SIZE * sizeof(struct hash_bucket_node));
		if(NULL == gHashBucket[index].next){
			DEBUGPRINTF("Not enough memory %s:%d\n", __FILE__, __LINE__);
			exit(1);
		}
		uint32_t indexSecond = 0;
		struct hash_bucket_node * hashSecondBucketNode = (struct hash_bucket_node *) gHashBucket[index].next;
		for(indexSecond = 0; indexSecond < HASH_BUCKET_SIZE; indexSecond++){
			hashSecondBucketNode[indexSecond].minimumTime = 0x7FFFFFFF;  // Year 2038
			if(pthread_mutex_init(&(hashSecondBucketNode[indexSecond].mutex), NULL) < 0) {
				DEBUGPRINTF("thread mutex[%d:%d] initial failed %s:%d\n", index, indexSecond, __FILE__, __LINE__);
				exit(1);
			}
			hashSecondBucketNode[indexSecond].next = NULL;
		}
	}
	return true;
}

bool freeDHashBucket(){
	uint32_t index = 0;
	for(index = 0; index < HASH_BUCKET_SIZE; index++){
		uint32_t indexSecond = 0;
		struct hash_bucket_node * hashSecondBucketNode = (struct hash_bucket_node *) gHashBucket[index].next;
		for(indexSecond = 0; indexSecond < HASH_BUCKET_SIZE; indexSecond++){
			if(NULL != hashSecondBucketNode[indexSecond].next){
				releasePacketNode(&(hashSecondBucketNode[indexSecond]), (struct packet_info *)(hashSecondBucketNode[indexSecond].next), (struct packet_info *)(hashSecondBucketNode[indexSecond].next));
			}
			hashSecondBucketNode[indexSecond].next = NULL;
		}

		if(NULL != gHashBucket[index].next){
			free(gHashBucket[index].next);
		}
	}
	return true;
}

struct tcphdr* reWriteTcpHeader(uint8_t *packet, struct iphdr *iph, struct packet_info *packet_info) {
	struct tcphdr *tmp;
	tmp = (struct tcphdr*) (ipHeaderPos(packet) + iph->ihl * 4);
	//源端口，目的端口，seq和ack置0，校验和置1

	packet_info->saddr = ntohl(iph->saddr);
	packet_info->daddr = ntohl(iph->daddr);
	packet_info->ttl = iph->ttl;
	packet_info->protol = iph->protocol;
	packet_info->sport = ntohs(tmp->source);
	packet_info->dport = ntohs(tmp->dest);
	packet_info->total_len = ntohs(iph->tot_len);
	packet_info->data = packet;
	packet_info->ip_data = iph;
	packet_info->payload_data = (uint8_t*) (tmp);
//	packet_info->payload_data += sizeof(struct tcphdr);  // TODO: support tcp option
	DEBUGPRINTF("tcp_hdr_rewrite packet data:%p, ip_data:%p, payload_data:%p\n", packet_info->data, packet_info->ip_data, packet_info->payload_data);
	iph->daddr = 0;
	iph->saddr = 0;
	iph->id = 0;
	iph->frag_off = 0;
	iph->check = htons(1);

	tmp->source = 0;
	tmp->dest = 0;
	tmp->seq = 0;
	tmp->ack_seq = 0;
	tmp->check = htons(1);
	return tmp;
}

static inline struct udphdr* reWriteUdpHeader(uint8_t *packet, struct iphdr *iph, struct packet_info *packet_info) {
	struct udphdr *tmp;
	tmp = (struct udphdr*) (ipHeaderPos(packet) + iph->ihl * 4);
	//如果是UDP则需要将源端口目的端口置0，校验和置1

	packet_info->saddr = ntohl(iph->saddr);
	packet_info->daddr = ntohl(iph->daddr);
	packet_info->ttl = iph->ttl;
	packet_info->protol = iph->protocol;
	packet_info->sport = ntohs(tmp->source);
	packet_info->dport = ntohs(tmp->dest);
	packet_info->total_len = ntohs(iph->tot_len);
	packet_info->data = packet;
	packet_info->ip_data = iph;
	packet_info->payload_data = (uint8_t*) (tmp);
//	packet_info->payload_data += sizeof(struct udphdr);
	DEBUGPRINTF("udp_hdr_rewrite packet data:%p, ip_data:%p, payload_data:%p\n", packet_info->data, packet_info->ip_data, packet_info->payload_data);
	iph->daddr = 0;
	iph->saddr = 0;
	iph->id = 0;
	iph->frag_off = 0;
	iph->check = htons(1);

	tmp->source = 0;
	tmp->dest = 0;
	tmp->check = htons(1);
	return (struct udphdr*) tmp;
}

struct packet_info* formatPacket(uint8_t *packet, uint16_t length) {
	struct iphdr *iph;
	struct packet_info *packetNode;

	gPacketProcCount++;

	iph = getIpHeader(packet);
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) {
		DEBUGPRINTF("Unknown protocol:%d\n", iph->protocol);
		return NULL;
	}
	packetNode = (struct packet_info*) malloc(sizeof(struct packet_info));
	if (!packetNode) {
		return NULL;
	}
	memset(packetNode, 0, sizeof(struct packet_info));
	DEBUGPRINTF("Memory malloc for packetNode %p\n", packetNode);

	switch (iph->protocol) {
	case IPPROTO_TCP:
		reWriteTcpHeader(packet, iph, packetNode);
		break;
	case IPPROTO_UDP:
		reWriteUdpHeader(packet, iph, packetNode);
		break;
	default:
		DEBUGPRINTF("Unknown protocol:%d\n", iph->protocol);
		free(packetNode);
		DEBUGPRINTF("Memory free for packetNode %p\n", packetNode);
		packetNode = NULL;
		break;
	}

	// DEBUGPRINTF("set packet_info is ok\n");
	return packetNode;
}

void printMNNPacketCsvInfo(struct packet_info *packetNode, uint8_t *buffer, FILE *fp){
	if(NULL == fp){
		return;
	}
	uint32_t index = 0;
	fprintf(fp, "%d.%d.%d.%d.", (uint8_t)(packetNode->saddr>>24), (uint8_t)(packetNode->saddr>>16), (uint8_t)(packetNode->saddr>>8), (uint8_t)(packetNode->saddr));
	fprintf(fp, "%d.%d.%d.%d.", (uint8_t)(packetNode->daddr>>24), (uint8_t)(packetNode->daddr>>16), (uint8_t)(packetNode->daddr>>8), (uint8_t)(packetNode->daddr));
	fprintf(fp, "%d.%d.%d,", packetNode->protol, packetNode->sport, packetNode->dport);
	fprintf(fp, "\"[");
	for(index = 0; index < MAX_SINGLE_MNN_LEN; index++){
		if(index == MAX_SINGLE_MNN_LEN - 1){
			fprintf(fp, "%d]\"\n", buffer[index]);
		}else{
			fprintf(fp, "%d, ", buffer[index]);
		}
	}
	fflush(fp);
}


void setLastSixBytes(uint8_t *buffer, uint32_t *lengths){
	uint32_t totalLen = 0;
	uint32_t averageLen = 0;
	uint32_t sqrtLen = 0;
	totalLen = lengths[0] + lengths[1] + lengths[2];
	averageLen = totalLen / 3;
	uint32_t index = MAX_SINGLE_MNN_LEN - 6;

	DEBUGPRINTF("packet length: %d %d %d\n", lengths[0], lengths[1], lengths[2]);
	totalLen = totalLen / 10;
	if(totalLen > 255){
		totalLen = 255;
	}

	int32_t aveValue1 = (lengths[0] - averageLen) * (lengths[0] - averageLen);
	int32_t aveValue2 = (lengths[1] - averageLen) * (lengths[1] - averageLen);
	int32_t aveValue3 = (lengths[2] - averageLen) * (lengths[2] - averageLen);
	uint32_t tmpValue = (aveValue1 + aveValue2 + aveValue3) / 2;
	sqrtLen = sqrt(tmpValue) / 10;
	if (sqrtLen > 255) {
		sqrtLen = 255;
	}

	averageLen = averageLen / 10;
	if(averageLen > 255){
		averageLen = 255;
	}

	buffer[index++] = totalLen;
	buffer[index++] = averageLen;
	buffer[index++] = sqrtLen;
	uint32_t lengthIndex = 0;
	for (lengthIndex = 0; lengthIndex < 3; lengthIndex++) {
		tmpValue = lengths[lengthIndex] / 10;
		if (tmpValue > 255) {
			tmpValue = 255;
		}
		buffer[index++] = tmpValue;

	}

	DEBUGPRINTF("Attach %d %d %d %d %d %d\n", buffer[MAX_SINGLE_MNN_LEN-6], buffer[MAX_SINGLE_MNN_LEN-5], buffer[MAX_SINGLE_MNN_LEN-4], buffer[MAX_SINGLE_MNN_LEN-3], buffer[MAX_SINGLE_MNN_LEN-2], buffer[MAX_SINGLE_MNN_LEN-1]);
}

extern BaseBloomFilter gBloomFilter;
void releasePacketNode(struct hash_bucket_node *secondHashBucket, struct packet_info *preNode, struct packet_info *packetNode){
	if(NULL == secondHashBucket || NULL == packetNode){
		DEBUGPRINTF("error param![%s:%d]\n", __FILE__, __LINE__);
		return ;
	}
	DEBUGPRINTF("releasePacketNode, [%p]->next[%p]\n", secondHashBucket, secondHashBucket->next);

	// 1, 置bloomfilter
	// TODO: disable specify p4 copy_to_cpu rule
	int iRet = BloomFilter_Add(&gBloomFilter, packetNode, getFiveKeyLength());
	DEBUGPRINTF("Add bloomfilter return: %d\n", iRet);

	// 2, release packetNode
	DEBUGPRINTF("secondHashBucket->next[%p], packetNode[%p]\n", secondHashBucket->next, packetNode);
	if(secondHashBucket->next == packetNode){
		secondHashBucket->next = packetNode->next;
		DEBUGPRINTF("set secondHashBucket[%p]->next = [%p]\n", secondHashBucket, secondHashBucket->next);
	} else if(preNode != packetNode){
		preNode->next = packetNode->next;
	}
	freePacketInfo(packetNode);
}

bool sendPacketToMNN(struct hash_bucket_node *secondHashBucket, struct packet_info *preNode, struct packet_info *packetNode, FILE *fp){
	if(NULL == secondHashBucket || NULL == packetNode){
		DEBUGPRINTF("error param![%s:%d]\n", __FILE__, __LINE__);
		return false;
	}
	if(NULL == g_MnnBuffer){
		g_MnnBuffer = (uint8_t *)malloc((MAX_SINGLE_MNN_LEN + RCV_PKT_APPEND_HEAD_LEN) * MAX_MNN_STREAMS * sizeof(uint8_t));
		g_MnnBufferLen = 0;
		if(NULL == g_MnnBuffer){
			printf("Out of memory when sendPacketToMNN\n");
			exit(0);
		}
	}
	uint8_t *buffer = g_MnnBuffer;

	// The first packet should pass clock received to MNN
	uint8_t *clockBuffer = buffer + MAX_SINGLE_MNN_LEN * MAX_MNN_STREAMS + (g_MnnBufferLen / MAX_SINGLE_MNN_LEN) * RCV_PKT_APPEND_HEAD_LEN;
	DEBUGPRINTF("---Clock Buffer:%p should set to %ld.%ld\n", clockBuffer, packetNode->rcv_clock.tv_sec, packetNode->rcv_clock.tv_nsec);
	memcpy(clockBuffer, (uint8_t *)&packetNode->rcv_clock, RCV_PKT_APPEND_HEAD_LEN);
	DEBUGPRINTF("---Clock Buffer:%p actual set to %ld.%ld\n", clockBuffer, (*(struct timespec *)clockBuffer).tv_sec, (*(struct timespec *)clockBuffer).tv_nsec );

	buffer += g_MnnBufferLen;

	uint32_t bufferPtr = 0;
	int32_t bufferRemain = MAX_SINGLE_MNN_LEN - 6;
	uint32_t copyLength = 0;
	uint32_t index = 0;
	uint32_t lengths[3] = {0};

	struct packet_info *currentNode = packetNode;

	// First 252 Bytes
	while(currentNode != NULL && index < 3){
		lengths[index] = currentNode->total_len;
		if (bufferRemain > 0) {
			int32_t curLength = (index == 0) ? currentNode->total_len : (currentNode->total_len - ((uint16_t) (currentNode->payload_data - (uint8_t *)currentNode->ip_data)));
			uint8_t *copyPtr = (index == 0) ? (uint8_t *)currentNode->ip_data : (uint8_t *)currentNode->payload_data;
			if (curLength >= bufferRemain) {
				copyLength = bufferRemain;
				bufferRemain = 0;
			} else {
				copyLength = curLength;
				bufferRemain -= copyLength;
			}
			DEBUGPRINTF("copy to buffer[%d], with length: %d, and ptr:%p\n", bufferPtr, copyLength, copyPtr);
			memcpy(buffer + bufferPtr, copyPtr, copyLength);
			bufferPtr += copyLength;
		}
		currentNode = currentNode->subsequent;
		index ++;
	}

	// next 6 bytes
	setLastSixBytes(buffer, lengths);
	//	printMNNPacketInfo(packetNode, g_MnnBuffer, fp);

	g_MnnBufferLen += MAX_SINGLE_MNN_LEN;
	DEBUGPRINTF("---USE buffer length %d \n", g_MnnBufferLen);
	if (g_MnnBufferLen >= MAX_SINGLE_MNN_LEN * MAX_MNN_STREAMS) {
		// send buffer to MNN
		DEBUGPRINTF("---Before Send to MNN:%p set to %ld\n", clockBuffer, *((clock_t *)clockBuffer));
		threadPool.enqueue(mnnProcessPacket, g_MnnBuffer, g_MnnBufferLen, MAX_MNN_STREAMS);

		g_MnnBufferLen = 0;
		g_MnnBuffer = NULL;
	}

	// release resources
	releasePacketNode(secondHashBucket, preNode, packetNode);

	return true;
}

bool timerPacketToMNN(struct hash_bucket_node *secondHashBucket, struct packet_info *preNode, struct packet_info *packetNode, FILE *fp){
	if(NULL == secondHashBucket || NULL == packetNode){
		DEBUGPRINTF("error param![%s:%d]\n", __FILE__, __LINE__);
		return false;
	}
	if (NULL == g_MnnTimerBuffer) {
		g_MnnTimerBuffer = (uint8_t*) malloc((MAX_SINGLE_MNN_LEN + RCV_PKT_APPEND_HEAD_LEN) * MAX_MNN_STREAMS * sizeof(uint8_t));
		g_MnnTimerBufferLen = 0;
		if (NULL == g_MnnTimerBuffer) {
			printf("Out of memory when timerPacketToMNN\n");
			exit(0);
		}
	}
	uint8_t *buffer = g_MnnTimerBuffer;

	// The first packet should pass clock received to MNN
	uint8_t *clockBuffer = buffer + MAX_SINGLE_MNN_LEN * MAX_MNN_STREAMS + (g_MnnTimerBufferLen / MAX_SINGLE_MNN_LEN) * RCV_PKT_APPEND_HEAD_LEN;
	DEBUGPRINTF("---Clock Timer Buffer:%p should set to %ld.%ld\n", clockBuffer, packetNode->rcv_clock.tv_sec, packetNode->rcv_clock.tv_nsec);
	memcpy(clockBuffer, (uint8_t *)&packetNode->rcv_clock, RCV_PKT_APPEND_HEAD_LEN);
	DEBUGPRINTF("---Clock Timer Buffer:%p actual set to %ld.%ld\n", clockBuffer, (*(struct timespec *)clockBuffer).tv_sec,  (*(struct timespec *)clockBuffer).tv_nsec);

	buffer += g_MnnTimerBufferLen;

	uint32_t bufferPtr = 0;
	int32_t bufferRemain = MAX_SINGLE_MNN_LEN - 6;
	uint32_t copyLength = 0;
	uint32_t index = 0;
	uint32_t lengths[3] = {0};

	struct packet_info *currentNode = packetNode;

	// First 252 Bytes
	while(currentNode != NULL && index < 3){
		lengths[index] = currentNode->total_len;
		if (bufferRemain > 0) {
			int32_t curLength = (index == 0) ? currentNode->total_len : (currentNode->total_len - ((uint16_t) (currentNode->payload_data - (uint8_t *)currentNode->ip_data)));
			uint8_t *copyPtr = (index == 0) ? (uint8_t *)currentNode->ip_data : (uint8_t *)currentNode->payload_data;
			if (curLength >= bufferRemain) {
				copyLength = bufferRemain;
				bufferRemain = 0;
			} else {
				copyLength = curLength;
				bufferRemain -= copyLength;
			}
			DEBUGPRINTF("copy to timer buffer[%d], with length: %d, and ptr:%p\n", bufferPtr, copyLength, copyPtr);
			memcpy(buffer + bufferPtr, copyPtr, copyLength);
			bufferPtr += copyLength;
		}
		currentNode = currentNode->subsequent;
		index ++;
	}

	// next 6 bytes
	setLastSixBytes(buffer, lengths);
	g_MnnTimerBufferLen += MAX_SINGLE_MNN_LEN;
	// send buffer to MNN
//	printMNNPacketInfo(packetNode, buffer, fp);
	if(g_MnnTimerBufferLen >= MAX_SINGLE_MNN_LEN * MAX_MNN_STREAMS){
		threadPool.enqueue(mnnProcessPacket, g_MnnTimerBuffer, g_MnnTimerBufferLen, MAX_MNN_STREAMS);
		g_MnnTimerBufferLen = 0;
		g_MnnTimerBuffer = NULL;
	}

	// release resources
	releasePacketNode(secondHashBucket, preNode, packetNode);

	return true;
}

// ms任务到时，需要refresh buffer内容到MNN快速执行
bool refreshToMNN(FILE *fp){
	DEBUGPRINTF("---Refresh buffer %p with length %d\n", g_MnnBuffer,  g_MnnBufferLen);

	// send buffer to MNN
	threadPool.enqueue(mnnProcessPacket, g_MnnBuffer, g_MnnBufferLen, g_MnnBufferLen/MAX_SINGLE_MNN_LEN);
	g_MnnBufferLen = 0;
	g_MnnBuffer = NULL;

	return true;
}

// ms任务到时，需要refresh buffer内容到MNN快速执行
bool refreshTimerToMNN(FILE *fp){
	if(NULL == g_MnnTimerBuffer){
		return false;
	}
	DEBUGPRINTF("---USE timer buffer %p with length %d\n", g_MnnTimerBuffer, g_MnnTimerBufferLen);

	// send buffer to MNN
	threadPool.enqueue(mnnProcessPacket, g_MnnTimerBuffer, g_MnnTimerBufferLen, g_MnnTimerBufferLen/MAX_SINGLE_MNN_LEN);
	g_MnnTimerBufferLen = 0;
	g_MnnTimerBuffer = NULL;

	return true;
}

void freePacketInfo(struct packet_info *packetNode){
	struct packet_info *nextNode = packetNode->subsequent;
	while(NULL != packetNode){
		nextNode = packetNode->subsequent;
		DEBUGPRINTF("Release data[%p], and node[%p]\n", packetNode->data, packetNode);
		if(NULL != packetNode->data){
			free(packetNode->data);
			DEBUGPRINTF("Memory free for packetBuffer %p\n", packetNode->data);
		}
		free(packetNode);
		DEBUGPRINTF("Memory free for packetNode %p\n", packetNode);
		packetNode = nextNode;
		{
			unique_lock<std::mutex> lock(g_CountMutex);
			gPacketRemainCount --;
			gPacketSendToMnnCount++;
		}
	}
}

bool attachPacket(struct packet_info *headNode, struct packet_info *packet){
	if(NULL == headNode){
		DEBUGPRINTF("unknown head node when attach current packet to bucket[%s:%d]\n", __FILE__, __LINE__);
		return false;
	}
	uint32_t count = 1;
	while(NULL != headNode){
		count++;
		if(NULL != headNode->subsequent){
			headNode = headNode->subsequent;
		}else{
			headNode->subsequent = packet;
			break;
		}
	}
	DEBUGPRINTF("Add No.%d Node\n", count);
	if(count >= 3){
		return true;
	}
	return false;
}

void processPacket(struct hash_bucket_node *headNode, struct packet_info *packet, FILE *fp){
	if(NULL == headNode){
		return ;
	}
	if(NULL == headNode->next){
		headNode->next = packet;
		headNode->minimumTime = packet->time;
		DEBUGPRINTF("Add first NodeList, [%p]->next[%p]\n", headNode, headNode->next);
		return ;
	}
	struct packet_info *curNode = (struct packet_info *)(headNode->next);
	struct packet_info *preNode = curNode;

	int count = 1;
	while(NULL != curNode){
		if(0 == memcmp(curNode, packet, getFiveKeyLength())){
			if(attachPacket(curNode, packet)){
				// send to MNN
				sendPacketToMNN(headNode, preNode, curNode, fp);
			}
			DEBUGPRINTF("stream process finished\n");
			return ;
		}
		preNode = curNode;
		curNode = curNode->next;
		count++;
	}
	// an new stream
	if(preNode){
		preNode->next = packet;
		DEBUGPRINTF("Add No.%d NodeList, preNode[%p]->next = %p\n", count, preNode, packet);
	}
	return ;
}


/****************
 1、处理报文逻辑
 2、从缓存收包逻辑
 *****************/
void* packetProcess(void *arg) {
	uint8_t *packetBuffer;
	uint32_t packetLength;
	int iRet = 0;
	FILE *mnnFp = NULL;
	FILE *rawPacketFp = NULL;

	cpu_set_t mask;
	CPU_ZERO( &mask );
	CPU_SET(1, &mask );
	if (sched_setaffinity(0, sizeof(mask), &mask) == -1) {
		printf("WARNING: Could not set CPU Affinity %d for thread %s, continuing...\n", 1, "packetProcess");
	}

	mnnFp = fopen("./1.csv", "w");
	if(NULL == mnnFp){
		printf("packetProcess can't create output csv file\n");
		exit(0);
	}
	struct timespec startClock = {0};
	clock_gettime(CLOCK_MONOTONIC_RAW, &startClock);
	uint32_t count = 0;
	while (g_flag) {
		if (1) {	// for PRODUCTION
			if (isRingBufferEmpty()) {
				usleep(10);
				continue;
			}
			uint64_t index = gMemoryBuffer->tailPos;
			packetLength = gMemoryBuffer->nodes[index].dateLen;
			packetBuffer = (uint8_t*) malloc(MAX_RCV_PKT_BUF_LENGTH * sizeof(uint8_t));
			if (NULL == packetBuffer) {
				DEBUGPRINTF("malloc failed[%s:%d]\n", __FILE__, __LINE__);
				continue;
			}
			memcpy(packetBuffer, gMemoryBuffer->nodes[index].pData, MAX_RCV_PKT_BUF_LENGTH);
			DEBUGPRINTF("process %ld packet which length is %d\n", index, packetLength);
			releaseBufferNode();
		}else{		// for DEBUG
			rawPacketFp = fopen("./raw.pkt", "r");
			if(NULL == rawPacketFp){
				printf("packetProcess can't open raw.pkt file\n");
				exit(0);
			}
			packetBuffer = (uint8_t*) malloc((MAX_RCV_PKT_BUF_LENGTH) * sizeof(uint8_t));
			packetLength = fread(packetBuffer, sizeof(uint8_t), MAX_RCV_PKT_BUF_LENGTH, rawPacketFp);
			if(packetLength < 64){
				break;
			}
		}
		count++;
//		fwrite(packetBuffer, sizeof(uint8_t), MAX_LENGTH, rawPacketFp);
		DEBUGPRINTF("Memory malloc for packetBuffer %p\n", packetBuffer);

		struct packet_info* packetNode;
		packetNode = formatPacket(packetBuffer, packetLength);
		if(NULL == packetNode){
			free(packetBuffer);
			DEBUGPRINTF("Memory free for packetBuffer %p\n", packetBuffer);
			DEBUGPRINTF("Packet not support, continue\n");
			continue;
		}
		gPacketRemainCount++;
		packetNode->rcv_clock = *((struct timespec *)(packetBuffer + MAX_RCV_PKT_LENGTH));
		DEBUGPRINTF("process packet receive from %ld.%ld with length %d saved in %p\n", packetNode->rcv_clock.tv_sec, packetNode->rcv_clock.tv_nsec, packetLength, packetBuffer);

		getSystemTime(&(packetNode->time));
		DEBUGPRINTF("[%ld] Receive %d bytes, %04x:%d to %04x:%d, Node:%p\n", packetNode->time, packetLength, packetNode->saddr, packetNode->sport, packetNode->daddr, packetNode->dport, packetNode);
		iRet = BloomFilter_Check(&gBloomFilter, packetNode, getFiveKeyLength());
		if(iRet == 1){
		    uint64_t hash1 = MurmurHash2_x64(packetNode, getFiveKeyLength(), 0);
		    uint64_t hash2 = MurmurHash2_x64(packetNode, getFiveKeyLength(), MIX_UINT64(hash1));
		    uint32_t hashIndexFirst = hash1 & HASH_BUCKET_MASK;
			uint32_t hashIndexSecond = hash2 & HASH_BUCKET_MASK;

			struct hash_bucket_node *secondBucket = (struct hash_bucket_node *)gHashBucket[hashIndexFirst].next;
			secondBucket += hashIndexSecond;
			pthread_mutex_lock(&secondBucket->mutex);
			processPacket(secondBucket, packetNode, mnnFp);
			pthread_mutex_unlock(&secondBucket->mutex);
			DEBUGPRINTF("packet process successfully\n");
		}else if(iRet == 0){
			DEBUGPRINTF("Ip stream already exist, protocol[%d] %04x[%d] -> %04x[%d] \n",
					packetNode->protol, packetNode->saddr, packetNode->sport,
					packetNode->daddr, packetNode->dport);
			freePacketInfo(packetNode);
		}else{
			DEBUGPRINTF("Bloom filter action failed with iRet:%d\n", iRet);
			freePacketInfo(packetNode);
		}

	}
	struct timespec endClock = {0};
	clock_gettime(CLOCK_MONOTONIC_RAW, &endClock);

	DEBUGPRINTF("packetProcess: packet number %8d in %f seconds\n", count, SubTimeSpecToUs(endClock, startClock));


	if(NULL != rawPacketFp){
		fclose(rawPacketFp);
	}

	if (NULL != g_MnnBuffer) {
		free(g_MnnBuffer);
		g_MnnBuffer = NULL;
	}
	if (NULL != g_MnnTimerBuffer) {
		free(g_MnnTimerBuffer);
		g_MnnTimerBuffer = NULL;
	}
	fclose(mnnFp);
	return NULL;
}

