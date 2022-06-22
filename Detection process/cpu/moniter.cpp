/*
 * moniter.cpp
 *
 *  Created on: 2022年2月22日
 *      Author: xiegr19
 */
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include "moniter.h"
#include "bloomfilter.h"
#include "ringbuffer.h"
#include "common_data.h"
#include "packet_process.h"

FILE *moniterFp = NULL;

extern BaseBloomFilter gBloomFilter;
extern struct RingBuffer *gMemoryBuffer;
extern uint64_t gPacketRcvCount;
extern uint64_t gPacketProcCount;
extern uint64_t gPacketSendToMnnCount;
extern uint64_t gRingBufferFull;
extern uint32_t g_MNNStreamsCount;

void freeMoniterResource(){
	fclose(moniterFp);
}

void* monitorProcess(void *arg) {
	cpu_set_t mask;
	CPU_ZERO( &mask );
	CPU_SET(2, &mask );
	if (sched_setaffinity(0, sizeof(mask), &mask) == -1) {
		printf("WARNING: Could not set CPU Affinity %d for thread %s, continuing...\n", 2, "packet_timer");
	}

	moniterFp = fopen("./memory.csv", "w");
	if(NULL == moniterFp){
		printf("monitorProcess can't create output csv file\n");
		exit(0);
	}
	sleep(3);	// 延迟S启动

	uint32_t count = 0;
	fprintf(moniterFp, "Second,BloomFilter,RingBuffer,RB_Full_Count,DHASH_Buffer,PkgReceived,PkgProcced,PkgToMnn,StreamMnnCount\n");
	while (true) {
		usleep(MONITER_TIMEOUT * 1000 * 1000);

		uint64_t ringBufferLen = 0;
		if(gMemoryBuffer->writePos >= gMemoryBuffer->tailPos){
			ringBufferLen = gMemoryBuffer->writePos - gMemoryBuffer->tailPos;
		}else{
			ringBufferLen = gMemoryBuffer->writePos + MAX_RINGBUFFER_SIZE - gMemoryBuffer->tailPos;
		}
		fprintf(moniterFp, "%d,%lu,%ld,%ld,%ld,%ld,%ld,%ld,%d\n", count, gBloomFilter.dwFilterSize, ringBufferLen * (MAX_RCV_PKT_BUF_LENGTH * sizeof(uint8_t)), gRingBufferFull
				, (gPacketProcCount - gPacketSendToMnnCount) * (sizeof(struct packet_info)) + HASH_BUCKET_SIZE * HASH_BUCKET_SIZE * sizeof(struct hash_bucket_node)
				, gPacketRcvCount, gPacketProcCount, gPacketSendToMnnCount, g_MNNStreamsCount);
		fflush(moniterFp);
		count++;
	}
	fclose(moniterFp);
}

