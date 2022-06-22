/*
 * ringbuffer.cpp
 *
 *  Created on: 2022年2月10日
 *      Author: xiegr19
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#include"common_data.h"
#include "ringbuffer.h"

struct RingBuffer *gMemoryBuffer;

int initRingBuffer(void) {
	uint32_t index;
	gMemoryBuffer = (struct RingBuffer*) malloc(sizeof(struct RingBuffer));
	if (NULL == gMemoryBuffer) {
		return -1;
	}

	for (index = 0; index < MAX_RINGBUFFER_SIZE; index++) {
		(gMemoryBuffer->nodes[index]).pData = (uint8_t *) malloc(MAX_RCV_PKT_BUF_LENGTH * sizeof(uint8_t));
		if (!gMemoryBuffer->nodes[index].pData) {
			DEBUGPRINTF("Run out of memory, turn down ring buffer size\n");
			exit(1);
		}

		memset(gMemoryBuffer->nodes[index].pData, 0, MAX_RCV_PKT_BUF_LENGTH);
		gMemoryBuffer->nodes[index].dateLen = 0;
	}
	gMemoryBuffer->writePos = 0;
	gMemoryBuffer->tailPos = 0;
	return 0;
}

void destroyRingBuffer(void) {
	uint32_t index;

	for (index = 0; index < MAX_RINGBUFFER_SIZE; index++) {
		free(gMemoryBuffer->nodes[index].pData);
	}
	free(gMemoryBuffer);
}

bool isRingBufferFull() {
	if (((gMemoryBuffer->writePos + 1) % MAX_RINGBUFFER_SIZE) == gMemoryBuffer->tailPos) {
		return true;
	}
	return false;
}

bool isRingBufferEmpty() {
	if (gMemoryBuffer->tailPos == gMemoryBuffer->writePos){
		return true;
	}
	return false;
}

void advenceBufferNode(uint32_t len){
	gMemoryBuffer->nodes[gMemoryBuffer->writePos].dateLen = len;
	gMemoryBuffer->writePos = (gMemoryBuffer->writePos + 1) % MAX_RINGBUFFER_SIZE;		// TODO: use CAS operation?
}


void releaseBufferNode(void) {
	gMemoryBuffer->nodes[gMemoryBuffer->tailPos].dateLen = 0;
	gMemoryBuffer->tailPos = (gMemoryBuffer->tailPos + 1) % MAX_RINGBUFFER_SIZE;		// TODO: use CAS operation?

}




