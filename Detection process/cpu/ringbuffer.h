/*
 * ringbuffer.h
 *
 *  Created on: 2022年2月10日
 *      Author: xiegr19
 *
 *  简单的RingBuffer封装结构
 */

#ifndef RING_BUFFER_H
#define RING_BUFFER_H

#include <stdint.h>
#include "common_data.h"

struct BufferNode {
	uint8_t *pData;
	uint32_t dateLen;
};

struct RingBuffer {
	uint64_t pad0, pad1, pad2, pad3, pad4, pad5, pad6;
	volatile  uint64_t writePos; //head
	uint64_t pad8, pad9, pad10, pad11, pad12, pad13, pad14;
	volatile uint64_t tailPos;
	uint64_t pad16, pad17, pad18, pad19, pad20, pad21, pad22;
	struct BufferNode nodes[MAX_RINGBUFFER_SIZE];
};
// 初始化RingBuffer的相关数据结构
int initRingBuffer(void);

// 释放RingBuffer所占用的资源
void destroyRingBuffer(void);

// 判断RingBuffer资源是否已经全部占用
bool isRingBufferFull();

// 判断RingBuffer为空
bool isRingBufferEmpty();

// 占用一个RingBuffer节点，将指针指向下一个可用资源
void advenceBufferNode(uint32_t len);

// 释放RingBuffer
void releaseBufferNode(void);

#endif
