/*
 * MNN_process.h
 *
 *  Created on: 2022年2月10日
 *      Author: xiegr19
 */

#ifndef MNN_PROCESS_H_
#define MNN_PROCESS_H_

#include <stdint.h>

// 初始化MNN处理模块
void initialMNN();

// 释放MNN处理模块的资源
void freeMNN();

// 对报文进行MNN推理
int mnnProcessPacket(uint8_t *packet_data, uint32_t data_len, uint32_t stream_count);


#endif /* MNN_PROCESS_H_ */
