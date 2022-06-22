/*
 * packet_receive.h
 *
 *  Created on: 2022年1月27日
 *      Author: xiegr19
 */

#ifndef PACKET_RECEIVE_H_
#define PACKET_RECEIVE_H_


bool initPacketBloomFilter();
void* packetRecv(void *arg);

#endif /* PACKET_RECEIVE_H_ */
