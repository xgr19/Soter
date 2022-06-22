/*
 * moniter.h
 *
 *  Created on: 2022年2月22日
 *      Author: xiegr19
 */

#ifndef MONITER_H_
#define MONITER_H_


#define MONITER_TIMEOUT 1    // 1S

#define MONITER_BLOOMFILTER   0
#define MONITER_RINGBUFFER    1
#define MONITER_RINGBUFFERFUL 2
#define MONITER_DHASHBUFFER   3
#define MONITER_RCVPKGNUM     4
#define MONITER_PROCPKGNUM    5
#define MONITER_MNNPKGNUM     6

void freeMoniterResource();
void* monitorProcess(void *arg);

#endif /* MONITER_H_ */
