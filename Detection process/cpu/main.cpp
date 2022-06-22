#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include "common_data.h"
#include "moniter.h"
#include "MNN_process.h"
#include "packet_process.h"
#include "packet_timer.h"
#include "packet_receive.h"

extern int initRingBuffer(void);
extern bool initPacketBloomFilter();
extern bool initDHashBucket();
extern void destroyRingBuffer(void);
extern bool freePacketBuffer();
extern bool freeDHashBucket();

int g_flag=1;

static void sig_usr(int signum)
{
    g_flag=0;
}


void init_sigal_handle(struct sigaction *sa_usr)
{
    sa_usr->sa_flags = 0;
    sa_usr->sa_handler = sig_usr;   //信号处理函数
   
    sigaction(SIGINT, sa_usr, NULL);
}


/***********************
主函数
***********************/
int main(int argc, char **argv) {
	int iRet = 0;
	pthread_t receivePktThread, processPktThread, timerThread, moniterThread;
	struct sigaction sa_usr = {0};

	if (argc != 2) {
		DEBUGPRINTF("please enter the portname\n");
		return -1;
	}

	init_sigal_handle(&sa_usr);

	iRet = initRingBuffer();
	if (iRet < 0) {
		DEBUGPRINTF("create buffer is error\n");
		return -1;
	}

	if (!initPacketBloomFilter()) {
		DEBUGPRINTF("Run out of memory! turn down bloom filter parameter\n");
		return -1;
	}
	if (!initDHashBucket()) {
		DEBUGPRINTF("Run out of memory! turn down hash bucket parameter\n");
		return -1;
	}

	initialMNN();

	if (pthread_create(&processPktThread, NULL, packetProcess, NULL) != 0) {
		pthread_cancel(receivePktThread);
		DEBUGPRINTF("thread packetProcess create failed\n");
		return -1;
	}

	sleep(5);

	if (pthread_create(&timerThread, NULL, timerProcess, NULL) != 0) {
		pthread_cancel(receivePktThread);
		pthread_cancel(processPktThread);
		DEBUGPRINTF("thread timerProcess create failed \n");
		return -1;
	}

	if (pthread_create(&receivePktThread, NULL, packetRecv, argv[1]) != 0) {
		DEBUGPRINTF("thread packetRecv create failed\n");
		return -1;
	}

	if (pthread_create(&moniterThread, NULL, monitorProcess, argv[1]) != 0) {
		DEBUGPRINTF("thread monitorProcess create failed\n");
		return -1;
	}


	pthread_join(receivePktThread, NULL);
	pthread_join(processPktThread, NULL);
	pthread_join(timerThread, NULL);
	pthread_join(moniterThread, NULL);

	destroyRingBuffer();
	freeDHashBucket();
	freePacketBuffer();
	freeMNN();
	freeMoniterResource();
	return 1;

}
