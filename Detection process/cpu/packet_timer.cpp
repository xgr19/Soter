#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include "packet_process.h"
#include "packet_timer.h"

extern struct hash_bucket_node gHashBucket[HASH_BUCKET_SIZE];
extern void getSystemTime(time_t *sys_time);
extern int g_flag;

bool inline isTimeOut(struct packet_info *head_node, time_t sys_time) {
	if ((sys_time - head_node->time) > STREAM_TIMEOUT) {
		return true;
	}
	return false;
}

void* timerProcess(void *arg) {
	time_t curTime;
	FILE *fp = NULL;

	cpu_set_t mask;
	CPU_ZERO( &mask );
	CPU_SET(2, &mask );
	if (sched_setaffinity(0, sizeof(mask), &mask) == -1) {
		printf("WARNING: Could not set CPU Affinity %d for thread %s, continuing...\n", 2, "packet_timer");
	}

	fp = fopen("./0.csv", "w");
	if(NULL == fp){
		printf("timerProcess can't create output csv file\n");
		exit(0);
	}


	while (g_flag) {
		usleep(STREAM_TIMEOUT*1000*1000/3);	// 1/3 timeout period
		getSystemTime(&curTime);
		int indexFirst = 0;
		uint32_t count = 0;

		clock_t startClock = clock();
		for (indexFirst = 0; indexFirst < HASH_BUCKET_SIZE; indexFirst++) {
			int indexSecond = 0;
			struct hash_bucket_node *bucketNode = (struct hash_bucket_node*) gHashBucket[indexFirst].next;
			for (indexSecond = 0; indexSecond < HASH_BUCKET_SIZE; indexSecond++) {
				struct hash_bucket_node *secondBucketNode = bucketNode + indexSecond;

				pthread_mutex_lock(&secondBucketNode->mutex);
				struct packet_info *packetNode = (struct packet_info*) secondBucketNode->next;
				while (NULL != packetNode) {
					if (isTimeOut(packetNode, curTime)) {
						count++;
						if(!timerPacketToMNN(secondBucketNode, packetNode, packetNode, fp)){
							break;	//
						}
					}else{
						break;	// no need to further process
					}
					packetNode = (struct packet_info*) secondBucketNode->next;
				}
				pthread_mutex_unlock(&secondBucketNode->mutex);


			}
		}
		refreshTimerToMNN(fp);
		clock_t endClock = clock();
		if(count > 0){
			double tempTime = endClock - startClock;
			DEBUGPRINTF(" timerProcess: packet number %8d in %f seconds\n", count, tempTime / CLOCKS_PER_SEC);
		}
	}
	fclose(fp);
	exit(0);
}
