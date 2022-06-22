#ifndef COMMON_DATA_H
#define COMMON_DATA_H

#define	STREAM_TIMEOUT			3		// 30s
#define MAX_RINGBUFFER_SIZE     3840000		// 1GB
#define MAX_RCV_PKT_BUF_LENGTH  288
#define RCV_PKT_APPEND_HEAD_LEN	sizeof(struct timespec)	// 数据包头添加时间戳
#define MAX_RCV_PKT_LENGTH  (MAX_RCV_PKT_BUF_LENGTH - RCV_PKT_APPEND_HEAD_LEN)
#define CUR_RCV_PKT_LENGTH  270

#define VLAN_TYPE       	0x8100
#define MAC_LENGTH      	12
#define MAX_SINGLE_MNN_LEN 	258		// 单条流输入数据大小
#define MAX_MNN_STREAMS    	1 		// 单次输入MNN的流条数
#define THREASHOLD_LENGTH  	252
#define MIN_PACKET_LENGTH  	64
#define HASH_BUCKET_MASK   	0x7F
#define HASH_BUCKET_SIZE   	128 	// 首级和次级BUCKET同大小

#define MNN_THREAD_COUNT	1

// BloomFilter参数
#define BF_MAX_STREAMS 		1000000
#define BF_CONFLICT_RATE	0.000001

#ifndef IPPROTO_TCP 
#define IPPROTO_TCP     6
#endif

#ifndef IPPROTO_UDP 
#define IPPROTO_UDP     17
#endif

#ifdef DEBUG
    #define DEBUGPRINTF(format, ...) printf (format, ##__VA_ARGS__)
#else
    #define DEBUGPRINTF(format, ...)
#endif

inline double SubTimeSpecToUs(struct timespec endTime, struct timespec startTime){
	long timeDiff = 0.0;
	if(endTime.tv_sec < startTime.tv_sec){
		return timeDiff;
	}
	timeDiff = (endTime.tv_sec - startTime.tv_sec) * 1000000;
	timeDiff += endTime.tv_nsec/1000;
	timeDiff -= startTime.tv_nsec/1000;

	return (double)timeDiff/1000000;
}
#endif
