#ifndef packetProcess_H
#define packetProcess_H

#include <time.h>
#include "common_data.h"

struct tcphdr {
	uint16_t	source;
	uint16_t	dest;
	uint32_t	seq;
	uint32_t	ack_seq;
#if defined(LITTLE_ENDIAN_BITFIELD)
	uint16_t	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(BIG_ENDIAN_BITFIELD)
	uint16_t	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"makefile set "
#endif	
	uint16_t	window;
	uint16_t	check;
	uint16_t	urg_ptr;
};

struct udphdr {
	uint16_t	source;
	uint16_t	dest;
	uint16_t	len;
	uint16_t	check;
};


struct iphdr {
#if defined(LITTLE_ENDIAN_BITFIELD)
	uint8_t	ihl:4,
		version:4;
#elif defined (BIG_ENDIAN_BITFIELD)
	uint8_t	version:4,
  		ihl:4;
#else
#error	"Please makefile set num"
#endif
	uint8_t	tos;
	uint16_t	tot_len;
	uint16_t	id;
	uint16_t	frag_off;
	uint8_t	ttl;
	uint8_t	protocol;
	uint16_t	check;
	uint32_t	saddr;
	uint32_t	daddr;
	/*The options start here. */
};

#pragma pack (1)
struct packet_info{
	uint32_t	saddr;
	uint32_t	daddr;
	uint16_t sport;
	uint16_t dport;
	uint8_t  protol;
	uint8_t ttl;
	uint16_t total_len;
	time_t time;
	struct timespec rcv_clock;
	uint8_t* data;
	struct iphdr *ip_data;
	uint8_t *payload_data;

	struct packet_info *next;
	struct packet_info *subsequent;
};
#pragma pack ()

struct hash_node
{
	uint8_t head_flag:1;
	uint8_t count:3;
	uint8_t timer_ttl;
	uint16_t sum_length;
    uint16_t pkg_length[3];
	struct packet_info *packet_info;
	struct hash_node*children;
	struct hash_node*next;
};

// hash bucket struct
struct hash_bucket_node{
	time_t minimumTime;
	pthread_mutex_t mutex;
	void *next;
};

bool initDHashBucket();
bool freeDHashBucket();

void getSystemTime(time_t *sys_time);
int getFiveKeyLength();
void processPacket(struct hash_bucket_node *headNode, struct packet_info *packet, FILE *fp);
struct packet_info* formatPacket(uint8_t *packet,uint16_t length);
bool sendPacketToMNN(struct hash_bucket_node *secondHashBucket, struct packet_info *preNode, struct packet_info *packetNode, FILE *fp);
bool refreshToMNN(FILE *fp);
bool timerPacketToMNN(struct hash_bucket_node *secondHashBucket, struct packet_info *preNode, struct packet_info *packetNode, FILE *fp);
bool refreshTimerToMNN(FILE *fp);
void freePacketInfo(struct packet_info *packet);
void releasePacketNode(struct hash_bucket_node *secondHashBucket, struct packet_info *preNode, struct packet_info *packetNode);

void* packetProcess(void *arg);
#endif
