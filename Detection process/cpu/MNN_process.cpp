/*
 * MNN_process.cpp
 *
 *  Created on: 2022年2月10日
 *      Author: xiegr19
 *
 *  MNN推理处理模块，
 *
 */
#include <iostream>
#include <cmath>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <typeinfo>
#include <mutex>
#include <memory>
#include <map>
#include <thread>
#include <sstream>
#include <string>
#include <MNN/Interpreter.hpp>
#include "common_data.h"

#define INPUT_NAME "input"
#define OUTPUT_NAME "output"

using namespace std;

MNN::Interpreter * g_mnnNet;
MNN::Session * g_session;
double total_time = 0;
double total_mnn_time = 0;
FILE *res = NULL;
FILE *prob = NULL;
FILE *finishTimeFile = NULL;
std::mutex mnnMutex;
map<thread::id, MNN::Session *> g_sessionMap;
uint32_t g_MNNStreamsCount = 0;
uint32_t g_MNNCount = 0;

void initialMNN(){
	res = fopen("vcls.txt", "w");
	prob = fopen("vprob.txt", "w");
	finishTimeFile = fopen("finishtime.csv", "w");

	g_mnnNet = MNN::Interpreter::createFromFile("our_model.mnn");
}
void freeMNN(){
	fflush(res);
	fflush(prob);
	fflush(finishTimeFile);
	delete g_mnnNet;
	g_mnnNet = NULL;
	fclose(res);
	fclose(prob);
	fclose(finishTimeFile);
}

int mnnProcessPacket(uint8_t *packet_data, uint32_t data_len, uint32_t stream_count) {
	if(NULL == finishTimeFile){
		printf("Error: finishTimeFile is NULL and return\n");
		return 1;
	}
	thread::id threadId = this_thread::get_id();
	std::ostringstream oss;
	oss << threadId;
	auto iter = g_sessionMap.find(threadId);
	if(iter == g_sessionMap.end()){
		MNN::ScheduleConfig netConfig;
		netConfig.numThread = 1;
		std::unique_lock<std::mutex> lock(mnnMutex);
		g_sessionMap[threadId] = g_mnnNet->createSession(netConfig);

		DEBUGPRINTF("ThreadId %s add session:%p\n", oss.str().c_str(), g_sessionMap[threadId]);
	}
	MNN::Session * session = g_sessionMap[threadId];
	stringstream sin;
	sin << threadId;
	DEBUGPRINTF("ThreadId %s use session:%p, with input %p length %d\n", oss.str().c_str(), session, packet_data, data_len);
	struct timespec  mnnStartTime = {0};
	clock_gettime(CLOCK_MONOTONIC_RAW, &mnnStartTime);
	MNN::Tensor *input = NULL; {
		std::unique_lock<std::mutex> lock(mnnMutex);
		input = g_mnnNet->getSessionInput(session, INPUT_NAME);
	}

	for (uint32_t i = 0; i < data_len; i++) {
		input->host<int>()[i] = packet_data[i];
	}

	// run session
	struct timespec cstart, ccpend;
	clock_gettime(CLOCK_MONOTONIC_RAW, &cstart);
	g_mnnNet->runSession(session);
	clock_gettime(CLOCK_MONOTONIC_RAW, &ccpend);
	double timeDiff1 = SubTimeSpecToUs(ccpend, cstart);{
		std::unique_lock<std::mutex> lock(mnnMutex);
		total_time += timeDiff1;
		g_MNNStreamsCount += stream_count;
	}
	// get output data
	MNN::Tensor *output = NULL;{
		std::unique_lock<std::mutex> lock(mnnMutex);
		output = g_mnnNet->getSessionOutput(session, OUTPUT_NAME);
	}
	auto output_host = make_shared < MNN::Tensor > (output, MNN::Tensor::CAFFE);
	output->copyToHostTensor(output_host.get());

	// Write process time to file
	struct timespec mnnEndTime = {0};
	clock_gettime(CLOCK_MONOTONIC_RAW, &mnnEndTime);
	struct timespec *packetRcvTime = (struct timespec*) (packet_data + MAX_SINGLE_MNN_LEN * MAX_MNN_STREAMS); {
		DEBUGPRINTF("write to file %p with buffer %p and value %ld.%ld - %ld.%ld\n", finishTimeFile, packetRcvTime, mnnEndTime.tv_sec, mnnEndTime.tv_nsec, packetRcvTime[0].tv_sec, packetRcvTime[0].tv_nsec);
		std::unique_lock<std::mutex> lock(mnnMutex);
		for (uint32_t i = 0; i < stream_count; i++) {
			fprintf(finishTimeFile, "%f,%f\n",  timeDiff1/stream_count,  SubTimeSpecToUs(mnnEndTime, packetRcvTime[i]));
		}
		fflush(finishTimeFile);
		total_mnn_time += SubTimeSpecToUs(mnnEndTime, mnnStartTime);
	}
	DEBUGPRINTF("ThreadId %s count %d start %ld.%ld end %ld.%ld core %f total_core %f total_mnn %f\n", oss.str().c_str(), g_MNNCount, mnnStartTime.tv_sec, mnnStartTime.tv_nsec, mnnEndTime.tv_sec, mnnEndTime.tv_nsec, timeDiff1, total_time, total_mnn_time);
	free(packet_data);
	return 0;
}
