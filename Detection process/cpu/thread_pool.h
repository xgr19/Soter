/*
 * thread_pool.h
 *
 *  Created on: 2022年2月10日
 *      Author: xiegr19
 */

#ifndef THREAD_POOL_H_
#define THREAD_POOL_H_

#include <vector>
#include <queue>
#include <memory>
#include <sched.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <future>
#include <functional>
#include <stdexcept>

class ThreadPool {
public:
	ThreadPool(size_t);
	template<class F, class ... Args>
	auto enqueue(F &&f, Args &&... args) -> std::future<typename std::result_of<F(Args...)>::type>;
	~ThreadPool();
private:
	// need to keep track of threads so we can join them
	std::vector<std::thread> workers;
	// the task queue
	std::queue<std::function<void()> > tasks;

	// synchronization
	std::mutex queue_mutex;
	std::condition_variable condition;
	bool stop;
};

// the constructor just launches some amount of workers
inline ThreadPool::ThreadPool(size_t threads) : stop(false) {
	for (size_t i = 0; i < threads; ++i) {
		workers.emplace_back([this, i] {
			int totalCpuCount = std::thread::hardware_concurrency();
			int hostCpuCore = totalCpuCount - (i%totalCpuCount) - 1;
			// 设置CPU亲和属性
			// TODO：采取普适性更好的适配算法
			cpu_set_t mask;
			CPU_ZERO( &mask );
			CPU_SET(hostCpuCore, &mask );
			if (sched_setaffinity(0, sizeof(mask), &mask) == -1) {
				printf("WARNING: Could not set CPU Affinity %d for thread %ld, continuing...\n", hostCpuCore, i);
			}
			for (;;) {
				std::function<void()> task;

				{
					std::unique_lock<std::mutex> lock(this->queue_mutex);
					this->condition.wait(lock, [this] {
						return this->stop || !this->tasks.empty();
					});
					if (this->stop && this->tasks.empty()) {
						return;
					}

					task = std::move(this->tasks.front());
					this->tasks.pop();
				}

				task();
			}
		}
		);
	}
}

// add new work item to the pool
template<class F, class ... Args>
auto ThreadPool::enqueue(F &&f, Args &&... args) -> std::future<typename std::result_of<F(Args...)>::type> {
	using return_type = typename std::result_of<F(Args...)>::type;

	auto task = std::make_shared<std::packaged_task<return_type()> >(std::bind(std::forward<F>(f), std::forward<Args>(args)...));

	std::future<return_type> res = task->get_future();
	{
		std::unique_lock<std::mutex> lock(queue_mutex);

		// don't allow enqueueing after stopping the pool
		if (stop){
			throw std::runtime_error("enqueue on stopped ThreadPool");
		}

		tasks.emplace([task]() {
			(*task)();
		});
	}
	condition.notify_one();
	return res;
}

// the destructor joins all threads
inline ThreadPool::~ThreadPool() {
	{
		std::unique_lock<std::mutex> lock(queue_mutex);
		stop = true;
	}
	condition.notify_all();
	for (std::thread &worker : workers){
		worker.join();
	}
}

#endif /* THREAD_POOL_H_ */
