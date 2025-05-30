/*
 * This is a C++ version of the canonical pthread service example. It intends
 * to abstract the service management functionality and sequencing for ease
 * of use. Much of the code is left to be implemented by the student.
 *
 * Build with g++ --std=c++23 -Wall -Werror -pedantic
 * Steve Rizor 3/16/2025
 * 
 * #References used in this code:
 * This code combines parts of model code from Exercises 1 to 4,
 * along with help from LLM-based tools for C++ syntax and structure.
 */
extern "C" {
    #include "packet_logger.h"
}
#pragma once

#include <cstdint>
#include <functional>
#include <thread>
#include <vector>
#include <semaphore.h>
#include <atomic>
#include <csignal>
#include <ctime>
#include <unistd.h>
#include <iostream>
#include <syslog.h>
#include <limits>
#include <mutex>
#include <algorithm>
#include <queue>
#include <atomic>
#include <thread>



// The service class contains the service function and service parameters
// (priority, affinity, etc). It spawns a thread to run the service, configures
// the thread as required, and executes the service whenever it gets released.

class Service
{
public:
    Service(Service&&) = default;
    Service& operator=(Service&&) = default;

    Service(const Service&) = delete;
    Service& operator=(const Service&) = delete;

    template<typename T>
    Service(T&& doService, const std::string& serviceName, uint8_t affinity, uint8_t priority, uint32_t period) :
        _doService(std::forward<T>(doService)),
        _serviceName(serviceName),
        _service(),
        _running(true),
        _affinity(affinity),
        _priority(priority),
        _period(period),
        _minJitter(std::numeric_limits<double>::max()),
        _minExecTime(std::numeric_limits<double>::max())
    {
        sem_init(&_sem, 0, 0);
        _service = std::jthread(&Service::_provideService, this);
        _csvFile = fopen((_serviceName + "_exec_times.csv").c_str(), "w");
        if (_period != INFINITE_PERIOD) {   // Only for periodic services
        _csvFile = fopen((_serviceName + "_exec_times.csv").c_str(), "w");
        if (_csvFile) {
            fprintf(_csvFile, "ExecutionTime_us\n");
            fflush(_csvFile);
        }
    }
    }

    void stop(){
        _running.store(false);
        sem_post(&_sem);
    }

    void release(){
        struct timespec releaseTime;
        clock_gettime(CLOCK_MONOTONIC, &releaseTime);
        {
            std::lock_guard<std::mutex> lock(_releaseMutex);
            _releaseTimes.push(releaseTime);
        }
        sem_post(&_sem);
    }

    ~Service()
    {
        stop();
        sem_destroy(&_sem);
        if (_csvFile) fclose(_csvFile);
        printStatistics();
    }

    sem_t& getSemaphore() { return _sem; }
    uint32_t getPeriod() const { return _period; }
    
private:
    std::function<void(void)> _doService;
    std::string _serviceName;
    std::jthread _service;
    std::atomic<bool> _running;
    sem_t _sem;

    uint8_t _affinity;
    uint8_t _priority;
    uint32_t _period;
    FILE *_csvFile = nullptr;

    std::queue<struct timespec> _releaseTimes;
    std::mutex _releaseMutex;

    double _minJitter = 0, _maxJitter = 0, _totalJitter = 0;
    size_t _jitterCount = 0;
    double _minExecTime = 0, _maxExecTime = 0, _totalExecTime = 0;
    size_t _execCount = 0;

    static inline double diffTimeUs(const struct timespec &start, const struct timespec &end) {
        return (end.tv_sec - start.tv_sec) * 1e6 + (end.tv_nsec - start.tv_nsec) / 1e3;
    }

    void _taskLoop() {
        while (_running.load()) {
            sem_wait(&_sem);
            if (!_running.load()) break;

            struct timespec releaseTime, startTime, endTime;
            {
                std::lock_guard<std::mutex> lock(_releaseMutex);
                if (!_releaseTimes.empty()) {
                    while (_releaseTimes.size() > 1) _releaseTimes.pop();
                    releaseTime = _releaseTimes.front();
                    _releaseTimes.pop();
                } else {
                    clock_gettime(CLOCK_MONOTONIC, &releaseTime);
                }
            }

            clock_gettime(CLOCK_MONOTONIC, &startTime);
            double jitter = diffTimeUs(releaseTime, startTime);
            _minJitter = std::min(_minJitter, jitter);
            _maxJitter = std::max(_maxJitter, jitter);
            _totalJitter += jitter;
            ++_jitterCount;

            _doService();

            clock_gettime(CLOCK_MONOTONIC, &endTime);
            double execTime = diffTimeUs(startTime, endTime);
            _minExecTime = std::min(_minExecTime, execTime);
            _maxExecTime = std::max(_maxExecTime, execTime);
            _totalExecTime += execTime;
            ++_execCount;

            if (_csvFile) {
                fprintf(_csvFile, "%.2f\n", execTime);
                fflush(_csvFile);
            }
        }
    }

    void _initializeService() {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(_affinity, &cpuset);
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

        sched_param sch_params{};
        sch_params.sched_priority = _priority;
        pthread_setschedparam(pthread_self(), SCHED_FIFO, &sch_params);
    }

    void _provideService() {
        _initializeService();
        _taskLoop();
    }


    void printStatistics() const {
  if (_period == INFINITE_PERIOD){
        return;
        }  // Skip printing statistics for infinite services
        syslog(LOG_INFO,"\n=== Service: %-10s (Period: %u us) Statistics ===\n", _serviceName.c_str(), _period*1000);
        if (_jitterCount > 0)
             syslog(LOG_INFO, " Start Jitter (us): min = %.2f, max = %.2f, avg = %.2f\n",
                   _minJitter, _maxJitter, _totalJitter / _jitterCount);
        if (_execCount > 0)
             syslog(LOG_INFO, "  Execution Time (us): min = %.2f, max = %.2f, avg = %.2f\n",
                   _minExecTime, _maxExecTime, _totalExecTime / _execCount);
    }


};
// The sequencer class contains the services set and manages
// starting/stopping the services. While the services are running,
// the sequencer releases each service at the requisite timepoint.
class Sequencer
{
public:
    template<typename... Args>
    void addService(Args&&... args)
    {
        // Add the new service to the services list,
        // constructing it in-place with the given args
        //_services.emplace_back(std::forward<Args>(args)...);
            _services.emplace_back(std::make_unique<Service>(std::forward<Args>(args)...));
    }
void startServices()
{
    _runningTimer.store(true);

    _tickThread = std::jthread([](Sequencer* self) {
        int tick_ms = 0;
        static std::unordered_map<Service*, bool> started_map;  // Moved outside loop

        while (self->_runningTimer.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            ++tick_ms;

            for (auto& service : self->_services) {
                Service* service_ptr = service.get(); // Get raw pointer once

                if (service_ptr->getPeriod() == INFINITE_PERIOD) {
                    if (!started_map[service_ptr]) {
                        sem_post(&service_ptr->getSemaphore());
                        started_map[service_ptr] = true;
                    }
                }
                else if (tick_ms % service_ptr->getPeriod() == 0) {
                    sem_post(&service_ptr->getSemaphore());
                }
            }

            if (tick_ms >= 1000) tick_ms = 0;
        }
    }, this);
}


void stopServices()
{
    _runningTimer.store(false); // Tell tick thread to stop
    if (_tickThread.joinable())
        _tickThread.join();

    for (auto& service : _services)
        service->stop();
}



private:
    std::jthread _tickThread;
    std::atomic<bool> _runningTimer {false};
    //std::vector<Service> _services;
    std::vector<std::unique_ptr<Service>> _services;

     static inline Sequencer* _instance = nullptr;
    timer_t _timerId;

    static void _timerHandler(int sig, siginfo_t* si, void* uc)
    {
    (void)sig; (void)si; (void)uc;
        static int tick = 0;
        tick += 1;

        if (!_instance) return;

        for (auto& service : _instance->_services)
        {
            if (service->getPeriod() == INFINITE_PERIOD)
                {
                    static bool started = false;
                    if (!started)
                    {
                        sem_post(&service->getSemaphore());
                        started = true;
                    }
                }
                else if (tick % service->getPeriod() == 0)
                    {
                        sem_post(&service->getSemaphore());
                    }
        }
        if (tick >= 100) tick = 0;
    }
};
