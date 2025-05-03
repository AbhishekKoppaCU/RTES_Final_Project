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
#include <unordered_map>
#include <iomanip>

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
        if (_period != INFINITE_PERIOD) {
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

    void release(const struct timespec& releaseTime) {
        {
            std::lock_guard<std::mutex> lock(_releaseMutex);
            _releaseTimes.push(releaseTime);
        }
        sem_post(&_sem);
    }

    void release() {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        release(now);
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
    double _totalDrift = 0;
    size_t _deadlineMissCount = 0;

    struct timespec _baseReleaseTime {};
    bool _hasBaseRelease = false;
    size_t _tickCount = 0;

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

            if (_period != INFINITE_PERIOD) {
                if (!_hasBaseRelease) {
                    _baseReleaseTime = releaseTime;
                    _hasBaseRelease = true;
                }

                ++_tickCount;

                uint64_t expected_us = static_cast<uint64_t>(_tickCount) * _period;
                struct timespec expected;
                expected.tv_sec = _baseReleaseTime.tv_sec + expected_us / 1000;
                expected.tv_nsec = _baseReleaseTime.tv_nsec + (expected_us % 1000) * 1'000'000;

                if (expected.tv_nsec >= 1'000'000'000) {
                    expected.tv_sec += 1;
                    expected.tv_nsec -= 1'000'000'000;
                }

                double drift = diffTimeUs(expected, startTime);
                _totalDrift = drift;
            }

            _doService();

            clock_gettime(CLOCK_MONOTONIC, &endTime);
            double execTime = diffTimeUs(startTime, endTime);
            _minExecTime = std::min(_minExecTime, execTime);
            _maxExecTime = std::max(_maxExecTime, execTime);
            _totalExecTime += execTime;
            ++_execCount;

            if (_period != INFINITE_PERIOD && execTime > _period * 1000.0) {
                ++_deadlineMissCount;
            }

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
        if (_period == INFINITE_PERIOD) return;

        double avgJitter = _maxJitter - _minJitter;
        double avgExecTime = (_execCount > 0) ? (_totalExecTime / _execCount) : 0;
        double cpuUtilPercent = (_period > 0) ? (avgExecTime / (_period * 1000.0)) * 100.0 : 0.0;

        syslog(LOG_INFO, "\n=== Service: %-10s | Period: %-6u us ===", _serviceName.c_str(), _period * 1000);
        syslog(LOG_INFO, "  Jitter (us)        : min = %8.2f | max = %8.2f | avg = %8.2f",
               _minJitter, _maxJitter, avgJitter);
        syslog(LOG_INFO, "  Exec Time (us)     : min = %8.2f | max = %8.2f | avg = %8.2f",
               _minExecTime, _maxExecTime, avgExecTime);
        syslog(LOG_INFO, "  CPU Utilization    : %6.2f%%", cpuUtilPercent);
        syslog(LOG_INFO, "  Cumulative Drift   : %8.2f us", _totalDrift);
        syslog(LOG_INFO, "  Deadline Misses    : %6zu\n", _deadlineMissCount);
    }
};

class Sequencer
{
public:
    template<typename... Args>
    void addService(Args&&... args)
    {
        _services.emplace_back(std::make_unique<Service>(std::forward<Args>(args)...));
    }

    void startServices()
    {
        _runningTimer.store(true);
        _tickThread = std::jthread([](Sequencer* self) {
            static struct timespec base_time;
            static bool base_set = false;

            int tick_ms = 0;
            static std::unordered_map<Service*, bool> started_map;

            while (self->_runningTimer.load()) {
                if (!base_set) {
                    clock_gettime(CLOCK_MONOTONIC, &base_time);
                    base_set = true;
                }

                struct timespec expected = base_time;
                expected.tv_nsec += tick_ms * 1'000'000;
                expected.tv_sec += expected.tv_nsec / 1'000'000'000;
                expected.tv_nsec %= 1'000'000'000;

                clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &expected, NULL);

                struct timespec now;
                clock_gettime(CLOCK_MONOTONIC, &now);

                double drift_us = (now.tv_sec - expected.tv_sec) * 1e6 + (now.tv_nsec - expected.tv_nsec) / 1e3;

                if (drift_us > 0) {
                    base_time.tv_nsec += static_cast<long>(drift_us * 1e3);
                } else if (drift_us < 0) {
                    base_time.tv_nsec += static_cast<long>(drift_us * 1e3);
                }

                if (base_time.tv_nsec >= 1'000'000'000) {
                    base_time.tv_sec += 1;
                    base_time.tv_nsec -= 1'000'000'000;
                } else if (base_time.tv_nsec < 0) {
                    base_time.tv_sec -= 1;
                    base_time.tv_nsec += 1'000'000'000;
                }

                struct timespec release_time = now;
                for (auto& service : self->_services) {
                    Service* service_ptr = service.get();

                    if (service_ptr->getPeriod() == INFINITE_PERIOD) {
                        if (!started_map[service_ptr]) {
                            service_ptr->release(release_time);
                            started_map[service_ptr] = true;
                        }
                    } else if (tick_ms % service_ptr->getPeriod() == 0) {
                        service_ptr->release(release_time);
                    }
                }

                ++tick_ms;
                if (tick_ms >= 1000) tick_ms = 0;
            }
        }, this);
    }

    void stopServices()
    {
        _runningTimer.store(false);
        if (_tickThread.joinable())
            _tickThread.join();
        for (auto& service : _services)
            service->stop();
    }

private:
    std::jthread _tickThread;
    std::atomic<bool> _runningTimer {false};
    std::vector<std::unique_ptr<Service>> _services;
};
