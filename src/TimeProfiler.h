/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_BENCHMARK_H
#define SQUID_BENCHMARK_H

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <math.h>
#include <sstream>
#include <vector>

typedef std::micro Period;

class TimePoint
{
    public:
        std::chrono::time_point<std::chrono::steady_clock> timePoint;
        time_t cpuPoint;
};

template<class D>
class Durations
{
    public:
        typedef std::chrono::duration<double, Period> DoubleDuration;

        explicit Durations(const char *aDescription) :
            description(aDescription), numberOfSlices(-1), objectSize(-1) {}
        typedef std::vector<D> Store;
        typedef typename Store::const_iterator StoreIterator;
        typedef std::pair<StoreIterator, StoreIterator> StorePair;

        D mean() {
            return std::accumulate(store.begin(), store.end(), D::zero())/store.size();
        }

        StorePair minMax() {
            return std::minmax_element(store.begin(), store.end());
        }

        double deviation() {
            const auto theMean = std::chrono::duration_cast<DoubleDuration>(mean());
            double accum = 0.;
            std::for_each(store.begin(), store.end(), [&](const D &dur) {
                        const auto val = std::chrono::duration_cast<DoubleDuration>(dur);
                        accum += (val.count() - theMean.count()) * (val.count() - theMean.count());
                    });

            return sqrt(accum / (store.size() - 1));
        }

        D median() {
            auto copy = store;
            std::nth_element(copy.begin(), copy.begin() + copy.size()/2, copy.end());
            return copy[copy.size()/2];
        }

        double relativeDeviation() {
            return deviation()/std::chrono::duration_cast<DoubleDuration>(mean()).count();
        }

        std::string unit() {
            if (Period::den / 1000000000 == 1)
                return "nanoseconds";
            else if (Period::den / 1000000 == 1)
                return "microseconds";
            else if (Period::den / 1000 == 1)
                return "milliseconds";
            return "unknown";
        }

        std::string toString()
        {
            std::stringstream stream;
            const auto minmax = minMax();
            stream.precision(3);
            stream << std::fixed << description << "\n" <<
                      "Object size(KB):    " << objectSize/1024 << "\n" <<
                      "Total hits number:  " << store.size() << "\n" <<
                      "Min:                " << minmax.first->count() << "\n" <<
                      "Max:                " << minmax.second->count() << "\n" <<
                      "Mean:               " << mean().count() << "\n" <<
                      "Median:             " << median().count() << "\n" <<
                      "Deviation:          " << deviation() << "\n" <<
                      "Relative deviation: " << relativeDeviation() << "\n" <<
                      "Slices:             " << numberOfSlices<< "\n" <<
                      "mean/Slice count:   " << std::chrono::duration_cast<DoubleDuration>(mean()).count()/numberOfSlices << "\n";
            return stream.str();
        }

        int size() const { return store.size(); }

        void takeObjectInfo(const int slices, const int objSize) {
            if (numberOfSlices != -1)
                return;
            numberOfSlices = slices;
            objectSize = objSize;
        }

        Store store;
        const char *description;
        int numberOfSlices;
        int objectSize;
};

template<class D>
class GenericProfiler
{
    public:

        GenericProfiler(const char *method, const int interval) :
            times("Total time"),
            cpuTimes("CPU time"),
            methodName(method),
            printStatInterval(interval) {}

        void start(TimePoint &start)
        {
            start.timePoint = std::chrono::steady_clock::now();
            start.cpuPoint = clock();
        }

        void stop(const TimePoint &start)
        {
            using CpuDuration = std::chrono::duration<int, std::ratio<1, CLOCKS_PER_SEC> >;
            TimePoint end;
            end.timePoint = std::chrono::steady_clock::now();
            end.cpuPoint = clock();

            const auto cpuTicksElapsed = CpuDuration(end.cpuPoint - start.cpuPoint);
            const auto cpuElapsed = std::chrono::duration_cast<D>(cpuTicksElapsed);
            const auto timeElapsed = std::chrono::duration_cast<D>(end.timePoint - start.timePoint);
            cpuTimes.store.push_back(cpuElapsed);
            times.store.push_back(timeElapsed);
        }

        bool needPrintStat() { return times.size() && !(times.size() % printStatInterval); }
        void takeObjectInfo(const int slices, const int objSize) {
            times.takeObjectInfo(slices, objSize);
            cpuTimes.takeObjectInfo(slices, objSize);
        }

        std::string toString() {
            std::stringstream stream;
            stream << "\nTime statistics(" << times.unit() << ") for " << methodName << ":\n\n" <<
                times.toString() << "\n" << cpuTimes.toString();
            return stream.str();
        }


        Durations<D> times;
        Durations<D> cpuTimes;
        std::string methodName;
        int printStatInterval;
};

template<class T>
class GenericProfilerScope
{
    public:
        GenericProfilerScope(T *mark) : profiler(mark)
        {
            profiler->start(beg);
        }

        ~GenericProfilerScope() {
            profiler->stop(beg);
        }

        TimePoint beg;
        T *profiler;
};

typedef std::chrono::duration<int, Period> Duration;
typedef GenericProfiler<Duration> Profiler;
typedef GenericProfilerScope<Profiler> ProfilerScope;

#endif

