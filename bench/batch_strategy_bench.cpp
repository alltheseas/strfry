// Benchmark: Drain vs Timeout batching strategies for signature verification
//
// Demonstrates why the natural "drain" pattern (pop_all) is superior to
// timeout-based batching for signature verification.
//
// Compile: g++ -std=c++20 -O2 -pthread bench.cpp -o bench

#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <vector>
#include <chrono>
#include <algorithm>
#include <numeric>
#include <iomanip>

using namespace std::chrono;
using Clock = steady_clock;

// ============================================================
// Configuration (matching real-world values)
// ============================================================

constexpr auto SINGLE_VERIFY_TIME = microseconds(50);  // ~50μs per schnorr verify
constexpr auto BATCH_TIMEOUT = milliseconds(2);        // PR uses 2ms timeout
constexpr size_t MAX_BATCH_SIZE = 53;                  // libsecp256k1 limit

// Simulates verification time. Batch gives ~2x speedup (log n factor)
microseconds simulate_verify(size_t batch_size) {
    if (batch_size == 0) return microseconds(0);
    double speedup = (batch_size == 1) ? 1.0 : 1.0 + std::log(batch_size) / 10.0;
    auto total = SINGLE_VERIFY_TIME * batch_size;
    return duration_cast<microseconds>(duration<double>(total) / speedup);
}

// ============================================================
// Simple thread-safe queue (like hoytech::protected_queue)
// ============================================================

template<typename T>
struct SimpleQueue {
    std::deque<T> items;
    std::mutex mtx;
    std::condition_variable cv;
    bool closed = false;

    void push(T item) {
        std::lock_guard<std::mutex> lk(mtx);
        items.push_back(std::move(item));
        cv.notify_one();
    }

    // Block until at least one item, then return all (drain pattern)
    std::deque<T> pop_all() {
        std::unique_lock<std::mutex> lk(mtx);
        cv.wait(lk, [&] { return !items.empty() || closed; });
        return std::move(items);
    }

    // Block for first item, then wait up to timeout for more
    std::deque<T> pop_with_timeout(microseconds timeout) {
        std::unique_lock<std::mutex> lk(mtx);
        cv.wait(lk, [&] { return !items.empty() || closed; });
        if (closed && items.empty()) return {};

        auto deadline = Clock::now() + timeout;
        while (items.size() < MAX_BATCH_SIZE && Clock::now() < deadline) {
            cv.wait_until(lk, deadline);
        }
        return std::move(items);
    }

    void close() {
        std::lock_guard<std::mutex> lk(mtx);
        closed = true;
        cv.notify_all();
    }
};

struct Event {
    Clock::time_point arrived_at;
};

// ============================================================
// BASELINE: No batching (current strfry without batch PR)
// Verify each event individually as it arrives
// ============================================================

std::vector<microseconds> run_no_batch_strategy(SimpleQueue<Event>& queue) {
    std::vector<microseconds> latencies;

    while (true) {
        auto batch = queue.pop_all();
        if (batch.empty()) break;

        // Verify each event individually (no batch speedup)
        for (const auto& event : batch) {
            std::this_thread::sleep_for(SINGLE_VERIFY_TIME);  // 50μs each
            auto done = Clock::now();
            latencies.push_back(duration_cast<microseconds>(done - event.arrived_at));
        }
    }

    return latencies;
}

// ============================================================
// STRATEGY 1: Timeout-based (like the PR)
// Wait up to 2ms to accumulate a batch
// ============================================================

std::vector<microseconds> run_timeout_strategy(SimpleQueue<Event>& queue) {
    std::vector<microseconds> latencies;

    while (true) {
        auto batch = queue.pop_with_timeout(BATCH_TIMEOUT);
        if (batch.empty()) break;

        // Process in chunks of MAX_BATCH_SIZE (same as drain)
        while (!batch.empty()) {
            size_t chunk_size = std::min(batch.size(), MAX_BATCH_SIZE);

            std::this_thread::sleep_for(simulate_verify(chunk_size));
            auto done = Clock::now();

            for (size_t i = 0; i < chunk_size; i++) {
                latencies.push_back(duration_cast<microseconds>(done - batch.front().arrived_at));
                batch.pop_front();
            }
        }
    }

    return latencies;
}

// ============================================================
// STRATEGY 2: Drain-based (natural batching like strfry writer)
// Take whatever is available immediately, no waiting
// ============================================================

std::vector<microseconds> run_drain_strategy(SimpleQueue<Event>& queue) {
    std::vector<microseconds> latencies;

    while (true) {
        auto batch = queue.pop_all();  // This is the key difference!
        if (batch.empty()) break;

        // Process in chunks of MAX_BATCH_SIZE
        while (!batch.empty()) {
            size_t chunk_size = std::min(batch.size(), MAX_BATCH_SIZE);

            std::this_thread::sleep_for(simulate_verify(chunk_size));
            auto done = Clock::now();

            for (size_t i = 0; i < chunk_size; i++) {
                latencies.push_back(duration_cast<microseconds>(done - batch.front().arrived_at));
                batch.pop_front();
            }
        }
    }

    return latencies;
}

// ============================================================
// Benchmark harness
// ============================================================

void run_benchmark(
    const char* name,
    size_t event_count,
    microseconds interval,
    std::vector<microseconds> (*strategy)(SimpleQueue<Event>&)
) {
    SimpleQueue<Event> queue;
    auto start = Clock::now();

    // Producer thread
    std::thread producer([&] {
        for (size_t i = 0; i < event_count; i++) {
            queue.push(Event{Clock::now()});
            if (interval.count() > 0) {
                std::this_thread::sleep_for(interval);
            }
        }
        queue.close();
    });

    // Consumer (verifier)
    auto latencies = strategy(queue);
    producer.join();
    auto total_time = duration_cast<microseconds>(Clock::now() - start);

    // Calculate stats
    auto sum = std::accumulate(latencies.begin(), latencies.end(), microseconds(0));
    auto avg = sum / latencies.size();
    auto [min_it, max_it] = std::minmax_element(latencies.begin(), latencies.end());
    double throughput = (double)event_count / (total_time.count() / 1'000'000.0);

    std::cout << "  " << std::left << std::setw(12) << name
              << " avg: " << std::setw(7) << std::right << avg.count() << "μs"
              << "  min: " << std::setw(6) << min_it->count() << "μs"
              << "  max: " << std::setw(7) << max_it->count() << "μs"
              << "  throughput: " << std::setw(7) << (int)throughput << "/s\n";
}

int main() {
    std::cout << "Batch Strategy Benchmark\n";
    std::cout << "Config: single_verify=50μs, timeout=2ms, max_batch=53\n";
    std::cout << "Latency: avg/min/max (μs) | Throughput: events/sec\n\n";

    std::cout << "LOW LOAD (1 event every 10ms, 50 events):\n";
    run_benchmark("NoBatch:", 50, milliseconds(10), run_no_batch_strategy);
    run_benchmark("Timeout:", 50, milliseconds(10), run_timeout_strategy);
    run_benchmark("Drain:", 50, milliseconds(10), run_drain_strategy);
    std::cout << "\n";

    std::cout << "MEDIUM LOAD (1 event every 500μs, 200 events):\n";
    run_benchmark("NoBatch:", 200, microseconds(500), run_no_batch_strategy);
    run_benchmark("Timeout:", 200, microseconds(500), run_timeout_strategy);
    run_benchmark("Drain:", 200, microseconds(500), run_drain_strategy);
    std::cout << "\n";

    std::cout << "HIGH LOAD (1000 events as fast as possible):\n";
    run_benchmark("NoBatch:", 1000, microseconds(0), run_no_batch_strategy);
    run_benchmark("Timeout:", 1000, microseconds(0), run_timeout_strategy);
    run_benchmark("Drain:", 1000, microseconds(0), run_drain_strategy);
    std::cout << "\n";

    std::cout << "BURST (100 events instant, simulating sync):\n";
    run_benchmark("NoBatch:", 100, microseconds(0), run_no_batch_strategy);
    run_benchmark("Timeout:", 100, microseconds(0), run_timeout_strategy);
    run_benchmark("Drain:", 100, microseconds(0), run_drain_strategy);
    std::cout << "\n";

    return 0;
}
