#pragma once

#include <atomic>
#include <thread>
#include <chrono>
#include <iostream>

#include "types.h"

namespace PacketAnalyzer {

class StatsReporter {
public:
    // Constructor takes reference to shared DPIStats and atomic stop flag.
    StatsReporter(DPI::DPIStats& stats, const std::atomic<bool>& keepRunning)
        : stats_(stats), keep_running_(keepRunning), stop_requested_(false) {
        reporter_thread_ = std::thread(&StatsReporter::run, this);
    }

    // Destructor ensures thread is joined.
    ~StatsReporter() {
        stop_requested_ = true;
        if (reporter_thread_.joinable()) {
            reporter_thread_.join();
        }
    }

private:
    void run() {
        while (!stop_requested_) {
            // Print stats every second while main is running.
            if (keep_running_) {
                printStats();
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    void printStats() const {
        const DPI::DPIStats& s = stats_;
        std::cout << "\n--- DPI Statistics (1s interval) ---\n";
        std::cout << "  Total packets:       " << s.total_packets.load() << "\n";
        std::cout << "  Total bytes:         " << s.total_bytes.load() << "\n";
        std::cout << "  Forwarded packets:   " << s.forwarded_packets.load() << "\n";
        std::cout << "  Dropped packets:     " << s.dropped_packets.load() << "\n";
        std::cout << "  TCP packets:        " << s.tcp_packets.load() << "\n";
        std::cout << "  UDP packets:        " << s.udp_packets.load() << "\n";
        std::cout << "  Other packets:       " << s.other_packets.load() << "\n";
        std::cout << "  Active connections: " << s.active_connections.load() << "\n";
        std::cout << "-----------------------------------\n";
    }

    DPI::DPIStats& stats_;
    const std::atomic<bool>& keep_running_; // reference to global keep_running flag
    std::atomic<bool> stop_requested_;
    std::thread reporter_thread_;
};

} // namespace PacketAnalyzer
