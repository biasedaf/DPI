#pragma once

#include "packet_source.h"

#include <string>
#include <pcap.h>

namespace PacketAnalyzer {

// LiveCaptureSource captures packets from a network interface using libpcap/Npcap.
class LiveCaptureSource : public PacketSource {
public:
    LiveCaptureSource();
    ~LiveCaptureSource();

    // Open a live capture on the given interface with optional BPF filter.
    // Returns true on success.
    bool open(const std::string &interface_name, const std::string &bpf_filter = "");

    // Close the capture and release resources.
    void close();

    // Retrieve the next packet. Returns true if a packet was captured.
    bool getNextPacket(RawPacket &packet) override;

    // Stop capture (used for graceful shutdown).
    void stopCapture();

private:
    pcap_t *handle_ = nullptr;
    char errbuf_[PCAP_ERRBUF_SIZE]{};
    bool stopped_ = false;
};

} // namespace PacketAnalyzer
