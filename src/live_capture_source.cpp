// src/live_capture_source.cpp
#include "live_capture_source.h"
#include "packet_parser.h" // for RawPacket definition
#include <cstring>

namespace PacketAnalyzer {

LiveCaptureSource::LiveCaptureSource() = default;

LiveCaptureSource::~LiveCaptureSource() {
    close();
}

bool LiveCaptureSource::open(const std::string &interface_name, const std::string &bpf_filter) {
    // Find the device
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf_) == -1) {
        std::cerr << "Error finding devices: " << errbuf_ << std::endl;
        return false;
    }
    // Verify the requested interface exists
    bool found = false;
    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
        if (d->name && interface_name == d->name) {
            found = true;
            break;
        }
    }
    pcap_freealldevs(alldevs);
    if (!found) {
        std::cerr << "Interface not found: " << interface_name << std::endl;
        return false;
    }

    // Open live capture
    handle_ = pcap_open_live(interface_name.c_str(), 65535, 1, 1000, errbuf_);
    if (!handle_) {
        std::cerr << "Failed to open interface: " << errbuf_ << std::endl;
        return false;
    }

    // Apply BPF filter if provided
    if (!bpf_filter.empty()) {
        struct bpf_program fp;
        if (pcap_compile(handle_, &fp, bpf_filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Failed to compile filter: " << pcap_geterr(handle_) << std::endl;
            pcap_close(handle_);
            handle_ = nullptr;
            return false;
        }
        if (pcap_setfilter(handle_, &fp) == -1) {
            std::cerr << "Failed to set filter: " << pcap_geterr(handle_) << std::endl;
            pcap_freecode(&fp);
            pcap_close(handle_);
            handle_ = nullptr;
            return false;
        }
        pcap_freecode(&fp);
    }
    stopped_ = false;
    return true;
}

void LiveCaptureSource::close() {
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
    stopped_ = true;
}

void LiveCaptureSource::stopCapture() {
    stopped_ = true;
    if (handle_) {
        pcap_breakloop(handle_);
    }
}

bool LiveCaptureSource::getNextPacket(RawPacket &packet) {
    if (!handle_ || stopped_) return false;
    struct pcap_pkthdr *header;
    const u_char *data;
    int ret = pcap_next_ex(handle_, &header, &data);
    if (ret == 1) { // packet read
        packet.data.assign(data, data + header->caplen);
        packet.timestamp_sec = header->ts.tv_sec;
        packet.timestamp_usec = header->ts.tv_usec;
        return true;
    }
    // ret == 0 timeout, ret == -1 error, ret == -2 breakloop
    return false;
}

} // namespace PacketAnalyzer
