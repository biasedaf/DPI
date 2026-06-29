#pragma once

#include "packet_source.h"
#include "pcap_reader.h"

namespace PacketAnalyzer {

// PcapFileSource implements PacketSource by delegating to the existing PcapReader.
class PcapFileSource : public PacketSource {
public:
    PcapFileSource() = default;
    ~PcapFileSource();

    // Open a PCAP file for reading. Returns true on success.
    bool open(const std::string &filename) override;

    // Close the file.
    void close() override;

    // PacketSource implementation: retrieve next packet.
    bool getNextPacket(RawPacket &packet) override;

private:
    PcapReader reader_; // reuse existing reader implementation
};

} // namespace PacketAnalyzer
