#pragma once

#include "types.h"

namespace PacketAnalyzer {

// Abstract interface for packet sources. Implementations provide a method to retrieve the next RawPacket.
class PacketSource {
public:
    virtual ~PacketSource() = default;
    // Returns true if a packet was retrieved and stored in `packet`.
    virtual bool getNextPacket(RawPacket &packet) = 0;
};

} // namespace PacketAnalyzer
