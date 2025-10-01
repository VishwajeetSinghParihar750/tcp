#pragma once
#include <vector>
#include <memory>
#include "ip.hpp"

namespace tcp
{

    struct __attribute__((packed)) header_t
    {
        uint16_t source_port_addr, dest_port_addr;
        uint32_t seq_no, ack_no;
        uint16_t hlen_reserved_control, window_size;
        uint16_t checksum, urgent_pointer;
    };

    struct __attribute__((packed)) segment_t
    {
        header_t header;
        uint8_t options_padding_payload[];
    };

    class ip_facing_input_buffer
    {
        std::vector<std::unique_ptr<ipv4::packet_buffer>> segs;

    public:
        void write(std::unique_ptr<ipv4::packet_buffer> pf)
        {
            segs.push_back(std::move(pf));
        }
    };

} // namespace tcp
