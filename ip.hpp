#pragma once
#include "ipv4.hpp"
#include "tcp.hpp"
#include <memory>

class ip // this is being implemented only for IPv4 with no intentions of adding IPv6, hence tight coupling
{
    std::shared_ptr<tcp::ip_facing_input_buffer> tcp_input_buffer;

public:
    ip(std::shared_ptr<tcp::ip_facing_input_buffer> tcp_input_buffer);

    void forward_segment_to_tcp(std::unique_ptr<ipv4::packet_buffer> payload);

    void perform_header_checksum(const std::unique_ptr<ipv4::packet_buffer> &packet);

    void parse_incoming_ipv4_packets(int fd); // can overload if want to use some other input medium
};
