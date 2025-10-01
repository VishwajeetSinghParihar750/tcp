#include <memory>
#include "tcp.hpp"
#include "ip.hpp"
#include "tun_device.hpp"

int main()
{

    tun_device tun{}; // default setup

    ip ip_interface(std::make_shared<tcp::ip_facing_input_buffer>());
    ip_interface.parse_incoming_ipv4_packets(tun.fd());
}