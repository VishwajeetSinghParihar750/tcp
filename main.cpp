#include <memory>
#include "tcp.hpp"
#include "tun_device.hpp"
#include "ipv4.hpp"

int main()
{
    ipv4::process_packets();
}