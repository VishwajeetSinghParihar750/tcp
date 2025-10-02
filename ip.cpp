#include "ip.hpp"
#include "logger.hpp"
#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>

ip::ip(std::shared_ptr<tcp::ip_facing_input_buffer> tcp_input_buffer) : tcp_input_buffer(tcp_input_buffer) {}

void ip::forward_segment_to_tcp(std::unique_ptr<ipv4::packet_buffer> payload)
{
    tcp_input_buffer->write(payload->ip_payload(), payload->ip_payload_size());
}

void ip::perform_header_checksum(const std::unique_ptr<ipv4::packet_buffer> &packet)
{
    ipv4::header_t *header = packet->ip_header();
    uint8_t *options = packet->ip_options();

    uint32_t checksum = 0;
    auto wrap = [&]
    {
        if (checksum & (1 << 16))
        {
            checksum++;
            checksum ^= (1 << 16);
        }
    };

    checksum += (header->ver_and_hlen << 8) + header->service_type;
    checksum += htons(header->total_len);
    wrap();
    checksum += htons(header->identification);
    wrap();
    checksum += htons(header->flags_and_fragmentation_offset);
    wrap();
    checksum += (header->time_to_live << 8) + header->protocol;
    wrap();
    checksum += htons(header->header_checksum);
    wrap();
    checksum += (htonl(header->source_ip) >> 16) & 0xFFFF;
    wrap();
    checksum += htonl(header->source_ip) & 0xFFFF;
    wrap();
    checksum += (htonl(header->dest_ip) >> 16) & 0xFFFF;
    wrap();
    checksum += htonl(header->dest_ip) & 0xFFFF;
    wrap();

    size_t opt_sz = packet->ip_header_size() - 20;

    for (int i = 0; i < opt_sz / 2; i++)
    {
        checksum += (options[2 * i] << 8) + options[2 * i + 1];
        wrap();
    }

    if (checksum != 0xFFFF)
        throw ipv4::parsing_error(ipv4::PARSING_ERROR_TYPE::CHECKSUM_FAIL);
}

void ip::parse_incoming_ipv4_packets(int fd) // can overload if want to use some other input medium
{
    uint8_t buffer[1500]; // MTU = 1500 - tun is packet oriented, will give one full packet per read

    size_t nread = 0;
    while ((nread = read(fd, buffer, sizeof(buffer))) > 0)
    {
        try
        {
            auto pf = std::make_unique<ipv4::packet_buffer>(buffer, nread);
            perform_header_checksum(pf);

            // 🔮🔮  would add reassembly here in future

            logger::getInstance().logInfo("ip packet size ", pf->size()); ////////////////////////////////////

            forward_segment_to_tcp(std::move(pf)); //

            logger::getInstance().logInfo("PACKET FORWARDED TO TCP ");
        }
        catch (ipv4::parsing_error e) // any other exception should cause shutdown
        {
            logger::getInstance().logError(e.what(), ipv4::parsing_error_to_string(e.error));
        }
    }
    if (nread == -1)
        throw std::runtime_error("nread = -1 " + std::string(strerror(errno)));
}
