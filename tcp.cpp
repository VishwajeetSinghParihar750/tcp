#include <arpa/inet.h>
#include "tcp.hpp"
#include "logger.hpp"

namespace tcp
{

    void host_to_network_header(header_t *hdr, bool zero_checksum = false)
    {
        hdr->source_port_addr = htons(hdr->source_port_addr);
        hdr->dest_port_addr = htons(hdr->dest_port_addr);
        hdr->seq_no = htonl(hdr->seq_no);
        hdr->ack_no = htonl(hdr->ack_no);
        hdr->hlen_reserved_control = htons(hdr->hlen_reserved_control);
        hdr->window_size = htons(hdr->window_size);
        hdr->checksum = zero_checksum ? 0 : htons(hdr->checksum);
        hdr->urgent_pointer = htons(hdr->urgent_pointer);
    }

    void network_to_host_header(header_t *hdr)
    {
        hdr->source_port_addr = ntohs(hdr->source_port_addr);
        hdr->dest_port_addr = ntohs(hdr->dest_port_addr);
        hdr->seq_no = ntohl(hdr->seq_no);
        hdr->ack_no = ntohl(hdr->ack_no);
        hdr->hlen_reserved_control = ntohs(hdr->hlen_reserved_control);
        hdr->window_size = ntohs(hdr->window_size);
        hdr->checksum = ntohs(hdr->checksum);
        hdr->urgent_pointer = ntohs(hdr->urgent_pointer);
    }

    // uint16_t get_checksum(const segment_buffer &seg)
    // {
    //     uint32_t sum = 0;
    //     uint32_t src_ip = htonl(seg.source_ip());
    //     uint32_t dst_ip = htonl(seg.destination_ip());
    //     uint8_t protocol = 6;
    //     uint16_t tcp_len = htons(seg.size());

    //     sum += (src_ip >> 16) & 0xFFFF;
    //     if (sum & 0x10000)
    //         sum = (sum & 0xFFFF) + 1;

    //     sum += src_ip & 0xFFFF;
    //     if (sum & 0x10000)
    //         sum = (sum & 0xFFFF) + 1;

    //     sum += (dst_ip >> 16) & 0xFFFF;
    //     if (sum & 0x10000)
    //         sum = (sum & 0xFFFF) + 1;

    //     sum += dst_ip & 0xFFFF;
    //     if (sum & 0x10000)
    //         sum = (sum & 0xFFFF) + 1;

    //     sum += protocol;
    //     if (sum & 0x10000)
    //         sum = (sum & 0xFFFF) + 1;

    //     sum += tcp_len;
    //     if (sum & 0x10000)
    //         sum = (sum & 0xFFFF) + 1;

    //     uint8_t *data = seg.get_data();
    //     size_t total_len = seg.size();

    //     for (size_t i = 0; i < total_len; i += 2)
    //     {
    //         uint16_t word = (data[i] << 8) | data[i + 1];
    //         sum += htons(word);
    //         if (sum & 0x10000)
    //             sum = (sum & 0xFFFF) + 1;
    //     }

    //     return static_cast<uint16_t>(sum);
    // }

    // void verify_checksum(uint32_t s_ip, uint32_t d_ip, uint8_t *segment, uint16_t size)
    // {

    //     uint32_t sum = 0;
    //     header_t *hdr = reinterpret_cast<header_t *>(segment);
    //     hdr->checksum = 0;

    //     std::string hex_bytes;
    //     for (int i = 0; i < 40 && i < size; i++)
    //     {
    //         char buf[4];
    //         snprintf(buf, sizeof(buf), "%02X", segment[i]);
    //         hex_bytes += buf;
    //         if (i % 2 == 1)
    //             hex_bytes += " "; // space every 2 bytes
    //     }
    //     logger::getInstance().logInfo("First 40 bytes:", hex_bytes);

    //     auto wrap = [&]
    //     {
    //         if (sum > 0xFFFF)
    //             sum = (sum & 0xFFFF) + 1;
    //     };

    //     // Pseudo-header (in NETWORK byte order)
    //     sum += (htonl(s_ip) >> 16) & 0xFFFF;
    //     wrap();
    //     sum += htonl(s_ip) & 0xFFFF;
    //     wrap();
    //     sum += (htonl(d_ip) >> 16) & 0xFFFF;
    //     wrap();
    //     sum += htonl(d_ip) & 0xFFFF;
    //     wrap();

    //     sum += htons(6); //
    //     wrap();
    //     sum += htons(size); //

    //     for (auto i = 0; i < size; i += 2)
    //     {
    //         sum += (segment[i] << 8) + (i < size - 1 ? segment[i + 1] : 0);
    //         wrap();
    //     }

    //     // Final result should be 0xFFFF
    //     logger::getInstance().logInfo("checksum result: ", sum);

    //     // if (result != 0xFFFF)
    //     // {
    //     //     throw parsing_error(PARSING_ERROR_TYPE::CHECKSUM_FAIL);
    //     // }
    // }

    // void hton_and_add_checksum(segment_buffer &seg)
    // {
    //     host_to_network_header(seg.header(), true);
    //     uint16_t checksum = get_checksum(seg);
    //     seg.header()->checksum = checksum;
    //     network_to_host_header(seg.header());
    // }

} // namespace tcp
namespace tcp
{

    segment_buffer::segment_buffer(uint32_t src_ip_addr, uint32_t dst_ip_addr, uint8_t *dataptr, size_t sz) : data(new uint8_t[sz]), len(sz)
    {
        if (len < MIN_HEADER_LEN)
            throw parsing_error(PARSING_ERROR_TYPE::SEGMENT_TOO_SMALL);

        src_ip = src_ip_addr, dest_ip = dst_ip_addr;

        memcpy(data.get(), dataptr, sz);

        parse_network_segment();
    }

    void segment_buffer::parse_network_segment()
    {
        tcp_hdr = reinterpret_cast<header_t *>(data.get());

        network_to_host_header(tcp_hdr);

        tcp_hdr_size = (tcp_hdr->hlen_reserved_control >> 12) * 4;
        {
            if (tcp_hdr_size < MIN_HEADER_LEN)
                throw parsing_error(PARSING_ERROR_TYPE::HEADER_TOO_SMALL);
            else if (tcp_hdr_size > MAX_HEADER_LEN)
                throw parsing_error(PARSING_ERROR_TYPE::HEADER_TOO_BIG);
            else if (tcp_hdr_size > len)
                throw parsing_error(PARSING_ERROR_TYPE::SANITY_CHECK_FAIL);
        }
        tcp_options = data.get() + OPTIONS_OFFSET;
        tcp_payload_size = len - tcp_hdr_size;
        tcp_payload = data.get() + tcp_hdr_size;
    }

    void process_segment(uint32_t src_ip, uint32_t dest_ip, uint8_t *segment, uint16_t size)
    {
        try
        {
            auto seg = std::make_unique<segment_buffer>(src_ip, dest_ip, segment, size);

            // skip checksum for now

            logger::getInstance().logInfo("SEGMENT ACCEPTED SUCCESSFULLY ");
        }
        catch (const parsing_error &e)
        {
            logger::getInstance().logError(parsing_error_to_string(e.error));
        }
    }

} // namespace tcp