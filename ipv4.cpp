#include <cstring>
#include <arpa/inet.h>
#include "ipv4.hpp"
#include "tcp.hpp"
#include "tun_device.hpp"

namespace ipv4
{

    packet_buffer::packet_buffer(size_t capacity) : len_(capacity), data_(new uint8_t[capacity]) {}

    packet_buffer::packet_buffer(const uint8_t *src, size_t len) : packet_buffer(len)
    {
        if (len < 20)
            throw parsing_error(PARSING_ERROR_TYPE::PACKET_TOO_SMALL);

        memcpy(data_.get(), src, len);
        compute_offsets_and_lengths();
    }

    packet_buffer::packet_buffer(const uint32_t src_ip, const uint32_t des_ip, uint8_t *segment, size_t segment_size) : packet_buffer(segment_size + 20)
    {

        ip_hdr_ = reinterpret_cast<header_t *>(data_.get());
        memcpy(data_.get() + 20, segment, segment_size);

        //
        ip_hdr_->ver_and_hlen = 0x45;
        ip_hdr_->service_type = 0x00;
        ip_hdr_->total_len = htons(segment_size + 20);

        //
        ip_hdr_->identification = 0x0000;
        ip_hdr_->flags_and_fragmentation_offset = 0x0000; // laterrrr
        //
        ip_hdr_->time_to_live = 0x40; // 64
        ip_hdr_->protocol = 0x06;
        ip_hdr_->header_checksum = 0x0000; // laterrr
        //

        ip_hdr_->source_ip = htonl(src_ip);
        ip_hdr_->dest_ip = htonl(des_ip);

        compute_offsets_and_lengths();
    }

    void packet_buffer::compute_offsets_and_lengths()
    {
        ip_hdr_ = reinterpret_cast<header_t *>(data_.get());

        ip_hdr_size_ = (ip_hdr_->ver_and_hlen & 0x0F) * 4;

        {
            if (ip_hdr_size_ < 20)
                throw parsing_error(PARSING_ERROR_TYPE::SANITY_CHECK_FAIL, "IP header too small");
            if (ip_hdr_size_ > 60)
                throw parsing_error(PARSING_ERROR_TYPE::SANITY_CHECK_FAIL, "IP header too large");
            if (ip_hdr_size_ > len_)
                throw parsing_error(PARSING_ERROR_TYPE::PACKET_TOO_SMALL, "IP header exceeds packet length");
        }

        // save pointer to ip options if any
        if (ip_hdr_size_ > 20)
            ip_options_ = data_.get() + 20;

        uint8_t version = (ip_hdr_->ver_and_hlen >> 4) & 0x0F;
        if (version != 4)
            throw parsing_error(PARSING_ERROR_TYPE::NOT_IPV4, "Not IPv4");

        uint16_t total_len = ntohs(ip_hdr_->total_len);

        {
            if (total_len < ip_hdr_size_)
                throw parsing_error(PARSING_ERROR_TYPE::SANITY_CHECK_FAIL, "Total length smaller than header");
            if (total_len > len_)
                throw parsing_error(PARSING_ERROR_TYPE::PACKET_TOO_SMALL, "Total length exceeds buffer size");
        }

        ip_payload_ = data_.get() + ip_hdr_size_;
        ip_payload_size_ = total_len - ip_hdr_size_;
    }

    void send_segment_tcp(std::unique_ptr<packet_buffer> payload)
    {
        tcp::process_segment(payload->ip_header()->dest_ip, payload->ip_header()->source_ip, payload->ip_payload(), payload->ip_payload_size());
    }

    uint16_t get_checksum(const std::unique_ptr<packet_buffer> &packet)
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

        uint16_t opt_sz = packet->ip_header_size() - 20;

        for (auto i = 0; i < opt_sz / 2; i++)
        {
            checksum += (options[2 * i] << 8) + options[2 * i + 1];
            wrap();
        }

        return checksum;
    }

    void verify_checksum(const std::unique_ptr<packet_buffer> &packet)
    {
        if (get_checksum(packet) != 0xFFFF)
            throw ipv4::parsing_error(ipv4::PARSING_ERROR_TYPE::CHECKSUM_FAIL);
    }

    void add_checksum(const std::unique_ptr<packet_buffer> &packet)
    {
        packet->ip_header()->header_checksum = 0x0000;
        uint16_t checksum = get_checksum(packet);
        packet->ip_header()->header_checksum = 0xFFFF ^ checksum;
    }

    std::pair<uint8_t *, int> get_packet()
    {
        static uint8_t buffer[1500]; // MTU = 1500 - tun is packet oriented, will give one full packet per read
        int nread = 0;

        nread = read(tunnel_device_instance().fd(), buffer, sizeof(buffer));

        return {buffer, nread};
    }

    void process_packets() //
    {

        while (true)
        {
            auto [buffer, nread] = get_packet();

            if (nread > 0)
            {
                try
                {
                    auto pf = std::make_unique<ipv4::packet_buffer>(buffer, nread);

                    verify_checksum(pf);

                    // 🔮🔮  would add reassembly here in future

                    send_segment_tcp(std::move(pf));
                }
                catch (const parsing_error &e) // any other exception should cause shutdown
                {
                    logger::getInstance().logError(e.what(), ipv4::parsing_error_to_string(e.error));
                }
            }

            else if (nread == -1)
                throw std::runtime_error("nread = -1 " + std::string(strerror(errno)));
        }
    }

    void send_packet(uint8_t *packet, size_t packet_size)
    {
        if (write(tunnel_device_instance().fd(), packet, packet_size) < (ssize_t)packet_size)
            throw std::runtime_error("INCOMPLETE PACKET WRITE ");
    }

    void process_segment(uint8_t *segment, size_t segment_size, uint32_t src_ip, uint32_t dest_ip)
    {

        try
        {
            auto pf = std::make_unique<ipv4::packet_buffer>(src_ip, dest_ip, segment, segment_size);

            // 🔮🔮 would add fragmenation here in future

            add_checksum(pf);

            send_packet(pf->data(), pf->size());
        }
        catch (const parsing_error &e) // any other exception should cause shutdown
        {
            logger::getInstance().logError(e.what(), ipv4::parsing_error_to_string(e.error));
        }
    }

} // namespace ipv4
