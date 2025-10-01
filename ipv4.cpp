#include "ipv4.hpp"
#include "tcp.hpp"
#include <cstring>
#include <arpa/inet.h>

namespace ipv4
{

    packet_buffer::packet_buffer(size_t capacity)
        : data_(new uint8_t[capacity]) {}

    packet_buffer::packet_buffer(const uint8_t *src, size_t len) : packet_buffer(len)
    {
        if (len < 20)
            throw parsing_error(PARSING_ERROR_TYPE::PACKET_TOO_SMALL);

        memcpy(data_.get(), src, len);
        len_ = len;
        compute_offsets_and_lengths();
    }

    void packet_buffer::compute_offsets_and_lengths()
    {
        ip_hdr_ = reinterpret_cast<header_t *>(data_.get());

        ip_hdr_size_ = (ip_hdr_->ver_and_hlen & 0x0F) * 4;

        if (ip_hdr_size_ < 20)
            throw parsing_error(PARSING_ERROR_TYPE::SANITY_CHECK_FAIL, "IP header too small");

        if (ip_hdr_size_ > 60)
            throw parsing_error(PARSING_ERROR_TYPE::SANITY_CHECK_FAIL, "IP header too large");

        if (ip_hdr_size_ > len_)
            throw parsing_error(PARSING_ERROR_TYPE::PACKET_TOO_SMALL, "IP header exceeds packet length");

        // save pointer to IP options if any
        if (ip_hdr_size_ > 20)
            ip_options_ = data_.get() + 20;

        uint8_t version = (ip_hdr_->ver_and_hlen >> 4) & 0x0F;
        if (version != 4)
            throw parsing_error(PARSING_ERROR_TYPE::NOT_IPV4, "Not IPv4");

        uint16_t total_len = ntohs(ip_hdr_->total_len);
        if (total_len < ip_hdr_size_)
            throw parsing_error(PARSING_ERROR_TYPE::SANITY_CHECK_FAIL, "Total length smaller than header");

        if (total_len > len_)
            throw parsing_error(PARSING_ERROR_TYPE::PACKET_TOO_SMALL, "Total length exceeds buffer size");

        // tcp header immediately follows IP header (IP options included)
        tcp_hdr_ = reinterpret_cast<tcp::header_t *>(data_.get() + ip_hdr_size_);

        ip_payload_ = reinterpret_cast<uint8_t *>(tcp_hdr_);
        ip_payload_size_ = total_len - ip_hdr_size_;

        // calculate TCP payload
        tcp_payload_ = reinterpret_cast<uint8_t *>(tcp_hdr_ + tcp_hdr_size_);
        tcp_payload_size_ = ip_payload_size_ - tcp_hdr_size_;

        if (tcp_payload_size_ + tcp_hdr_size_ != ip_payload_size_)
            throw parsing_error(PARSING_ERROR_TYPE::SANITY_CHECK_FAIL, "TCP payload size mismatch");
    }

} // namespace ipv4
