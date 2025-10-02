#pragma once
#include <memory>
#include <unistd.h>
#include <cstdint>
#include <arpa/inet.h>
#include <memory.h>
#include <queue>
#include <exception>
#include <string>
#include <algorithm>
#include "logger.hpp"
#include "tun_device.hpp"

namespace tcp
{
    class ip_facing_input_buffer;
    class header_t;
}

namespace ipv4
{

    struct __attribute__((packed)) header_t
    {
        uint8_t ver_and_hlen; // 4, 4 [ this headerlen is in word count ie 4 bytes ]
        uint8_t service_type;
        uint16_t total_len;
        uint16_t identification;
        uint16_t flags_and_fragmentation_offset; // 3, 13
        uint8_t time_to_live;
        uint8_t protocol;
        uint16_t header_checksum;
        uint32_t source_ip;
        uint32_t dest_ip;
    };

    struct __attribute__((packed)) packet_t // not even needed really, i wil just work with packet_buffer
    {
        header_t header;
        uint8_t options_and_payload[]; // this will have both options and payload
    };

    //

    enum class PARSING_ERROR_TYPE
    {
        CHECKSUM_FAIL,
        PACKET_TOO_SMALL,
        PARSER_ERROR,
        SANITY_CHECK_FAIL,
        NOT_IPV4
    };

    inline std::string parsing_error_to_string(PARSING_ERROR_TYPE e)
    {
        switch (e)
        {
        case PARSING_ERROR_TYPE::PACKET_TOO_SMALL:
            return "IPV4_PACKET_TOO_SMALL";
        case PARSING_ERROR_TYPE::CHECKSUM_FAIL:
            return "IPV4_CHECKSUM FAIL";
        case PARSING_ERROR_TYPE::NOT_IPV4:
            return "IPV4_NOT IPV4";
        case PARSING_ERROR_TYPE::PARSER_ERROR:
            return "IPV4_PARSER_ERROR";
        case PARSING_ERROR_TYPE::SANITY_CHECK_FAIL:
            return "IPV4_SANITY_CHECK_FAIL";
        default:
            return "IPV4_UNKNOWN_ERROR";
        }
    }

    class parsing_error : public std::runtime_error
    {
    public:
        PARSING_ERROR_TYPE error;
        parsing_error(PARSING_ERROR_TYPE err, const char *msg = "") : runtime_error(msg), error(err) {}
    };

    class packet_buffer // ℹ️ this will be referred to as "pf"
    {
        uint16_t len_{0};

        std::unique_ptr<uint8_t[]> data_;

        // precomputed pointers and sizes
        header_t *ip_hdr_{nullptr};
        uint8_t *ip_options_{nullptr};
        size_t ip_hdr_size_{0};
        uint8_t *ip_payload_{nullptr};
        size_t ip_payload_size_{0};

        explicit packet_buffer(size_t capacity);
        void compute_offsets_and_lengths();

    public:
        packet_buffer(const uint8_t *src, size_t len); // this if u give full paceket as input

        packet_buffer(const uint32_t src_ip, const uint32_t des_ip, uint8_t *segment, size_t segment_size); // for making from a recieved segment

        uint8_t *data() noexcept { return data_.get(); }
        size_t size() const noexcept { return len_; }

        header_t *ip_header() { return ip_hdr_; }     // header struct doesn't include options
        uint8_t *ip_options() { return ip_options_; } // pointer to IP options (if any)
        uint8_t *ip_payload() { return ip_payload_; } // payload includes TCP header + TCP payload

        size_t ip_header_size() const { return ip_hdr_size_; } // includes options
        size_t ip_payload_size() const { return ip_payload_size_; }
    };

    //
    inline const tun_device &tunnel_device_instance()
    {
        static tun_device tun_device_instance{};
        return tun_device_instance;
    }

    uint16_t get_checksum(const std::unique_ptr<ipv4::packet_buffer> &packet);
    void verify_checksum(const std::unique_ptr<ipv4::packet_buffer> &packet);
    void add_checksum(const std::unique_ptr<ipv4::packet_buffer> &packet);

    std::pair<uint8_t *, int> get_packet();
    void process_packets(); // can overload if want to use some other input mediumh
    void send_segment_tcp(std::unique_ptr<ipv4::packet_buffer> payload);
    void process_segment(uint8_t *segment, size_t segment_size, uint32_t src_ip, uint32_t dest_ip);

} // namespace ipv4
