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

    struct __attribute__((packed)) packet_t
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
            return "PACKET_TOO_SMALL";
        case PARSING_ERROR_TYPE::CHECKSUM_FAIL:
            return "CHECKSUM FAIL";
        case PARSING_ERROR_TYPE::PARSER_ERROR:
            return "PARSER_ERROR";
        case PARSING_ERROR_TYPE::SANITY_CHECK_FAIL:
            return "SANITY_CHECK_FAIL";
        default:
            return "UNKNOWN_ERROR";
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
        std::unique_ptr<uint8_t[]> data_;
        size_t len_{0};

        // precomputed pointers and sizes
        header_t *ip_hdr_{nullptr};
        uint8_t *ip_options_{nullptr};
        size_t ip_hdr_size_{0};
        uint8_t *ip_payload_{nullptr};
        size_t ip_payload_size_{0};

        tcp::header_t *tcp_hdr_{nullptr};
        size_t tcp_hdr_size_{0};
        uint8_t *tcp_payload_{nullptr};
        size_t tcp_payload_size_{0};

        void compute_offsets_and_lengths();

    public:
        explicit packet_buffer(size_t capacity);
        packet_buffer(const uint8_t *src, size_t len);

        uint8_t *data() noexcept { return data_.get(); }
        size_t size() const noexcept { return len_; }

        header_t *ip_header() { return ip_hdr_; }     // header struct doesn't include options
        uint8_t *ip_options() { return ip_options_; } // pointer to IP options (if any)
        uint8_t *ip_payload() { return ip_payload_; } // payload includes TCP header + TCP payload
        tcp::header_t *tcp_header() { return tcp_hdr_; }
        uint8_t *tcp_payload() { return tcp_payload_; }

        size_t ip_header_size() const { return ip_hdr_size_; } // includes options
        size_t ip_payload_size() const { return ip_payload_size_; }
        size_t tcp_header_size() const { return tcp_hdr_size_; }
        size_t tcp_payload_size() const { return tcp_payload_size_; }
    };

} // namespace ipv4
