#pragma once
#include <vector>
#include <memory>
#include <memory.h>
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

    //
    enum class PARSING_ERROR_TYPE
    {
        CHECKSUM_FAIL,
        SEGMENT_TOO_SMALL,
        HEADER_TOO_SMALL,
        HEADER_TOO_BIG,
        PARSER_ERROR,
        SANITY_CHECK_FAIL,
    };

    inline std::string parsing_error_to_string(PARSING_ERROR_TYPE e)
    {
        switch (e)
        {
        case PARSING_ERROR_TYPE::SEGMENT_TOO_SMALL:
            return "TCP_SEGMENT_TOO_SMALL";

        case PARSING_ERROR_TYPE::HEADER_TOO_SMALL:
            return "TCP_HEADER_TOO_SMALL";
        case PARSING_ERROR_TYPE::HEADER_TOO_BIG:
            return "TCP_HEADER_TOO_BIG";
        case PARSING_ERROR_TYPE::CHECKSUM_FAIL:
            return "TCP_CHECKSUM FAIL";
        case PARSING_ERROR_TYPE::PARSER_ERROR:
            return "PARSER_ERROR";
        case PARSING_ERROR_TYPE::SANITY_CHECK_FAIL:
            return "TCP_SANITY_CHECK_FAIL";
        default:
            return "TCP_UNKNOWN_ERROR";
        }
    }

    class parsing_error : public std::runtime_error
    {
    public:
        PARSING_ERROR_TYPE error;
        parsing_error(PARSING_ERROR_TYPE err, const char *msg = "") : runtime_error(msg), error(err) {}
    };

    class segment_buffer
    {
        static const size_t MIN_HEADER_LEN = 20;
        static const size_t OPTIONS_OFFSET = 20;
        static const size_t MAX_HEADER_LEN = 60;

        std::unique_ptr<uint8_t[]> data;
        size_t len{0};

        header_t *tcp_hdr{nullptr};
        size_t tcp_hdr_size{0};
        uint8_t *tcp_options{nullptr};
        uint8_t *tcp_payload{nullptr};
        size_t tcp_payload_size{0};

        void compute_offsets_and_lengths();

    public:
        segment_buffer(uint8_t *dataptr, size_t sz) : data(new uint8_t[sz]), len(sz)
        {
            if (len < MIN_HEADER_LEN)
                throw parsing_error(PARSING_ERROR_TYPE::SEGMENT_TOO_SMALL);

            memcpy(data.get(), dataptr, sz);

            compute_offsets_and_lengths();
        }

        header_t *header() const { return tcp_hdr; }
        size_t header_size() const { return tcp_hdr_size; }
        uint8_t *options() const { return tcp_options; }
        uint8_t *payload() const { return tcp_payload; }
        size_t payload_size() const { return tcp_payload_size; }
        uint8_t *get_data() const { return data.get(); }
        size_t size() const { return len; }
    };

    class ip_facing_input_buffer
    {
        std::vector<std::unique_ptr<segment_buffer>> segs;

    public:
        void write(uint8_t *segment, size_t size)
        {
            try
            {
                segs.push_back(std::make_unique<segment_buffer>(segment, size));

                logger::getInstance().logInfo("SEGMENT ACCEPTED SUCCESSFULLY ");
            }
            catch (parsing_error e)
            {
                logger::getInstance().logError(parsing_error_to_string(e.error));
            }
        }
    };

} // namespace tcp
