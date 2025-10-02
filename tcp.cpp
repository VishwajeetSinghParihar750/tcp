#include <arpa/inet.h>
#include "tcp.hpp"
#include "logger.hpp"

namespace tcp
{

    segment_buffer::segment_buffer(uint32_t src_ip_addr, uint32_t dst_ip_addr, uint8_t *dataptr, size_t sz) : data(new uint8_t[sz]), len(sz)
    {
        if (len < MIN_HEADER_LEN)
            throw parsing_error(PARSING_ERROR_TYPE::SEGMENT_TOO_SMALL);

        src_ip = src_ip_addr, dst_ip = dst_ip_addr;

        memcpy(data.get(), dataptr, sz);

        compute_offsets_and_lengths();
    }

    void segment_buffer::compute_offsets_and_lengths()
    {
        tcp_hdr = reinterpret_cast<header_t *>(data.get());

        tcp_hdr_size = (ntohs(tcp_hdr->hlen_reserved_control) >> 12) * 4;

        if (tcp_hdr_size < MIN_HEADER_LEN)
            throw parsing_error(PARSING_ERROR_TYPE::HEADER_TOO_SMALL);
        else if (tcp_hdr_size > MAX_HEADER_LEN)
            throw parsing_error(PARSING_ERROR_TYPE::HEADER_TOO_BIG);
        else if (tcp_hdr_size > len)
            throw parsing_error(PARSING_ERROR_TYPE::SANITY_CHECK_FAIL);

        tcp_options = data.get() + OPTIONS_OFFSET;
        tcp_payload_size = len - tcp_hdr_size;
        tcp_payload = data.get() + tcp_hdr_size;
    }

    void process_segment(uint32_t src_ip, uint32_t dest_ip, uint8_t *segment, size_t size)
    {
        try
        {
            auto seg = std::make_unique<segment_buffer>(src_ip, dest_ip, segment, size);
            //

            logger::getInstance().logInfo("SEGMENT ACCEPTED SUCCESSFULLY ");
        }
        catch (const parsing_error &e)
        {
            logger::getInstance().logError(parsing_error_to_string(e.error));
        }
    }

} // namespace tcp
