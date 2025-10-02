#include "tcp.hpp"

namespace tcp
{

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
} // namespace tcp
