/**
 * Multifunctional network analyser tool.
 * Copyright (C) 2024  Alexander (@alkuzin).
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <ntool/icmp.hpp>
#include <cstring>
#include <string>


namespace ntool {

// Auxilar functions ------------------------------------------------------------------

    static const std::array<std::string_view, 16> unreach_table = {
        "Destination network unreachable",
        "Destination host unreachable",
        "Destination protocol unreachable",
        "Destination port unreachable",
        "Fragmentation required, and DF flag set",
        "Source route failed",
        "Destination network unknown",
        "Destination host unknown",
        "Source host isolated",
        "Network administratively prohibited",
        "Host administratively prohibited",
        "Network unreachable for ToS",
        "Host unreachable for ToS",
        "Communication administratively prohibited",
        "Host Precedence Violation",
        "Precedence cutoff in effect "
    };
    
    const char *unreach_decription(std::uint8_t code)
    {
        return unreach_table[code].data();
    }
    
    std::uint16_t calculate_checksum(void *buffer, std::size_t size)
    {
        std::uint16_t *buf   = reinterpret_cast<std::uint16_t *>(buffer);
        std::uint32_t sum    = 0;
        std::uint16_t result = 0;

        for (sum = 0; size > 1; size -= 2)
            sum += *buf++;

        if (size == 1)
            sum += *reinterpret_cast<std::uint8_t *>(buf);
        
        sum     = (sum >> 0x10) + (sum & 0xFFFF);
        sum    += (sum >> 0x10);
        result  = ~sum;

        return result;
    }

// ICMP ------------------------------------------------------------------

    ICMP::ICMP(const icmphdr& header)
    {
        set(header);
    }

    ICMP::ICMP(std::uint8_t type, std::uint8_t code, std::uint16_t id, std::uint16_t sequence)
    {
        set(type, code, id, sequence);
    }
    
    void ICMP::set(const icmphdr& header)
    {
        std::memset(&m_header, 0, sizeof(m_header));

        m_header = header;
    }
    
    void ICMP::set(std::uint8_t type, std::uint8_t code, std::uint16_t id, std::uint16_t sequence)
    {
        std::memset(&m_header, 0, sizeof(m_header));
        
        m_header.type             = type;
        m_header.code             = code;
        m_header.un.echo.id       = id;
        m_header.un.echo.sequence = sequence;
        m_header.checksum         = calculate_checksum(&m_header, sizeof(m_header));
    }

    icmphdr ICMP::header(void) const
    {
        return m_header;
    }

    std::uint8_t ICMP::type(void) const
    {
        return m_header.type;
    }
    
    std::uint8_t ICMP::code(void) const
    {
        return m_header.code;
    }

    std::uint16_t ICMP::checksum(void) const
    {
        return m_header.checksum;
    }
    
    void ICMP::checksum(std::uint16_t chsum)
    {
        m_header.checksum = chsum;
    }

    std::uint16_t ICMP::id(void) const
    {
        return m_header.un.echo.id;
    }

    std::uint16_t ICMP::sequence(void) const
    {
        return m_header.un.echo.sequence;
    }

// ICMP Packet ------------------------------------------------------------------

    ICMPPacket::ICMPPacket(const icmphdr& header, const ICMPPayload& payload)
    {
        set(header, payload);
    }

    void ICMPPacket::set(const icmphdr& header, const ICMPPayload& payload)
    {
        m_header         = header;
        auto data        = m_data.data();
        auto header_size = sizeof(m_header);

        m_header.checksum = 0;
        std::memcpy(data, &m_header, header_size);
        std::copy(payload.begin(), payload.end(), m_data.begin() + header_size);

        m_header.checksum = calculate_checksum(data, m_data.size());

        m_data[2] = static_cast<std::byte>(m_header.checksum & 0xFFFF);
        m_data[3] = static_cast<std::byte>(m_header.checksum >> 0x8);
    }
    
    ICMPPayload ICMPPacket::payload(void) const
    {
        ICMPPayload p;
        std::copy(m_data.begin() + sizeof(m_header), m_data.end(), p.begin());

        return p;
    }

    const ICMPPacketData& ICMPPacket::data(void) const
    {
        return m_data;
    }

} // namespace ntool