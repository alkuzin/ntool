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
#include <array>

namespace ntool {

    ICMP::ICMP(const icmphdr& header)
    {
        std::memset(&m_header, 0, sizeof(m_header));

        m_header = header;
    }

    ICMP::ICMP(std::uint8_t type, std::uint8_t code, std::uint16_t id, std::uint16_t sequence)
    {
        std::memset(&m_header, 0, sizeof(m_header));
        
        m_header.type             = type;
        m_header.code             = code;
        m_header.un.echo.id       = id;
        m_header.un.echo.sequence = sequence;
        m_header.checksum         = set_checksum();
    }
    
    std::uint16_t ICMP::set_checksum(void)
    {
        std::uint16_t *buf   = reinterpret_cast<std::uint16_t *>(&m_header);
        std::size_t   len    = sizeof(m_header);
        std::uint32_t sum    = 0;
        std::uint16_t result = 0;

        for (sum = 0; len > 1; len -= 2)
            sum += *buf++;

        if (len == 1)
            sum += *reinterpret_cast<std::uint8_t *>(buf);
        
        sum     = (sum >> 0x10) + (sum & 0xFFFF);
        sum    += (sum >> 0x10);
        result  = ~sum;

        return result;
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
        m_header.checksum         = set_checksum();
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

    std::uint16_t ICMP::id(void) const
    {
        return m_header.un.echo.id;
    }

    std::uint16_t ICMP::sequence(void) const
    {
        return m_header.un.echo.sequence;
    }

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

} // namespace ntool