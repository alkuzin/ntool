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


namespace ntool {

inline const char *unreach_table[16] = {
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
    return unreach_table[code];
}

std::uint16_t checksum(void *buffer, std::size_t size)
{
    std::uint16_t *buf   = reinterpret_cast<std::uint16_t*>(buffer);
    std::uint32_t sum    = 0;
    std::uint16_t result = 0;

    for (sum = 0; size > 1; size -= 2)
        sum += *buf++;

    if (size == 1)
        sum += *reinterpret_cast<std::uint8_t*>(buf);

    sum     = (sum >> 0x10) + (sum & 0xFFFF);
    sum    += (sum >> 0x10);
    result  = ~sum;

    return result;
}

} // namespace ntool