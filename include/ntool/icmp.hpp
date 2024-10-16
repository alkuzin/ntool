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

/**
 * @file  icmp.hpp
 * @brief Internet Control Message Protocol wrapper.
 *
 * @author Alexander Kuzin (<a href="https://github.com/alkuzin">alkuzin</a>)
 * @date   12.09.2024
 */

#ifndef _NTOOL_ICMP_HPP_
#define _NTOOL_ICMP_HPP_

#include <netinet/ip_icmp.h>
#include <cstdint>


namespace ntool {

inline const std::uint8_t ICMP_PACKET_SIZE  {64};
inline const std::uint8_t ICMP_PAYLOAD_SIZE {56};

/**
 * @brief Get destination unreachable description.
 *
 * @param [in] code - given ICMP type sub-code.
 * @return description string.
 */
const char *unreach_decription(std::uint8_t code) noexcept;

/**
 * @brief Get checksum of given buffer.
 *
 * @param [in] buffer - given buffer.
 * @param [in] size - given buffer size in bytes.
 * @return checksum.
 */
std::uint16_t checksum(void *buffer, std::size_t size) noexcept;

} // namespace ntool

#endif // _NTOOL_ICMP_HPP_