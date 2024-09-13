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

/**
 * @brief Get destination unreachable description.
 * 
 * @param [in] code - given ICMP type sub-code.
 * @return const char* 
 */
const char *unreach_decription(std::uint8_t code);

/**
 * @brief Get checksum of given buffer.
 * 
 * @param [in] buffer - given buffer.
 * @param [in] size - given buffer size in bytes.
 * @return checksum.
 */
std::uint16_t calculate_checksum(void *buffer, std::size_t size);


class ICMP
{
    icmphdr m_header; // ICMP header structure

public:
    /** @brief ICMP object default constructor.*/
    ICMP(void) = default;

    /**
     * @brief Construct a new ICMP object.
     * 
     * @param [in] header - given ICMP header structure.
     */
    ICMP(const icmphdr& header);

    /**
     * @brief Construct a new ICMP object.
     * 
     * @param [in] type - given message type.
     * @param [in] code - given type sub-code.
     * @param [in] id - given identificator.
     * @param [in] sequence - given sequence number.
     */
    ICMP(std::uint8_t type, std::uint8_t code, std::uint16_t id, std::uint16_t sequence);

    /** @brief ICMP virtual destructor.*/
    virtual ~ICMP(void) = default;

    /**
     * @brief Set ICMP object.
     * 
     * @param [in] header - given ICMP header structure.
     */
    void set(const icmphdr& header);
    
    /**
     * @brief Set ICMP object.
     * 
     * @param [in] type - given message type.
     * @param [in] code - given type sub-code.
     * @param [in] id - given identificator.
     * @param [in] sequence - given sequence number.
     */
    void set(std::uint8_t type, std::uint8_t code, std::uint16_t id, std::uint16_t sequence);

    /**
     * @brief Get ICMP header.
     * 
     * @return ICMP header. 
     */
    icmphdr header(void) const;

    /**
     * @brief Set the ICMP packet checksum.
     * 
     * @param [in] chsum - given checksum to set.
     */
    void checksum(std::uint16_t chsum);

    /**
     * @brief Get message type.
     * 
     * @return ICMP message type.
     */
    std::uint8_t type(void) const;
    
    /**
     * @brief Get type sub-code.
     * 
     * @return ICMP type sub-code.
     */
    std::uint8_t code(void) const;

    /**
     * @brief Get checksum.
     * 
     * @return ICMP checksum.
     */
    std::uint16_t checksum(void) const;

    /**
     * @brief Get identificator.
     * 
     * @return ICMP identificator.
     */
    std::uint16_t id(void) const;

    /**
     * @brief Get sequence number.
     * 
     * @return ICMP sequence number.
     */
    std::uint16_t sequence(void) const;
};

} // namespace ntool

#endif // _NTOOL_ICMP_HPP_