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
 * @file  ping.hpp
 * @brief Network diagnostic tool used to test the reachability
 * of a host on an Internet Protocol (IP) network.
 *
 * @author Alexander Kuzin (<a href="https://github.com/alkuzin">alkuzin</a>)
 * @date   11.09.2024
 */

#ifndef _NTOOL_PING_HPP_
#define _NTOOL_PING_HPP_

#include <ntool/icmp.hpp>
#include <string>


namespace ntool {

struct ping_t
{
private:
    std::int32_t sockfd; // socket file descriptor

    /**
     * @brief Send ICMP packet.
     *
     * @param [in] request - given ICMP header.
     * @param [in] addr - given destination address.
     */
    void send(const icmphdr& request, sockaddr_in& addr) noexcept;

    /**
     * @brief Receive ICMP packet.
     *
     * @param [in] reply - given ICMP header.
     * @param [in] addr - given source address.
     */
    void recv(icmphdr& reply, sockaddr_in& addr) noexcept;

public:
    /** Initialize ping utility.*/
    void init(void) noexcept;

    /**
     * @brief Ping given target.
     *
     * @param [in] target - given target to ping.
     * @param [in] n - given number of ping.
     */
    void ping(const std::string_view& target, std::uint16_t n = 4) noexcept;
};

} // namespace ntool

#endif // _NTOOL_PING_HPP_