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

#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

#include <ntool/utils.hpp>
#include <ntool/ping.hpp>


static const uint32_t PACKET_SIZE = 64;    

namespace ntool {

Ping::Ping(void) : m_socket(RawSocket(AF_INET, IPPROTO_ICMP)) {}

void Ping::ping(const std::string_view& target)
{
    // TODO: handle "localhost", IPv4 (x.x.x.x) & domain names (e.g. example.com)
    utils::terminate_if_not_root();

    // Set destination address
    sockaddr_in addr;
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = inet_addr(target.data());

    // Set ICMP header
    ICMP icmp(
        ICMP_ECHO, // echo request
        0,         // echo reply
        getpid(),  // current process identificator
        1          // sequence number
    );

    send(icmp.header(), addr);
}

void Ping::send(const icmphdr& header, sockaddr_in& addr) const
{
    std::byte packet[PACKET_SIZE];
    auto header_size = sizeof(header);

    std::memcpy(packet, &header, header_size);

    int ret = sendto(m_socket.fd(), packet, header_size, 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));

    if (ret <= 0)
        utils::error("[ERROR] error to send ICMP packet");
}

} // namespace ntool