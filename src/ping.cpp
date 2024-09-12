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

#include <thread>
#include <chrono>


using  TimePoint = std::chrono::time_point<std::chrono::high_resolution_clock>;
static TimePoint m_begin_time; // sending packet time
static TimePoint m_end_time;   // receiving packet time

static const uint32_t PACKET_SIZE = 64;

namespace ntool {

/**
 * @brief Process ICMP packet.
 * 
 * @param [out] reply - given object to store ICMP packet.
 * @param [in] packet - given received packet to process.
 * @param [out] ttl - given variable to store packet time to live.
 */
static void process_packet(ICMP& reply, std::byte *packet, std::uint8_t& ttl);


Ping::Ping(void) : m_socket(RawSocket(AF_INET, IPPROTO_ICMP)) {}

void Ping::ping(const std::string_view& target)
{
    // TODO: handle "localhost", IPv4 (x.x.x.x) & domain names (e.g. example.com)
    utils::terminate_if_not_root();

    // Set destination address
    sockaddr_in addr;
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = inet_addr(target.data());    

    std::printf("Pinging %s [%s] with %u bytes of data:\n", target.data(), inet_ntoa(addr.sin_addr), PACKET_SIZE);

    // Set ICMP header
    ICMP request, reply;

    std::chrono::duration<double, std::milli> time;
    const char *reply_ip_str;
    std::uint16_t seq = 1;
    std::uint8_t ttl;

    while (true) {
        request.set(
            ICMP_ECHO, // echo request
            0,         // echo reply
            getpid(),  // current process identificator
            seq++      // sequence number
        );
        
        send(request.header(), addr);
        recv(reply, addr, ttl);
        
        // Handle received ICMP packet
        reply_ip_str = inet_ntoa(addr.sin_addr);
        
        switch (reply.type())
        {
        // TODO: fix issue with sending more packets when pinging 127.0.0.1
        case ICMP_ECHO:
            continue;

        case ICMP_ECHOREPLY:
            time = m_end_time - m_begin_time;

            std::printf("%u bytes from %s: icmp_seq=%u ttl=%u time=%.3lf ms\n",
                PACKET_SIZE,
                reply_ip_str,
                reply.sequence(),
                ttl,
                time.count()
            );
            break;
        
        case ICMP_UNREACH:
            std::printf("From %s: icmp_seq=%u %s\n",
                reply_ip_str,
                reply.sequence(),
                unreach_decription(reply.code())
            );
            break;
        
        default:
            std::printf("Received ICMP packet [type: %d  code: %d]", reply.type(), reply.code());
            break;
        }
        
        // Delay time for 1 second
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}

void Ping::send(const icmphdr& header, sockaddr_in& addr) const
{
    std::byte packet[PACKET_SIZE];
    auto header_size = sizeof(header);

    std::memcpy(packet, &header, header_size);

    auto ret = sendto(m_socket.fd(), packet, header_size, 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    m_begin_time = std::chrono::high_resolution_clock::now();

    if (ret <= 0)
        utils::error("[ERROR] error to send ICMP packet");
}

void Ping::recv(ICMP& reply, sockaddr_in& addr, std::uint8_t& ttl) const
{
    std::byte packet[PACKET_SIZE];

    auto len   = static_cast<socklen_t>(sizeof(addr));
    auto ret   = recvfrom(m_socket.fd(), packet, sizeof(packet), 0, reinterpret_cast<sockaddr*>(&addr), &len);
    m_end_time = std::chrono::high_resolution_clock::now();

    if (ret <= 0)
        utils::error("[ERROR] error to receive ICMP packet");

    process_packet(reply, packet, ttl);
}

static void process_packet(ICMP& reply, std::byte *packet, std::uint8_t& ttl)
{
    iphdr   *ip_header   = (iphdr *)packet;
    icmphdr *icmp_header = (icmphdr *)(packet + (ip_header->ihl * 4));

    icmphdr header;
    std::memcpy(&header, icmp_header, sizeof(header));

    reply.set(header);
    ttl = ip_header->ttl;
}

} // namespace ntool