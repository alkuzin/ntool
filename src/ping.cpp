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

#include <ntool/utils.hpp>
#include <ntool/ping.hpp>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <chrono>


namespace ntool {

struct Packet {
    icmphdr   header;
    std::byte payload[56];
};

using  TimePoint = std::chrono::time_point<std::chrono::high_resolution_clock>;
static TimePoint    begin_time; // sending packet time
static TimePoint    end_time;   // receiving packet time
static std::uint8_t ttl;        // packet time to live

static const uint32_t PACKET_SIZE = 64;
static std::uint16_t  ping_count  = 1;

/**
 * @brief Process ICMP packet.
 * 
 * @param [out] reply - given object to store ICMP packet.
 * @param [in] packet - given received packet to process.
 */
static void process_packet(ICMP& reply, std::byte *packet);

/**
 * @brief Set the packet to send.
 * 
 * @param [out] packet - given packet to set.
 * @param [in] header - given ICMP header.
 */
static void set_packet(Packet& packet, const icmphdr& header);


Ping::Ping(void) : m_socket(RawSocket(AF_INET, IPPROTO_ICMP)) {}

void Ping::ping(const std::string_view& target, std::uint16_t n)
{
    // TODO: handle "localhost", IPv4 (x.x.x.x) & domain names (e.g. example.com)
    utils::terminate_if_not_root();

    // Set destination address
    sockaddr_in addr;
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = inet_addr(target.data());
    addr.sin_port        = 0;

    std::printf("Pinging %s [%s] with %u bytes of data:\n", target.data(), inet_ntoa(addr.sin_addr), PACKET_SIZE);

    // Set ICMP header
    ICMP request, reply;

    std::chrono::duration<double, std::milli> time;
    const char *reply_ip_str;
        
    while (ping_count <= n) {
        request.set(
            ICMP_ECHO,   // echo request
            0,           // echo reply
            getpid(),    // current process identificator
            ping_count++ // sequence number
        );

        send(request.header(), addr);
        recv(reply, addr);
        
        // Handle received ICMP packet
        reply_ip_str = inet_ntoa(addr.sin_addr);
        
        switch (reply.type())
        {
        case ICMP_ECHO: // TODO: handle 127.0.0.1 echo requests correctly (icmp_seq issue)
        case ICMP_ECHOREPLY:
            time = end_time - begin_time;

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
            std::exit(EXIT_SUCCESS);
            break;
        
        default:
            std::printf("Received ICMP packet [type: %d code: %d id: %d]\n",
                reply.type(),
                reply.code(),
                reply.id()
            );
            break;
        }
        
        // Delay time for 1 second
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}

void Ping::send(const icmphdr& header, sockaddr_in& addr) const
{
    static Packet packet;
    set_packet(packet, header);

    auto ret   = sendto(m_socket.fd(), &packet, sizeof(packet), 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    begin_time = std::chrono::high_resolution_clock::now();

    if (ret <= 0)
        utils::error("[ERROR] error to send ICMP packet");
}

void Ping::recv(ICMP& reply, sockaddr_in& addr) const
{
    std::byte packet[PACKET_SIZE];

    auto len = static_cast<socklen_t>(sizeof(addr));
    auto ret = recvfrom(m_socket.fd(), packet, sizeof(packet), 0, reinterpret_cast<sockaddr*>(&addr), &len);
    end_time = std::chrono::high_resolution_clock::now();

    if (ret <= 0)
        utils::error("[ERROR] error to receive ICMP packet");

    process_packet(reply, packet);
}

static void set_packet(Packet& packet, const icmphdr& header)
{
    // clearing packet from garbage
    std::memset(&packet, 0, sizeof(packet));
    packet.header = header;
    
    // setting payload
    auto i = 0x0;
    for (auto& x : packet.payload) {
        x = static_cast<std::byte>(0x30 + i);
        ++i;
    }

    // clearing previous checksum & setting new including payload
    packet.header.checksum = 0;
    packet.header.checksum = calculate_checksum(&packet, sizeof(packet));
}

static void process_packet(ICMP& reply, std::byte *packet)
{
    icmphdr header;
    iphdr   *ip_header   = reinterpret_cast<iphdr*>(packet);
    icmphdr *icmp_header = reinterpret_cast<icmphdr*>(packet + (ip_header->ihl * 4));
    
    std::memcpy(&header, icmp_header, sizeof(header));

    reply.set(header);
    ttl = ip_header->ttl;
}

} // namespace ntool