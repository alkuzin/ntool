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
#include <signal.h>
#include <netdb.h>
#include <cstring>
#include <thread>
#include <chrono>
#include <vector>

namespace ntool {

using  TimePoint = std::chrono::time_point<std::chrono::high_resolution_clock>;
static TimePoint    begin_time; // sending packet time
static TimePoint    end_time;   // receiving packet time
static std::uint8_t ttl;        // packet time to live

static ICMPPayload default_payload {};
static const char *target_ip_str;
static std::uint16_t ping_count = 1;
static std::uint16_t transmitted_packets = 0;
static std::uint16_t received_packets    = 0;

//  Round-trip time (RTT)
static std::vector<double> rtt;
static double rtt_min  = 0.0; // minimum round-trip time recorded
static double rtt_avr  = 0.0; // average round-trip time recorded
static double rtt_max  = 0.0; // maximum round-trip time recorded
static double rtt_mdev = 0.0; // mean deviation

// Auxilar functions ------------------------------------------------------------------

/** @brief Set the default payload with ASCII symbols.*/
constexpr void set_default_payload(void)
{
    auto i = 0;
    for (auto& x : default_payload) {
        x = static_cast<std::byte>('0' + i);
        ++i;
    }
}

/**
 * @brief Get ICMP header from packet.
 * 
 * @param [out] reply - given object to store ICMP packet.
 * @param [in] packet - given received packet to process.
 */
static void process_packet(ICMP& reply, std::byte *packet)
{
    icmphdr header;
    iphdr   *ip_header   = reinterpret_cast<iphdr*>(packet);
    icmphdr *icmp_header = reinterpret_cast<icmphdr*>(packet + (ip_header->ihl * 4));
    
    std::memcpy(&header, icmp_header, sizeof(header));

    reply.set(header);
    ttl = ip_header->ttl;
}

/** @brief Get ping test statistics.*/
static void summary(void)
{
    std::printf("\n--- %s ping statistics ---\n", target_ip_str);
    std::printf("%u packets transmitted, %u received, %u%% packet loss\n",
        transmitted_packets,
        received_packets,
        (100 - ((received_packets / transmitted_packets) * 100)) // TODO: fix issue with calculation in case of missing packet
    );

    if (rtt.empty())
        utils::error("[ERROR] vector of RTT is empty");

    rtt_min  = *(std::min_element(rtt.begin(), rtt.end()));
    rtt_avr  = utils::mean(rtt.begin(), rtt.end());
    rtt_max  = *(std::max_element(rtt.begin(), rtt.end()));
    rtt_mdev = utils::mdev(rtt.begin(), rtt.end());

    std::printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", rtt_min, rtt_avr, rtt_max, rtt_mdev);
}

/**
 * @brief Handle keyboard interrupt.
 * 
 * @param [in] sig - given signal number.
 */
static void interrupt_handler(int sig)
{
    summary();
    std::exit(sig); // Exit the program
}

/**
 * @brief Get IP addres of target.
 * 
 * @param [in] target - given target text representation.
 * @return IP address.
 */
static in_addr_t handle_target(const std::string_view& target)
{
    sockaddr_in addr;

    if (target.compare("localhost") == 0)
        return inet_addr("127.0.0.1");

    if (inet_pton(AF_INET, target.data(), &(addr.sin_addr)) != 0)
        return addr.sin_addr.s_addr;
    else {
        hostent *he = gethostbyname(target.data());
        
        if (!he)
            utils::error("[ERROR] cannot resolve the target");
        
        addr.sin_addr = *reinterpret_cast<in_addr*>(he->h_addr);
        return addr.sin_addr.s_addr;
    }
}

// Ping implementation ------------------------------------------------------------------

Ping::Ping(void) : m_socket(RawSocket(AF_INET, IPPROTO_ICMP))
{
    signal(SIGINT, interrupt_handler);
}

void Ping::ping(const std::string_view& target, std::uint16_t n)
{
    utils::terminate_if_not_root();
    set_default_payload();

    // Set destination address
    sockaddr_in addr;
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = handle_target(target);
    addr.sin_port        = 0;

    std::printf("Pinging %s [%s] with %u bytes of data:\n", target.data(), inet_ntoa(addr.sin_addr), ICMP_PACKET_SIZE);

    // Set ICMP header
    ICMP request, reply;

    std::chrono::duration<double, std::milli> time;
    pid_t pid = getpid();
        
    while (ping_count <= n) {
        request.set(
            ICMP_ECHO,   // echo request
            0,           // echo reply
            pid,         // current process identificator
            ping_count++ // sequence number
        );

        send(request.header(), addr);
        recv(reply, addr);
        
        // Handle received ICMP packet
        target_ip_str = inet_ntoa(addr.sin_addr);
        
        switch (reply.type())
        {
        case ICMP_ECHO: // TODO: handle 127.0.0.1 echo requests correctly (icmp_seq issue)
        case ICMP_ECHOREPLY:
            time = end_time - begin_time;
            rtt.push_back(time.count());

            std::printf("%u bytes from %s: icmp_seq=%u ttl=%u rtt=%.3lf ms\n",
                ICMP_PACKET_SIZE,
                target_ip_str,
                reply.sequence(),
                ttl,
                rtt.back()
            );
            break;
        
        case ICMP_UNREACH:
            std::printf("From %s: icmp_seq=%u %s\n",
                target_ip_str,
                reply.sequence(),
                unreach_decription(reply.code())
            );

            if (kill(pid, SIGINT) == -1)
                utils::error("[ERROR] failde to send SIGINT");
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
    summary();
}

void Ping::send(const icmphdr& header, sockaddr_in& addr) const
{
    ICMPPacket packet(header, default_payload);

    auto data  = packet.data();
    auto ret   = sendto(m_socket.fd(), &data, sizeof(data), 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    begin_time = std::chrono::high_resolution_clock::now();

    if (ret <= 0)
        utils::error("[ERROR] error to send ICMP packet");
    
    transmitted_packets++;
}

void Ping::recv(ICMP& reply, sockaddr_in& addr) const
{
    std::byte packet[ICMP_PACKET_SIZE];

    auto len = static_cast<socklen_t>(sizeof(addr));
    auto ret = recvfrom(m_socket.fd(), packet, sizeof(packet), 0, reinterpret_cast<sockaddr*>(&addr), &len);
    end_time = std::chrono::high_resolution_clock::now();

    if (ret <= 0)
        utils::error("[ERROR] error to receive ICMP packet");

    received_packets++;
    process_packet(reply, packet);
}

} // namespace ntool