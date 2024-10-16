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
#include <ntool/icmp.hpp>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <cstring>
#include <csignal>
#include <chrono>
#include <thread>
#include <cmath>


namespace ntool {

/** @brief Initialize ping utility.*/
static void init(void) noexcept;

/**
 * @brief Set the ICMP packet.
 *
 * @param [out] packet - given received packet to process.
 * @param [in] header - given ICMP header.
 */
static void set_packet(std::uint8_t *packet, const icmphdr& header) noexcept;

/**
 * @brief Send ICMP packet.
 *
 * @param [in] request - given ICMP header.
 * @param [in] addr - given destination address.
 */
static void send(const icmphdr& request, sockaddr_in& addr) noexcept;

/**
 * @brief Get ICMP header from packet.
 *
 * @param [out] reply - given object to store ICMP packet.
 * @param [in] packet - given received packet to process.
 */
static void handle_packet(icmphdr& reply, const std::uint8_t *packet) noexcept;

/**
 * @brief Receive ICMP packet.
 *
 * @param [in] reply - given ICMP header.
 * @param [in] addr - given source address.
 */
static void recv(icmphdr& reply, sockaddr_in& addr) noexcept;

/** @brief Get ping test statistics.*/
static void summary(void) noexcept;

/**
 * @brief Handle keyboard interrupt.
 *
 * @param [in] sig - given signal number.
 */
static void sigint_handler(int sig) noexcept;

inline const std::uint8_t DEFAULT_PINGS_COUNT {4};

using namespace std::chrono;
using time_point_t = time_point<high_resolution_clock>;
using duration_t   = duration<double, std::milli>;

static std::uint16_t transmitted_packets = 0;
static std::uint16_t received_packets    = 0;
static time_point_t  begin_time;    // sending packet time
static time_point_t  end_time;      // receiving packet time
static std::uint8_t  ttl;           // packet time to live
static std::vector<double> rtt;     // round-trip time (RTT)

inline const char *target_ip_str = nullptr;
static std::int32_t sockfd       = 0;

// default ICMP payload
inline const std::uint8_t payload[ICMP_PAYLOAD_SIZE]
{
    "!!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUV"
};

static void init(void) noexcept
{
    transmitted_packets = 0;
    received_packets    = 0;
    ttl                 = 0;
    sockfd              = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (sockfd < 0)
        utils::error("ntool: ping: raw socket creation error");

    // add limit time for receiving packet
    timeval timeout;
    timeout.tv_sec  = 2;    // seconds
    timeout.tv_usec = 0;    // milliseconds

    auto ret = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
        &timeout, sizeof(timeout)
    );

    if (ret == -1)
        utils::error("ntool: ping: error to set timeout");

    std::signal(SIGINT, sigint_handler);
}

void ping(const std::string_view& target, std::uint16_t n) noexcept
{
    init();

    // set destination address
    sockaddr_in addr;
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = utils::get_ip_address(target);
    addr.sin_port        = 0;

    std::printf("Pinging %s [%s] with %u bytes of data:\n",
        target.data(), inet_ntoa(addr.sin_addr), ICMP_PACKET_SIZE
    );

    icmphdr    request, reply;
    duration_t time;

    target_ip_str   = inet_ntoa(addr.sin_addr);
    auto ping_count = 0;

    // handle incorrect number of pings
    if (n == 0)
        n = DEFAULT_PINGS_COUNT;

    rtt.reserve(n);

    while (ping_count < n) {
        // set request ICMP header
        request.type             = ICMP_ECHO;
        request.code             = 0;
        request.un.echo.id       = getpid();
        request.un.echo.sequence = ++ping_count;

        send(request, addr);
        recv(reply, addr);

        // Handle received ICMP packet
        switch (reply.type) {
        case ICMP_ECHO:
        case ICMP_ECHOREPLY:
            time = end_time - begin_time;
            rtt.push_back(time.count());

            std::printf("%u bytes from %s: icmp_seq=%u ttl=%u rtt=%.3lf ms\n",
                ICMP_PACKET_SIZE, target_ip_str, reply.un.echo.sequence,
                ttl, rtt.back()
            );
            break;

        case ICMP_UNREACH:
            std::printf("From %s: icmp_seq=%u %s\n", target_ip_str,
                reply.un.echo.sequence, unreach_decription(reply.code)
            );

            // terminate task
            if (kill(getpid(), SIGINT) == -1)
                utils::error("ntool: ping: fail to send SIGINT");
            break;

        default:
            std::printf("Received ICMP packet [type: %d code: %d id: %d]\n",
                reply.type, reply.code, reply.un.echo.id
            );
            break;
        }

        // Delay time for 1 second
        std::this_thread::sleep_for(milliseconds(1000));
    }

    summary();
    close(sockfd);
}

static void set_packet(std::uint8_t *packet, const icmphdr& header) noexcept
{
    icmphdr hdr  = header;
    hdr.checksum = 0;

    // copy ICMP header & payload into the packet
    std::memcpy(packet, &hdr, sizeof(icmphdr));
    std::memcpy(packet + sizeof(icmphdr), &payload, ICMP_PAYLOAD_SIZE);

    // calculate packet checksum
    hdr.checksum = checksum(packet, ICMP_PACKET_SIZE);
    packet[2]    = hdr.checksum & 0xFFFF;
    packet[3]    = hdr.checksum >> 0x8;
}

void send(const icmphdr& request, sockaddr_in& addr) noexcept
{
    static std::uint8_t packet[ICMP_PACKET_SIZE];

    std::memset(packet, 0, ICMP_PACKET_SIZE);
    set_packet(packet, request);

    auto ret = sendto(sockfd, packet, ICMP_PACKET_SIZE, 0,
        std::bit_cast<sockaddr*>(&addr), sizeof(sockaddr_in)
    );

    begin_time = high_resolution_clock::now();

    if (ret <= 0)
        utils::error("ntool: ping: error to send ICMP packet");

    transmitted_packets++;
}

static void handle_packet(icmphdr& reply, const std::uint8_t *packet) noexcept
{
    iphdr   *ip_hdr   = std::bit_cast<iphdr*>(packet);
    icmphdr *icmp_hdr = std::bit_cast<icmphdr*>(packet + (ip_hdr->ihl * 4));

    icmphdr header;
    std::memcpy(&header, icmp_hdr, sizeof(header));
    reply = header;
    ttl   = ip_hdr->ttl;
}

static void recv(icmphdr& reply, sockaddr_in& addr) noexcept
{
    static std::uint8_t packet[ICMP_PACKET_SIZE];

    auto len = static_cast<socklen_t>(sizeof(sockaddr_in));
    auto ret = recvfrom(sockfd, packet, ICMP_PACKET_SIZE, 0,
        std::bit_cast<sockaddr*>(&addr), &len
    );

    end_time = high_resolution_clock::now();

    if (ret < 0) {
        if (errno == EWOULDBLOCK) {
            std::printf("From %s: Failed to receive packet\n", target_ip_str);

            // terminate task
            if (kill(getpid(), SIGINT) == -1)
                utils::error("ntool: ping: fail to send SIGINT");
        }
        else
            utils::error("ntool: ping: error to receive ICMP packet");
    }

    received_packets++;
    handle_packet(reply, packet);
}

static void summary(void) noexcept
{
    auto ratio       = received_packets / transmitted_packets;
    auto packet_loss = std::ceil(100.0 - (ratio * 100.0));

    std::printf("\n--- %s ping statistics ---\n", target_ip_str);
    std::printf("%u packets transmitted, %u received, %u%% packet loss\n",
        transmitted_packets, received_packets,
        static_cast<std::uint32_t>(packet_loss)
    );

    if (rtt.empty())
        utils::error("ntool: ping: round-trip time wasn't calculated");

    double rtt_min  = *(std::min_element(rtt.begin(), rtt.end()));
    double rtt_avr  = utils::mean(rtt.begin(), rtt.end());
    double rtt_max  = *(std::max_element(rtt.begin(), rtt.end()));
    double rtt_mdev = utils::mdev(rtt.begin(), rtt.end());

    std::printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
        rtt_min, rtt_avr, rtt_max, rtt_mdev
    );
}

static void sigint_handler(int sig) noexcept
{
    summary();
    close(sockfd);
    std::exit(sig);
}

} // namespace ntool