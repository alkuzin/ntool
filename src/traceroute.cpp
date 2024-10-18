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

#include <ntool/traceroute.hpp>
#include <ntool/utils.hpp>
#include <ntool/icmp.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <cstring>
#include <netdb.h>


namespace ntool {

/**
 * @brief Initialize traceroute.
 *
 * @param [in] target - given target.
 * @return target info structure.
 */
static addrinfo *init(const char *target) noexcept;

inline const std::uint8_t MAX_HOPS {30};

static std::int32_t sockfd      {0};
static std::int32_t max_hops    {MAX_HOPS};
static timeval begin_time       {};
static timeval end_time         {};

static addrinfo *init(const char *target) noexcept
{
    // set destination address
    addrinfo hints {};
    addrinfo *result  = nullptr;
    hints.ai_family   = AF_INET;    // IPv4
    hints.ai_socktype = SOCK_RAW;   // raw socket

    if (getaddrinfo(target, nullptr, &hints, &result)) {
        perror("getaddrinfo");
        std::exit(EXIT_FAILURE);
    }

    sockfd = socket(hints.ai_family, hints.ai_socktype, IPPROTO_ICMP);

    if (sockfd < 0)
        utils::error("ntool: traceroute: raw socket creation error");

    // Convert the IP to a string and print it
    char ip_str[INET_ADDRSTRLEN];

    auto ip    = reinterpret_cast<sockaddr_in*>(result->ai_addr);
    void *addr = &(ip->sin_addr);
    inet_ntop(result->ai_family, addr, ip_str, sizeof(ip_str));

    std::printf("traceroute to %s (%s), %u hops max, %d byte packets\n",
        target, ip_str, max_hops, ICMP_PACKET_SIZE
    );

    return result;
}

void traceroute(const char *target) noexcept
{
    addrinfo *result = init(target);

    // set request ICMP header
    std::uint8_t packet[ICMP_PACKET_SIZE] {};
    std::uint8_t buffer[256] {};

    auto request        = reinterpret_cast<icmphdr*>(packet);
    request->type       = ICMP_ECHO;
    request->code       = 0;
    request->un.echo.id = getpid();

    sockaddr_in router_addr {};
    sockaddr_in prev_addr   {};
    fd_set      readfds {};
    timeval     timeout {};
    socklen_t   addr_len = sizeof(router_addr);

    bool reached = false;

    std::int32_t activity {0};
    iphdr *ip_hdr     = nullptr;
    icmphdr *icmp_hdr = nullptr;
    std::uint32_t rtt = 0;

    for (std::uint8_t ttl = 1; ttl <= max_hops; ttl++) {
        // set packet time to live (TTL)
        if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) == -1)
            utils::error("ntool: traceroute: error to set TTL");

        if (reached)
            break;

        std::printf(" %2u ", ttl);

        // send several probe packets
        for (std::uint16_t seq = 1; seq <= 3; seq++) {
            // update ICMP header
            request->un.echo.sequence = seq;
            request->checksum         = 0;
            request->checksum         = checksum(packet, ICMP_PACKET_SIZE);

            // sending packet
            if (sendto(sockfd, packet, ICMP_PACKET_SIZE, 0,
                result->ai_addr, result->ai_addrlen) < 0)
                utils::error("ntool: traceroute: error to send ICMP packet");

            gettimeofday(&begin_time, nullptr);

            FD_ZERO(&readfds);
            FD_SET(sockfd, &readfds);

            timeout.tv_sec  = 0;
            timeout.tv_usec = 600000; // 600 ms
            activity        = select(sockfd + 1, &readfds, 0, 0, &timeout);

            if (activity > 0) {
                if(recvfrom(sockfd, buffer, 256, 0,
                    std::bit_cast<sockaddr*>(&router_addr), &addr_len) < 0) {
                    perror("recvfrom failed");
                    exit(EXIT_FAILURE);
                }

                ip_hdr   = reinterpret_cast<iphdr*>(buffer);
                icmp_hdr = std::bit_cast<icmphdr*>(buffer + (ip_hdr->ihl * 4));

                gettimeofday(&end_time, nullptr);
                rtt = (end_time.tv_sec - begin_time.tv_sec) * 1000 +
                    (end_time.tv_usec - begin_time.tv_usec) / 1000;

                if (seq == 1) {
                    if (router_addr.sin_addr.s_addr == prev_addr.sin_addr.s_addr) {
                        reached = true;
                        break;
                    }

                    // Get the hostname
                    static char hostname[NI_MAXHOST];

                    if (getnameinfo((struct sockaddr *)&router_addr, sizeof(router_addr), hostname, sizeof(hostname), 0, 0, 0) != 0) {
                        perror("getnameinfo");
                        std::exit(EXIT_FAILURE);
                    }

                    std::printf(" %s (%s) ", hostname, inet_ntoa(router_addr.sin_addr));
                }
                std::printf(" %u ms", rtt);

                prev_addr = router_addr;

                if (icmp_hdr->type == ICMP_ECHOREPLY)
                    reached = true;
            }
            else {
                for (std::uint16_t i = seq; i <= 3; i++) {
                    std::putchar(' ');
                    std::putchar('*');
                }
                break;
            }
        }
        std::putchar('\n');
    }

    freeaddrinfo(result);
    close(sockfd);
}

} // namespace ntool