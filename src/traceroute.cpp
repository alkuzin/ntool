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
#include <csignal>
#include <netdb.h>


namespace ntool {

/**
 * @brief Initialize traceroute.
 *
 * @param [in] target - given target.
 * @return target info structure.
 */
addrinfo *init(const char *target) noexcept;

/**
 * @brief Calculate round trip time.
 *
 * @param [in] begin - given begin time.
 * @param [in] end - given end time.
 * @return round trip time in milliseconds.
 */
inline std::uint32_t rtt(const timeval& begin, const timeval& end) noexcept;

/**
 * @brief Print router info.
 *
 * @param [in] addr - given router address structure.
 * @param [in] size - given router address size.
 */
inline void print_entry(const sockaddr_in& addr, std::size_t size) noexcept;

/**
 * @brief Handle keyboard interrupt.
 *
 * @param [in] sig - given signal number.
 */
static void sigint_handler(int sig) noexcept;

inline const std::uint8_t MAX_HOPS      {30};
inline const std::uint8_t MAX_QUERIES   {3};

static std::int32_t max_hops    {MAX_HOPS};
static std::int32_t max_queries {MAX_QUERIES};
static std::int32_t sockfd      {0};


addrinfo *init(const char *target) noexcept
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

    std::signal(SIGINT, sigint_handler);

    return result;
}

void traceroute(const char *target, std::int32_t h, std::int32_t q) noexcept
{
    std::uint8_t reply[ICMP_PACKET_SIZE]    {};
    std::uint8_t packet[ICMP_PACKET_SIZE]   {};

    timeval     timeout, begin_time, end_time;
    sockaddr_in router_addr, prev_addr;
    socklen_t   addr_len = sizeof(router_addr);
    fd_set      readfds {};

    if (h == 0)
        h = MAX_HOPS;

    if (q == 0)
        q = MAX_QUERIES;

    max_hops    = h;
    max_queries = q;

    addrinfo *result = init(target);

    // set request ICMP header
    auto request        = reinterpret_cast<icmphdr*>(packet);
    request->type       = ICMP_ECHO;
    request->code       = 0;
    request->un.echo.id = getpid();

    bool reached = false;
    auto dest_ip = reinterpret_cast<sockaddr_in*>(result->ai_addr);

    std::int32_t activity {0};

    for (std::uint8_t ttl = 1; ttl <= max_hops; ttl++) {
        // set packet time to live (TTL)
        if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) == -1)
            utils::error("ntool: traceroute: error to set TTL");

        if (reached)
            break;

        std::printf(" %2u ", ttl);

        // send several probe packets
        for (std::uint16_t seq = 1; seq <= max_queries; seq++) {
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

            timeout.tv_sec  = 1;
            timeout.tv_usec = 0;
            activity        = select(sockfd + 1, &readfds, 0, 0, &timeout);

            if (activity > 0) {
                if(recvfrom(sockfd, reply, ICMP_PACKET_SIZE, 0,
                    std::bit_cast<sockaddr*>(&router_addr), &addr_len) < 0) {
                    utils::error("ntool: traceroute: error to receive reply");
                }

                gettimeofday(&end_time, nullptr);

                if (seq == 1) {
                    // handle case when previous & current
                    // router addresses are equal
                    auto& r_addr = router_addr.sin_addr.s_addr;
                    auto& p_addr = prev_addr.sin_addr.s_addr;

                    if (r_addr == p_addr) {
                        reached = true;
                        break;
                    }

                    print_entry(router_addr, sizeof(router_addr));
                }

                std::printf(" %u ms", rtt(begin_time, end_time));

                // finish traceroute when destination IP was reached
                if (router_addr.sin_addr.s_addr == dest_ip->sin_addr.s_addr)
                    reached = true;

                prev_addr = router_addr;
            }
            else {
                for (std::uint16_t i = seq; i <= max_queries; i++) {
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

inline std::uint32_t rtt(const timeval& begin, const timeval& end) noexcept
{
    auto sec      = (end.tv_sec - begin.tv_sec);
    auto microsec = (end.tv_usec - begin.tv_usec);

    return (sec * 1000) + (microsec / 1000);
}

inline void print_entry(const sockaddr_in& addr, std::size_t size) noexcept
{
    // Get the hostname
    static char hostname[NI_MAXHOST];

    if (getnameinfo(std::bit_cast<sockaddr*>(&addr), size, hostname,
        sizeof(hostname), 0, 0, 0) != 0) {
        utils::error("ntool: traceroute: get hostname error");
    }

    std::printf(" %s (%s) ", hostname, inet_ntoa(addr.sin_addr));
}

static void sigint_handler(int sig) noexcept
{
    close(sockfd);
    std::exit(sig);
}

} // namespace ntool