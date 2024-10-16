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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <cstring>
#include <cstdio>


namespace ntool {
namespace utils {

void terminate_if_not_root(void) noexcept
{
    if (geteuid() != 0)
        error("ntool: this process must be run as root");
}

void error(const std::string_view& msg)
{
    std::puts(msg.data());
    std::exit(EXIT_FAILURE);
}

/**
 * @brief Convert byte to ASCII.
 *
 * @param [in] ch - given byte to convert.
 * @return character to print.
 */
static inline char to_print(std::uint8_t ch) noexcept
{
    return (ch > 31 && ch < 127)? ch : '.';
}

inline const std::uint8_t BYTES_PER_LINE {16};

void memdump(const std::uint8_t *addr, std::size_t size) noexcept
{
    char    line[BYTES_PER_LINE + 1] {0};
    uint8_t bytes[BYTES_PER_LINE] {0};

    const uint8_t *stack_ptr = addr;
    uint8_t byte       = 0;
    size_t  byte_pos   = 0;
    size_t  rows       = 0;

    for (size_t k = 0; k < (size / BYTES_PER_LINE) + 1; k++) {
        std::memset(line, ' ', BYTES_PER_LINE);
        std::memset(bytes, ' ', BYTES_PER_LINE);

        for (size_t i = 0; i < BYTES_PER_LINE; i++) {
            byte     = stack_ptr[byte_pos];
            line[i]  = to_print(byte);
            bytes[i] = byte;
            byte_pos++;
        }

        std::printf("%08lx   ", rows);

        // print first half of 8 bytes in hexadecimal format
        for (size_t i = 0; i < BYTES_PER_LINE >> 1; i++)
            std::printf("%02x ", bytes[i]);

        std::putchar(' ');

        // print second half of 8 bytes in hexadecimal format
        for (size_t i = BYTES_PER_LINE >> 1; i < BYTES_PER_LINE; i++)
            std::printf("%02x ", bytes[i]);

        // print string representation of bytes
        std::printf("%s", "  |");
        for (const auto& ch : line)
            std::putchar(ch);

        std::putchar('|');
        std::putchar('\n');

        rows += 0x10;
    }
}

in_addr_t get_ip_address(const std::string_view& target) noexcept
{
    // handle localhost
    if (target.compare("localhost") == 0)
        return inet_addr("127.0.0.1");

    sockaddr_in addr;

    // handle string representation of IP address
    if (inet_pton(AF_INET, target.data(), &(addr.sin_addr)) != 0)
        return addr.sin_addr.s_addr;
    else {
        // handle hostname
        hostent *he = gethostbyname(target.data());

        if (!he)
            utils::error("ntool: ping: cannot resolve the target");

        addr.sin_addr = *reinterpret_cast<in_addr*>(he->h_addr);
        return addr.sin_addr.s_addr;
    }
}


} // namespace utils
} // namespace ntool