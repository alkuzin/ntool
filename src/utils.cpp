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
#include <unistd.h>
#include <cstring>
#include <cstdio>


namespace ntool {
namespace utils {

void terminate_if_not_root(void)
{
    if (geteuid() != 0)
        error("[ERROR] the process is not running as root");
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
static inline char to_print(std::uint8_t ch)
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

} // namespace utils
} // namespace ntool