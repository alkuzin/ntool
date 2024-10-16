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
 * @file  utils.hpp
 * @brief Auxillar functions.
 *
 * @author Alexander Kuzin (<a href="https://github.com/alkuzin">alkuzin</a>)
 * @date   11.09.2024
 */

#ifndef _NTOOL_UTILS_HPP_
#define _NTOOL_UTILS_HPP_

#include <netinet/in.h>
#include <numeric>
#include <cstdint>
#include <string>


namespace ntool {
namespace utils {

/** @brief Checks if current process is running as root.*/
void terminate_if_not_root(void) noexcept;

/**
 * @brief Handle error.
 *
 * @param msg - given error message.
 */
void error(const std::string_view& msg) noexcept;

/**
 * @brief Calculate mean value of given container.
 *
 * @param [in] begin - given begin iterator.
 * @param [in] end - given end iterator.
 * @return mean value.
 */
template <typename Iterator>
double mean(Iterator begin, Iterator end) noexcept
{
    if (begin == end)
        return 0.0;

    return std::accumulate(begin, end, 0.0) / std::distance(begin, end);
}

/**
 * @brief Calculate mean deviation value of given container.
 *
 * @param [in] begin - given begin iterator.
 * @param [in] end - given end iterator.
 * @return mean deviation.
 */
template <typename Iterator>
double mdev(Iterator begin, Iterator end) noexcept
{
    if (begin == end)
        return 0.0;

    double m = mean(begin, end);
    double total_deviation = 0.0;

    for (Iterator it = begin; it != end; ++it)
        total_deviation += std::abs(*it - m);

    return total_deviation / std::distance(begin, end);
}

/**
 * @brief Dump memory.
 *
 * @param [in] addr - given memory address to dump.
 * @param [in] size - given number of bytes to dump.
 */
void memdump(const std::uint8_t *addr, std::size_t size) noexcept;

/**
 * @brief Get IP addres of target.
 *
 * @param [in] target - given target text representation.
 * @return IP address.
 */
in_addr_t get_ip_address(const std::string_view& target) noexcept;

} // namespace utils
} // namespace ntool

#endif // _NTOOL_UTILS_HPP_