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
 * @file  traceroute.hpp
 * @brief Network diagnostic tool used for displaying possible routes (paths)
 * and transit delays of packets across an Internet Protocol (IP) network.
 *
 * @author Alexander Kuzin (<a href="https://github.com/alkuzin">alkuzin</a>)
 * @date   16.10.2024
 */

#ifndef _NTOOL_TRACEROUTE_HPP_
#define _NTOOL_TRACEROUTE_HPP_

namespace ntool {

/**
 * @brief Display trace route of given target.
 *
 * @param [in] target - given target to display.
 */
void traceroute(const char *target) noexcept;

} // namespace ntool

#endif // _NTOOL_TRACEROUTE_HPP_