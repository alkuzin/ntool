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

#include <string>

namespace ntool {
namespace utils {

/** @brief Checks if current process is running as root.*/
void terminate_if_not_root(void);

/**
 * @brief Handle error.
 * 
 * @param msg - given error message.
 */
void error(const std::string_view& msg);

} // namespace utils
} // namespace ntool

#endif // _NTOOL_UTILS_HPP_