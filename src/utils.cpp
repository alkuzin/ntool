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
#include <print>

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

} // namespace utils
} // namespace ntool