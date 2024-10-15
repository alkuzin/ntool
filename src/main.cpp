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
#include <cstring>


static void help(void) noexcept
{
    std::puts(
        "USAGE\n"
        "    ntool [options]\n\n"
        "DESCRIPTION\n"
        "    ntool - multifunctional network analyser tool.\n\n"
        "OPTIONS\n"
        "    --ping [options] [target]    ping specific IP address/hostname\n"
        "        -n [N] [target]          ping N times\n"
        "\n"
        "EXAMPLES\n"
        "    ntool --ping 127.0.0.1       ping IP address\n"
        "    ntool --ping example.com     ping hostname\n"
        "    ntool --ping -n 6 127.0.0.1  ping 6 times\n"
        "\n"
    );
    std::exit(EXIT_SUCCESS);
}

int main(std::int32_t argc, char **argv)
{
    ntool::utils::terminate_if_not_root();

    if (argc < 2)
        help();

    if (std::strncmp(argv[1], "--ping", 6) == 0) {
        ntool::ping_t ping;

        // handle ntool --ping [target]
        if (argc == 3) {
            ping.init();
            ping.ping(argv[2]);
        }
        // handle ntool --ping -n [N] [target]
        else if (argc == 5 && std::strncmp(argv[2], "-n", 2) == 0) {
            ping.init();
            ping.ping(argv[4], std::stoi(argv[3]));
        }
        else {
            std::printf("ntool: ping: incorrect arguments\n\n");
            help();
        }
    }
    else {
        std::printf("ntool: incorrect option: \"%s\"\n\n", argv[1]);
        help();
    }

    return 0;
}