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
#include <ntool/ping.hpp>
#include <getopt.h>
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
        "    -h, --help                   display list of commands\n"
        "    --tr [options] [target]      get trace route to target\n"
        "        -m [N]                   set max hops\n"
        "        -q [N]                   set max queries\n"
        "\n"
        "EXAMPLES\n"
        "    ntool --ping 127.0.0.1       ping IP address\n"
        "    ntool --ping example.com     ping hostname\n"
        "    ntool --ping -n 6 127.0.0.1  ping 6 times\n"
        "\n"
        "    ntool --tr 127.0.0.1         traceroute IP address\n"
        "    ntool --tr example.com       traceroute hostname\n"
        "\n"
        "    traceroute target with 10 max hops & 4 max queries:\n"
        "    ntool --tr -m 10 -q 4 example.com       traceroute hostname\n"
        "\n"
    );
    std::exit(EXIT_SUCCESS);
}

int main(std::int32_t argc, char **argv)
{
    using namespace ntool::utils;
    terminate_if_not_root();

    if (argc < 2)
        help();

    static option long_options[] {
        {"ping", no_argument, 0, 0},
        {"tr", no_argument, 0, 1},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    std::int32_t opt, ping_count = 0;
    bool is_ping = false;

    std::int32_t hops, queries = 0;
    bool is_tr   = false;

    while ((opt = getopt_long(argc, argv, "hn:m:q:", long_options, 0)) != -1) {
        switch (opt) {
        // handle --ping
        case 0:
            is_ping = true;
            is_tr   = false;
            break;

        // handle --ping -n [N]
        case 'n':
            ping_count = std::atoi(optarg);
            break;

        // handle --tr
        case 1:
            is_tr   = true;
            is_ping = false;
            break;

        // handle --tr -m [N]
        case 'm':
            hops = std::atoi(optarg);
            break;

        // handle --tr -q [N]
        case 'q':
            queries = std::atoi(optarg);
            break;

        // handle -h, --help
        case 'h':
            help();
            break;

        // handle unknown options
        case '?':
            error("Use -h or --help for usage.\n");
            help();
            break;

        default:
            break;
        }
    }

    if (is_ping) {
        if (optind < argc)
            ntool::ping(argv[optind], std::abs(ping_count));
        else
            error("ntool: expected target after --ping option");
    }
    else if (is_tr) {
        if (optind < argc)
            ntool::traceroute(argv[optind], std::abs(hops), std::abs(queries));
        else
            error("ntool: expected target after --tr option");
    }
    else
        help();

    return 0;
}