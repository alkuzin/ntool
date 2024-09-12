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

#include <ntool/raw_socket.hpp>
#include <ntool/utils.hpp>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

namespace ntool {
    
    RawSocket::RawSocket(void)
    {
        m_protocol = IPPROTO_RAW;
        m_domain   = AF_INET;
        m_sockfd   = -1;

        init();
    }

    RawSocket::RawSocket(int domain, int protocol)
    {
        m_protocol = protocol;
        m_domain   = domain;

        init();
    }

    void RawSocket::init(void)
    {
        m_sockfd = socket(m_domain, SOCK_RAW, m_protocol);

        if (m_sockfd < 0)
            utils::error("[ERROR] raw socket creation error");
    }

    RawSocket::~RawSocket(void)
    {
        int ret = close(m_sockfd);

        if (ret == -1)
            utils::error("[ERROR] error to close raw socket");
    }

    int RawSocket::protocol(void) const
    {
        return m_protocol;
    }
    
    int RawSocket::domain(void) const
    {
        return m_domain;
    }

    int RawSocket::fd(void) const
    {
        return m_sockfd;
    }

} // namespace ntool