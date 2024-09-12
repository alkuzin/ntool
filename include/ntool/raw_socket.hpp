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
 * @file  raw_socket.hpp
 * @brief Raw socket wrapper.
 * 
 * @author Alexander Kuzin (<a href="https://github.com/alkuzin">alkuzin</a>)
 * @date   12.09.2024
 */

#ifndef _NTOOL_RAW_SOCKET_HPP_
#define _NTOOL_RAW_SOCKET_HPP_

namespace ntool {

    class RawSocket
    {
        int m_protocol; // protocol type
        int m_domain;   // address family
        int m_sockfd;   // socket file descriptor
    
    private:
        /** @brief Initialize raw socket.*/
        void init(void);

    public:
        /** @brief Raw socket default constructor.*/
        RawSocket(void);

        /**
         * @brief Construct a custom raw socket object.
         * 
         * @param [in] domain - given address family.
         * @param [in] protocol - given protocol type.
         */
        RawSocket(int domain, int protocol);

        /** @brief Raw socket virtual destructor.*/
        virtual ~RawSocket(void);

        /**
         * @brief Get protocol type.
         * 
         * @return protocol type.
         */
        int protocol(void) const;
        
        /**
         * @brief Get address family.
         * 
         * @return address family.
         */
        int domain(void) const;

        /**
         * @brief Get socket file descriptor.
         * 
         * @return socket file descriptor.
         */
        int fd(void) const;
    };
} // namespace ntool

#endif // _NTOOL_RAW_SOCKET_HPP_