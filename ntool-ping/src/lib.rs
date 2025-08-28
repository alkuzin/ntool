// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present ntool project and contributors.

//! Network diagnostic tool used to test the reachability
//! of a host on an Internet Protocol (IP) network.

use std::{os::{fd::{FromRawFd, OwnedFd}, raw::c_void}, ptr::addr_of, ffi::CStr};
use libc::*;

/// TODO: move to utils module.
/// Get errno error string.
///
/// # Return
/// - Errno error in string representation.
fn errno_error() -> String {
    let str = unsafe { CStr::from_ptr(strerror(*__errno_location())) };
    str.to_string_lossy().to_string()
}

/// Ping handling struct.
pub struct Ping {
    /// Raw socket file descriptor.
    sockfd: OwnedFd,
}

impl Ping {
    /// Construct new `Ping` object.
    ///
    /// # Return
    /// - New `Ping` object - in case of success.
    /// - `Err` - otherwise.
    pub fn new() -> Result<Self, String> {
        // Create raw socket.
        // AF_INET - use IPv4.
        // SOCK_RAW - raw socket mode.
        // IPPROTO_ICMP - use ICMP protocol.
        let sockfd = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) };

        if sockfd == -1 {
            return Err(format!("Error to create raw socket: {}", errno_error()));
        }

        // Set time limit for receiving packet.
        let timeout = timeval {
            tv_sec: 2,  // Seconds.
            tv_usec: 0, // Milliseconds.
        };

        let timeout_ptr  = addr_of!(timeout) as *const c_void;
        let timeout_size = size_of::<timeval>() as socklen_t;

        // SOL_SOCKET - constant for socket-level options
        // that are protocol independent.
        // SO_RCVTIMEO - parameter for setting time limit for receiving packet.
        let ret = unsafe {
            setsockopt(
                sockfd, SOL_SOCKET, SO_RCVTIMEO, timeout_ptr, timeout_size
            )
        };

        if ret == -1 {
            return Err(format!("Error to set timeout: {}", errno_error()));
        }

        let sockfd = unsafe { OwnedFd::from_raw_fd(sockfd) };

        let ping = Self {
            sockfd,
        };

        Ok(ping)
    }

    /// Ping specific target.
    ///
    /// # Parameters
    /// - `target` - given target IP address/hostname to ping.
    /// - `count` - given number of pings.
    pub fn ping(&self, target: &str, count: usize) -> Result<(), String> {
        if target.is_empty() {
            return Err("Ping target cannot be empty".to_string());
        }

        let ping_range = 1..u8::MAX as usize;

        if !ping_range.contains(&count) {
            let err = format!("Ping count should be in range {:#?}", ping_range);
            return Err(err);
        }

        Ok(())
    }

}
