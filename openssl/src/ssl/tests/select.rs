use libc;
pub use self::imp::*;

#[cfg(unix)]
mod imp {
    use std::os::unix::prelude::*;
    use std::io;
    use libc;

    pub use libc::fd_set;

    pub fn fd_set<F: AsRawFd>(set: &mut fd_set, f: &F) {
        unsafe {
            libc::FD_SET(f.as_raw_fd(), set);
        }
    }

    pub unsafe fn select<F: AsRawFd>(max: &F,
                                     read: *mut fd_set,
                                     write: *mut fd_set,
                                     error: *mut fd_set,
                                     timeout_ms: u32)
                                     -> io::Result<bool> {
        let mut timeout = libc::timeval {
            tv_sec: (timeout_ms / 1000) as libc::time_t,
            tv_usec: (timeout_ms % 1000 * 1000) as libc::suseconds_t,
        };
        let rc = libc::select(max.as_raw_fd() + 1, read, write, error, &mut timeout);
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc != 0)
        }
    }
}

#[cfg(windows)]
mod imp {
    extern crate winapi;
    extern crate ws2_32;

    use std::os::windows::prelude::*;
    use std::io;
    use libc::{c_uint, c_long};
    use self::winapi::SOCKET;
    use self::winapi::winsock2;

    pub use self::winapi::winsock2::fd_set;

    pub fn fd_set<F: AsRawSocket>(set: &mut fd_set, f: &F) {
        set.fd_array[set.fd_count as usize] = f.as_raw_socket();
        set.fd_count += 1;
    }

    pub unsafe fn select<F: AsRawSocket>(_max: &F,
                                         read: *mut fd_set,
                                         write: *mut fd_set,
                                         error: *mut fd_set,
                                         timeout_ms: u32)
                                         -> io::Result<bool> {
        let mut timeout = winsock2::timeval {
            tv_sec: (timeout_ms / 1000) as c_long,
            tv_usec: (timeout_ms % 1000 * 1000) as c_long,
        };
        let rc = ws2_32::select(1, read, write, error, &mut timeout);
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc != 0)
        }
    }
}
