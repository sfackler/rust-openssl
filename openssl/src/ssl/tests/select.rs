use libc;
pub use self::imp::*;

extern "system" {
    #[link_name = "select"]
    fn raw_select(nfds: libc::c_int,
                  readfds: *mut fd_set,
                  writefds: *mut fd_set,
                  errorfds: *mut fd_set,
                  timeout: *mut libc::timeval) -> libc::c_int;
}

#[cfg(unix)]
mod imp {
    use std::os::unix::prelude::*;
    use std::io;
    use libc;

    const FD_SETSIZE: usize = 1024;

    #[repr(C)]
    pub struct fd_set {
        fds_bits: [u64; FD_SETSIZE / 64]
    }

    pub fn fd_set<F: AsRawFd>(set: &mut fd_set, f: &F) {
        let fd = f.as_raw_fd() as usize;
        set.fds_bits[fd / 64] |= 1 << (fd % 64);
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
        let rc = super::raw_select(max.as_raw_fd() + 1, read, write, error,
                                   &mut timeout);
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc != 0)
        }
    }
}

#[cfg(windows)]
mod imp {
    use std::os::windows::prelude::*;
    use std::io;
    use libc::{SOCKET, c_uint, c_long, timeval};

    const FD_SETSIZE: usize = 64;

    #[repr(C)]
    pub struct fd_set {
        fd_count: c_uint,
        fd_array: [SOCKET; FD_SETSIZE],
    }

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
        let mut timeout = timeval {
            tv_sec: (timeout_ms / 1000) as c_long,
            tv_usec: (timeout_ms % 1000 * 1000) as c_long,
        };
        let rc = super::raw_select(1, read, write, error, &mut timeout);
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc != 0)
        }
    }
}
