use libc;
use nix;
use nix::errno::Errno;
use nix::sys::socket::GetSockOpt;
use nix::Result;
use std::os::unix::io::RawFd;

// Define the SO_COOKIE option
#[derive(Debug, Clone, Copy)]
pub struct SoCookie;

impl GetSockOpt for SoCookie {
    type Val = u64;

    fn get(&self, fd: RawFd) -> Result<Self::Val> {
        unsafe {
            let mut val: u64 = 0;
            let mut len = std::mem::size_of::<u64>() as libc::socklen_t;
            let ret = libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_COOKIE,
                &mut val as *mut _ as *mut libc::c_void,
                &mut len,
            );
            Errno::result(ret).map(|_| val)
        }
    }
}
