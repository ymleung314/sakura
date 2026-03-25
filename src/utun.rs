use std::ffi::{CStr, CString};
use std::fmt::Display;
use std::io;
use std::mem;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

use bytemuck::must_cast_slice;

const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";

#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum UtunAddressFamily {
    Inet = libc::AF_INET as _,
    Inet6 = libc::AF_INET6 as _,
}

impl Display for UtunAddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            UtunAddressFamily::Inet => "IPv4",
            UtunAddressFamily::Inet6 => "IPv6",
        })
    }
}

#[derive(Debug)]
pub struct Utun {
    fd: OwnedFd,
    name: String,
}

#[derive(thiserror::Error, Debug)]
pub enum NewUtunError {
    #[error("cannot create KEXT control socket")]
    CreateSocket(io::Error),
    #[error("cannot set control target to utun for KEXT control socket")]
    SocketUtunControl(io::Error),
    #[error("cannot connect to KEXT control socket")]
    Connect(io::Error),
    #[error("cannot get utun interface name")]
    GetName(io::Error),
}

impl Utun {
    /// Creates a new `utun` interface with a system assigned unit number.
    pub fn new() -> Result<Self, NewUtunError> {
        Self::new_with_unit(0)
    }

    /// Creates a new `utun` interface with a specific unit number.
    ///
    /// Pass `0` to let the OS choose for you.
    pub fn new_with_unit(unit: u32) -> Result<Self, NewUtunError> {
        // MUST be move into the `Utun`.
        //
        // Placed at the beginning of the function to make sure that the fd is
        // closed automatically on error returns.
        let fd_owned = {
            let fd_raw =
                unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
            if fd_raw < 0 {
                return Err(NewUtunError::CreateSocket(io::Error::last_os_error()));
            }

            unsafe { OwnedFd::from_raw_fd(fd_raw) }
        };
        let fd = fd_owned.as_raw_fd();

        let mut info = libc::ctl_info {
            ctl_id: 0,
            ctl_name: [0; _],
        };

        // Note: This shouldn't fail as long as UTUN_CONTROL_NAME is valid, so we unwrap here.
        let ctl_name = CString::new(UTUN_CONTROL_NAME).unwrap();
        let ctl_name_bytes = ctl_name.as_bytes_with_nul();
        // Requirement: source slice length = destination slice length.
        info.ctl_name[..ctl_name_bytes.len()].copy_from_slice(must_cast_slice(ctl_name_bytes));

        if unsafe { libc::ioctl(fd, libc::CTLIOCGINFO, &mut info) } < 0 {
            return Err(NewUtunError::SocketUtunControl(io::Error::last_os_error()));
        }

        let addr = libc::sockaddr_ctl {
            sc_len: mem::size_of::<libc::sockaddr_ctl>() as libc::c_uchar,
            sc_family: libc::AF_SYSTEM as libc::c_uchar,
            ss_sysaddr: libc::AF_SYS_CONTROL as u16,
            sc_id: info.ctl_id,
            sc_unit: unit,
            sc_reserved: [0; _],
        };

        if unsafe {
            libc::connect(
                fd,
                &addr as *const libc::sockaddr_ctl as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
            )
        } < 0
        {
            return Err(NewUtunError::Connect(io::Error::last_os_error()));
        }

        let mut ifname_buf = [0u8; 256];
        let mut ifname_len = ifname_buf.len() as libc::socklen_t;

        if unsafe {
            libc::getsockopt(
                fd,
                libc::SYSPROTO_CONTROL,
                libc::UTUN_OPT_IFNAME,
                ifname_buf.as_mut_ptr() as *mut libc::c_void,
                &mut ifname_len,
            )
        } < 0
        {
            return Err(NewUtunError::GetName(io::Error::last_os_error()));
        }

        let name_cstr = CStr::from_bytes_until_nul(ifname_buf.as_slice())
            .map_err(|_| NewUtunError::GetName(io::Error::from(io::ErrorKind::OutOfMemory)))?;
        let name = name_cstr.to_string_lossy().into_owned();

        Ok(Utun { fd: fd_owned, name })
    }

    /// Creates an `Utun` from a raw file descriptor.
    ///
    /// Returns an error if the interface name cannot be retrieved.
    ///
    /// # Safety
    ///
    /// The file descriptor MUST be opened and valid.
    unsafe fn from_raw_fd_checked(fd: RawFd) -> io::Result<Self> {
        let mut ifname_buf = [0u8; 256];
        let mut ifname_len = ifname_buf.len() as libc::socklen_t;

        let name = if unsafe {
            libc::getsockopt(
                fd,
                libc::SYSPROTO_CONTROL,
                libc::UTUN_OPT_IFNAME,
                ifname_buf.as_mut_ptr() as *mut libc::c_void,
                &mut ifname_len,
            )
        } == 0
        {
            CStr::from_bytes_until_nul(ifname_buf.as_slice())
                .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?
                .to_string_lossy()
                .into_owned()
        } else {
            return Err(io::Error::last_os_error());
        };

        Ok(Utun {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            name,
        })
    }

    /// Returns the name of the interface (e.g., "utun0").
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut af_nl_bytes = [0u8; 4];

        let iov = [
            libc::iovec {
                iov_base: af_nl_bytes.as_mut_ptr() as *mut libc::c_void,
                iov_len: af_nl_bytes.len(),
            },
            libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            },
        ];

        let n = unsafe { libc::readv(self.fd.as_raw_fd(), iov.as_ptr(), iov.len() as i32) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        // TODO: Is it necessary to return af?
        // Exclude the size of header.
        Ok((n as usize) - af_nl_bytes.len())
    }

    pub fn write(&mut self, buf: &[u8], af: UtunAddressFamily) -> io::Result<usize> {
        // Endian for network.
        let af_nl_bytes = (af as u32).to_be_bytes();

        let iov = [
            libc::iovec {
                // SAFETY: `writev` does not modify buffers, this is safe.
                iov_base: af_nl_bytes.as_ptr() as *mut libc::c_void,
                iov_len: af_nl_bytes.len(),
            },
            libc::iovec {
                // SAFETY: `writev` does not modify buffers, this is safe.
                iov_base: buf.as_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            },
        ];

        let n = unsafe { libc::writev(self.fd.as_raw_fd(), iov.as_ptr(), iov.len() as i32) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        // Exclude the size of header.
        Ok((n as usize) - af_nl_bytes.len())
    }
}

impl AsRawFd for Utun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl IntoRawFd for Utun {
    fn into_raw_fd(self) -> RawFd {
        self.fd.into_raw_fd()
    }
}

impl FromRawFd for Utun {
    /// Creates an `Utun` from a raw file descriptor.
    ///
    /// If the interface name cannot be retrieved, the function panics.
    ///
    /// # Safety
    ///
    /// The file descriptor MUST be opened and valid.
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        unsafe { Self::from_raw_fd_checked(fd).expect("cannot get utun interface name") }
    }
}

impl Display for Utun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name)
    }
}
