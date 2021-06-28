#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

#[cfg(windows)]
fn main()
{
    use core::ptr::null_mut;
    use std::ffi::CString;
    use winapi::um::fileapi::CreateFileA;
    use winapi::um::winnt::{FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE};
    use winapi::um::winbase::FILE_FLAG_BACKUP_SEMANTICS;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::shared::winerror::ERROR_ACCESS_DENIED;
    use winapi::um::fileapi::OPEN_EXISTING;
    use winapi::um::handleapi::INVALID_HANDLE_VALUE;

    // Even a LPAC (S-1-15-2-2) can read /etc/hosts , check that we can (at least) read that
    let filepath = CString::new("C:\\Windows\\System32\\drivers\\etc\\hosts").unwrap();
    let res = unsafe { CreateFileA(filepath.as_ptr(), FILE_READ_DATA, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, null_mut(), OPEN_EXISTING, 0, null_mut()) };
    if res == INVALID_HANDLE_VALUE {
        panic!("Could not open: error {}", unsafe { GetLastError() });
    }

    // Everyone (S-1-1-0) can list the contents of C:\Users, check that we cannot do that
    let filepath = CString::new("C:\\Users").unwrap();
    let res = unsafe { CreateFileA(filepath.as_ptr(), FILE_READ_DATA, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, null_mut(), OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, null_mut()) };
    let err = unsafe { GetLastError() };
    if res != INVALID_HANDLE_VALUE || err != ERROR_ACCESS_DENIED {
        panic!("Opening didn't fail as expected: error {}", err);
    }
}

#[cfg(unix)]
fn main()
{
    use std::ffi::CString;

    // Everyone can read /etc/hosts, check that we cannot do that
    let filepath = CString::new("/etc/hosts").unwrap();
    let res = unsafe { libc::open(filepath.as_ptr(), libc::O_RDONLY) };
    if res >= 0 {
        panic!("Opening didn't fail as expected");
    }
    let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    panic!("OPEN = {}", err);
}
