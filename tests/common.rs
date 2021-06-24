use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::convert::TryInto;
use iris::{set_handle_inheritable};

pub fn open_tmp_out() -> (File, PathBuf) {
    let mut tmpdir = std::env::temp_dir();
    for i in 1..200000 {
        tmpdir.push(format!("tmp_test_{}", i));
        if let Ok(f) = OpenOptions::new().read(true).write(true).create_new(true).open(&tmpdir) {
            println!("Storing temporary output to {}", tmpdir.display());
            let handle = file_as_handle(&f);
            set_handle_inheritable(handle, true).unwrap();
            return (f, tmpdir);
        }
        tmpdir.pop();
    }
    panic!("No writable location found for temporary test logs");
}

#[cfg(unix)]
pub fn file_as_handle(f: &File) -> u64 {
    use std::os::unix::io::AsRawFd;
    f.as_raw_fd().try_into().unwrap()
}

#[cfg(windows)]
pub fn file_as_handle(f: &File) -> u64 {
    use std::os::windows::io::AsRawHandle;
    f.as_raw_handle() as u64
}

pub fn cleanup(path: &Path) {
    std::fs::remove_file(path).expect(&format!("Unable to remove temporary file {}", path.display()));
}


