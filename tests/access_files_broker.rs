mod common;
use common::{open_tmp_out, file_as_handle, cleanup};
use std::ffi::{CString, OsString};
use iris::{Policy, Worker};

#[test]
fn access_files()
{
    let exe = std::env::current_exe().unwrap();
    let ext = exe.extension().and_then(|e| Some(OsString::from(e)));
    let mut dir = exe.clone();
    let mut worker_binary;
    loop {
        dir = dir.parent().expect(&format!("worker binary not found in any parent directory of {}", exe.to_string_lossy())).to_path_buf();
        worker_binary = dir.with_file_name("access_files_worker");
        if let Some(ext) = &ext {
            worker_binary.set_extension(ext);
        }
        if worker_binary.exists() {
            break;
        }
    }
    let worker_binary = CString::new(worker_binary.as_os_str().to_string_lossy().as_bytes()).unwrap();

    // Don't allow any file to be accessed
    let policy = Policy::new();
    let (tmpout, tmppath) = open_tmp_out();
    let mut worker = Worker::new(&policy, &worker_binary, &[&worker_binary], &[], None, Some(file_as_handle(&tmpout)), Some(file_as_handle(&tmpout))).expect("worker creation failed");
    assert_eq!(worker.wait_for_exit(), Ok(0), "worker reported an error, see its output log");
    cleanup(&tmppath);
}

