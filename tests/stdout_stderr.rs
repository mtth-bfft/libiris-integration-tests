mod common;
use common::{open_tmp_out, file_as_handle, cleanup};
use std::io::{Write, Seek, SeekFrom};
use std::ffi::{CString, OsString};
use iris::{Policy, Worker};

#[test]
fn stdout_stderr_broker()
{
    let exe = std::env::current_exe().unwrap();
    let ext = exe.extension().and_then(|e| Some(OsString::from(e)));
    let mut dir = exe.clone();
    let mut worker_binary;
    loop {
        dir = dir.parent().expect(&format!("worker binary not found in any parent directory of {}", exe.to_string_lossy())).to_path_buf();
        worker_binary = dir.with_file_name("stdout_stderr_worker");
        if let Some(ext) = &ext {
            worker_binary.set_extension(ext);
        }
        if worker_binary.exists() {
            break;
        }
    }
    let worker_binary = CString::new(worker_binary.as_os_str().to_string_lossy().as_bytes()).unwrap();

    let policy = Policy::new();
    let (mut tmpin, tmpinpath) = open_tmp_out();
    let (tmpout, tmpoutpath) = open_tmp_out();
    let (tmperr, tmperrpath) = open_tmp_out();
    tmpin.write_all(b"OK_STDIN").unwrap();
    tmpin.seek(SeekFrom::Start(0)).unwrap();
    let mut worker = Worker::new(&policy, &worker_binary, &[&worker_binary], &[], Some(file_as_handle(&tmpin)), Some(file_as_handle(&tmpout)), Some(file_as_handle(&tmperr))).expect("worker creation failed");
    assert_eq!(worker.wait_for_exit(), Ok(0), "worker wait_for_exit failed");
    assert_eq!(std::fs::read_to_string(&tmpoutpath).expect("failed to read stdout"), "OK_STDOUT\n".to_owned(), "unexpected value from stdout");
    assert_eq!(std::fs::read_to_string(&tmperrpath).expect("failed to read stderr"), "OK_STDERR\n".to_owned(), "unexpected value from stderr");
    cleanup(&tmpinpath);
    cleanup(&tmpoutpath);
    cleanup(&tmperrpath);
}

