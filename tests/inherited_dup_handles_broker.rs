mod common;
use common::{open_tmp_out, file_as_handle, cleanup};
use std::ffi::{CString, OsString};
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::io::Write;
use std::convert::TryInto;
use iris::{Policy, Worker, set_handle_inheritable};

#[test]
fn inherited_dup_handles()
{
    let exe = std::env::current_exe().unwrap();
    let ext = exe.extension().and_then(|e| Some(OsString::from(e)));
    let mut dir = exe.clone();
    let mut worker_binary;
    loop {
        dir = dir.parent().expect(&format!("worker binary not found in any parent directory of {}", exe.to_string_lossy())).to_path_buf();
        worker_binary = dir.with_file_name("inherited_dup_handles_worker");
        if let Some(ext) = &ext {
            worker_binary.set_extension(ext);
        }
        if worker_binary.exists() {
            break;
        }
    }
    let worker_binary = CString::new(worker_binary.as_os_str().to_string_lossy().as_bytes()).unwrap();

    let (tmpout, tmpoutpath) = open_tmp_out(); // duplicate tmpout as stdout and stderr and a handle to be inherited
    let (tmpin, tmpinpath) = open_tmp_out(); // duplicate tmpin as stdin and a handle to be inherited
    let mut policy = Policy::new();
    policy.allow_inherit_resource(file_as_handle(&tmpout));
    policy.allow_inherit_resource(file_as_handle(&tmpin));

    let mut worker = Worker::new(&policy, &worker_binary, &[&worker_binary], &[], Some(file_as_handle(&tmpin)), Some(file_as_handle(&tmpout)), Some(file_as_handle(&tmpout))).expect("worker creation failed");
    assert_eq!(worker.wait_for_exit(), Ok(0), "worker reported an error");
    cleanup(&tmpoutpath);
    cleanup(&tmpinpath);
}

