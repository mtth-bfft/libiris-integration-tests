use std::ffi::{CString, OsString};
use iris::{Policy, Worker};

#[test]
fn spawn_broker()
{
    let exe = std::env::current_exe().unwrap();
    let ext = exe.extension().and_then(|e| Some(OsString::from(e)));
    let mut dir = exe;
    let mut worker_binary;
    loop {
        dir = dir.parent().expect("worker binary not found in any parent directory").to_path_buf();
        worker_binary = dir.with_file_name("01_spawn_worker");
        if let Some(ext) = &ext {
            worker_binary.set_extension(ext);
        }
        if worker_binary.exists() {
            break;
        }
    }
    let worker_binary = CString::new(worker_binary.as_os_str().to_string_lossy().as_bytes()).unwrap();

    let policy = Policy::new();
    let mut worker = Worker::new(&policy, &worker_binary, &[&worker_binary], &[]).expect("worker creation failed");
    worker.wait_for_exit().expect("worker wait_for_exit failed");
}

