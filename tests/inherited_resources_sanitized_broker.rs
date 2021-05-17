use std::ffi::{CString, OsString};
use std::fs::File;
use std::net::TcpListener;
use std::convert::TryInto;
use iris::{Policy, Worker, set_handle_inheritance};
use libc;

// Voluntarily set up resources (opened handles and file descriptors)
// ready to be leaked into our children. This could be the result of
// e.g. a poorly written parent program, or a poorly written plugin/AV
// injected into it or into its parents.

#[cfg(unix)]
fn leak_resource() {
    use std::os::unix::io::IntoRawFd;

    let f = File::open("/etc/hosts").expect("opening generic test file failed");
    let leak = f.into_raw_fd();
    set_handle_inheritance(leak.try_into().unwrap(), true);
}

#[cfg(windows)]
fn leak_resource() {
    use std::os::windows::io::IntoRawHandle;
    let f = File::open("C:\\Windows\\System32\\drivers\\etc\\hosts").expect("opening generic test file failed");
    let leak = f.into_raw_handle();
    set_handle_inheritance(leak, true);
}

#[test]
fn inherited_resources_sanitized()
{
    let exe = std::env::current_exe().unwrap();
    let ext = exe.extension().and_then(|e| Some(OsString::from(e)));
    let mut dir = exe.clone();
    let mut worker_binary;
    loop {
        dir = dir.parent().expect(&format!("worker binary not found in any parent directory of {}", exe.to_string_lossy())).to_path_buf();
        worker_binary = dir.with_file_name("inherited_resources_sanitized_worker");
        if let Some(ext) = &ext {
            worker_binary.set_extension(ext);
        }
        if worker_binary.exists() {
            break;
        }
    }
    let worker_binary = CString::new(worker_binary.as_os_str().to_string_lossy().as_bytes()).unwrap();

    leak_resource();

    let mut policy = Policy::new();
    policy.allow_inherit_resource(1);
    policy.allow_inherit_resource(2);
    // Don't allow any resource to be inherited by the worker process, and see if it still gets one
    let mut worker = Worker::new(&policy, &worker_binary, &[&worker_binary], &[], true).expect("worker creation failed");
    assert_eq!(worker.wait_for_exit(), Ok(0), "worker wait_for_exit failed");
}

