use std::fs::File;
use iris::{Policy, Worker, set_handle_inheritable};
use common::{get_worker_bin_path, check_worker_handles};

// Voluntarily set up resources (opened handles and file descriptors)
// ready to be leaked into our children. This could be the result of
// e.g. a poorly written parent program, or a poorly written plugin/AV
// injected into it or into its parents.

#[cfg(unix)]
fn os_specific_setup() {
    use std::os::unix::io::IntoRawFd;
    use std::net::TcpListener;
    use std::convert::TryInto;

    let f = File::open("/etc/hosts").expect("opening generic test file failed");
    let leak = f.into_raw_fd();
    set_handle_inheritable(leak.try_into().unwrap(), true).unwrap();

    let s = TcpListener::bind("127.0.0.1:0").expect("opening generic test socket failed");
    let leak = s.into_raw_fd();
    set_handle_inheritable(leak.try_into().unwrap(), true).unwrap();
}

#[cfg(windows)]
fn os_specific_setup() {
    use std::os::windows::io::IntoRawHandle;
    let f = File::open("C:\\Windows\\System32\\drivers\\etc\\hosts").expect("opening generic test file failed");
    let leak = f.into_raw_handle();
    set_handle_inheritable(leak as u64, true).unwrap();
}

#[test]
fn inherited_resources_sanitized()
{
    os_specific_setup();

    // Don't allow any resource to be inherited by the worker process, and see if it still gets one
    let policy = Policy::new();

    let worker_binary = get_worker_bin_path();
    let mut worker = Worker::new(&policy, &worker_binary, &[&worker_binary], &[], None, None, None).expect("worker creation failed");
    
    // When Worker::new() returns, execve/CreateProcess has returned but the process might be in the middle of acquiring
    // more resources. Wait for all resources to be acquired.
    std::thread::sleep(std::time::Duration::new(2, 0));
    check_worker_handles(&worker);

    assert_eq!(worker.wait_for_exit(), Ok(0), "worker wait_for_exit failed");
}

