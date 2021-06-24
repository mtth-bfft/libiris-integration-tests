use std::ffi::{CString, OsString};
use std::fs::File;
use std::net::TcpListener;
use std::convert::TryInto;
use iris::{Policy, Worker, set_handle_inheritable};

// Voluntarily set up resources (opened handles and file descriptors)
// ready to be leaked into our children. This could be the result of
// e.g. a poorly written parent program, or a poorly written plugin/AV
// injected into it or into its parents.

#[cfg(unix)]
fn os_specific_setup() {
    use std::os::unix::io::IntoRawFd;

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

// Check for open resources in another process, and panic if a resource is unexpected

#[cfg(unix)]
fn os_specific_check(worker: &Worker) {
    let mut sandbox_ipc_socket_found = false;
    for entry in std::fs::read_dir(format!("/proc/{}/fd/", worker.get_pid())).expect("unable to read /proc/x/fd/ directory") {
        let entry = entry.expect("unable to read /proc/x/fd/ entry");
        let mut path = entry.path();
        loop {
            match std::fs::read_link(&path) {
                Ok(target) => path = target,
                Err(_) => break,
            }
        }
        let path = path.to_string_lossy();
        // Stdin, stdout, and stderr can be redirected to /dev/null (harmless)
        if path == "/dev/null" {
            continue;
        }
        if path.starts_with("socket:[") && !sandbox_ipc_socket_found {
            sandbox_ipc_socket_found = true; // ignore exactly one Unix socket, the one we use to communicate with our broker
            continue;
        }
        panic!("File descriptor leaked into worker process: {}", path);
    }
}

#[cfg(windows)]
fn os_specific_check(worker: &Worker) {
     assert_eq!(true, false);
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

    os_specific_setup();

    // Don't allow any resource to be inherited by the worker process, and see if it still gets one
    let policy = Policy::new();

    let mut worker = Worker::new(&policy, &worker_binary, &[&worker_binary], &[], None, None, None).expect("worker creation failed");
    
    // When Worker::new() returns, execve/CreateProcess has returned but the process might be in the middle of acquiring
    // more resources. Wait for all resources to be acquired.
    std::thread::sleep(std::time::Duration::new(2, 0));
    os_specific_check(&worker); // FIXME: move into the worker process to avoid the need for a hardcoded sleep() (if possible to enumerate from within on windows)

    assert_eq!(worker.wait_for_exit(), Ok(0), "worker wait_for_exit failed");
}

