#[cfg(unix)]
fn main()
{
    let mut sandbox_ipc_socket_found = false;
    for entry in std::fs::read_dir("/proc/self/fd/").expect("unable to read directory") {
        let entry = entry.expect("unable to read entry");
        let mut path = entry.path();
        loop {
            match std::fs::read_link(&path) {
                Ok(target) => path = target,
                Err(_) => break,
            }
        }
        let path = path.to_string_lossy();
        if path == format!("/proc/{}/fd", std::process::id()) {
            continue; // ignore the file descriptor from the /proc/self/fd/ enumeration itself
        }
        if path.starts_with("/dev/pts/") {
            continue; // ignore the file descriptor from stdout/stderr
        }
        if path.starts_with("socket:[") && !sandbox_ipc_socket_found {
            sandbox_ipc_socket_found = true; // ignore exactly one Unix socket, the one we use to communicate with our broker
            continue;
        }
        panic!("File descriptor leaked into worker process: {}", path);
    }
}

