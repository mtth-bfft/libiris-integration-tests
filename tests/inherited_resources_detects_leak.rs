use core::ptr::null_mut;
use iris::{Policy, Worker};
use common::{get_worker_bin_path, check_worker_handles};

// Voluntarily set up resources (opened handles and file descriptors)
// ready to be leaked into our children. This could be the result of
// e.g. a poorly written parent program, or a poorly written plugin/AV
// injected into it or into its parents.

#[cfg(unix)]
fn os_specific_setup(worker: &Worker) {
   unimplemented!();
}

#[cfg(windows)]
fn os_specific_setup(worker: &Worker) {
    use std::convert::TryInto;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::handleapi::{DuplicateHandle, CloseHandle};
    use winapi::um::processthreadsapi::{OpenProcess, GetCurrentProcess};
    use winapi::um::winnt::{HANDLE, PROCESS_ALL_ACCESS, PROCESS_DUP_HANDLE};

    let h_worker = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, worker.get_pid().try_into().unwrap()) };
    assert_ne!(h_worker, null_mut(), "OpenProcess(worker) failed with error {}", unsafe { GetLastError() });
    // Voluntarily inject a full-privilege handle to ourselves into the worker
    let mut _unused: HANDLE = null_mut();
    let res = unsafe { DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), h_worker, &mut _unused as *mut _, PROCESS_ALL_ACCESS, 0, 0) };
    assert_ne!(res, 0, "DuplicateHandle() failed with error {}", unsafe { GetLastError() });
    unsafe { CloseHandle(h_worker) };
}

#[test]
#[should_panic(expected = "process")]
fn inherited_resources_detects_leak()
{
    let worker_binary = get_worker_bin_path();
    let policy = Policy::new(); // don't allow any resource to be inherited by the worker process
    let worker = Worker::new(&policy, &worker_binary, &[&worker_binary], &[], None, None, None).expect("worker creation failed");
    std::thread::sleep_ms(1000);
    os_specific_setup(&worker);
    check_worker_handles(&worker);
}

