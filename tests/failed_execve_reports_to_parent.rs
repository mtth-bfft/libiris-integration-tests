use std::ffi::{CString, OsString};
use iris::{Policy, Worker};

#[test]
fn failed_execve_reports_to_parent()
{
    let worker_binary = CString::new("nonexistent").unwrap();
    let policy = Policy::new();
    let worker = Worker::new(&policy, &worker_binary, &[&worker_binary], &[]);
    assert!(worker.is_err(), "worker creation should have failed");
}

