use iris::{Policy, Worker};
use common::get_worker_bin_path;

#[test]
fn spawn()
{
    let policy = Policy::new();
    let worker_binary = get_worker_bin_path();
    let mut worker = Worker::new(&policy, &worker_binary, &[&worker_binary], &[], None, None, None).expect("worker creation failed");
    assert_eq!(worker.wait_for_exit(), Ok(42), "worker wait_for_exit failed");
}

