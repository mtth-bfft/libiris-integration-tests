use iris::{Policy, Worker};
use common::{get_worker_bin_path, open_tmp_file, file_as_handle, cleanup_tmp_file};

#[test]
fn inherited_dup_handles()
{
    let (tmpout, tmpoutpath) = open_tmp_file(); // duplicate tmpout as stdout and stderr and a handle to be inherited
    let (tmpin, tmpinpath) = open_tmp_file(); // duplicate tmpin as stdin and a handle to be inherited
    let mut policy = Policy::new();
    policy.allow_inherit_resource(file_as_handle(&tmpout)).unwrap();
    policy.allow_inherit_resource(file_as_handle(&tmpin)).unwrap();

    let worker_binary = get_worker_bin_path();
    let mut worker = Worker::new(&policy, &worker_binary, &[&worker_binary], &[], Some(file_as_handle(&tmpin)), Some(file_as_handle(&tmpout)), Some(file_as_handle(&tmpout))).expect("worker creation failed");
    assert_eq!(worker.wait_for_exit(), Ok(0), "worker reported an error");
    cleanup_tmp_file(&tmpoutpath);
    cleanup_tmp_file(&tmpinpath);
}

