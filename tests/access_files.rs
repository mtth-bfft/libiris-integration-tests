use iris::{Policy, Worker};
use common::{get_worker_bin_path, open_tmp_file, file_as_handle, cleanup_tmp_file};

#[test]
fn access_files()
{
    // Don't allow any file to be accessed
    let policy = Policy::new();
    let worker_binary = get_worker_bin_path();
    let (tmpout, tmppath) = open_tmp_file();
    let mut worker = Worker::new(&policy, &worker_binary, &[&worker_binary], &[], None, Some(file_as_handle(&tmpout)), Some(file_as_handle(&tmpout))).expect("worker creation failed");
    assert_eq!(worker.wait_for_exit(), Ok(0), "worker reported an error, see its output log");
    cleanup_tmp_file(&tmppath);
}

