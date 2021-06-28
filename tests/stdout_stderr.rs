use std::io::{Seek, SeekFrom, Write};
use iris::{Policy, Worker};
use common::{get_worker_bin_path, open_tmp_file, file_as_handle, cleanup_tmp_file};

#[test]
fn stdout_stderr()
{
    let policy = Policy::new();
    let (mut tmpin, tmpinpath) = open_tmp_file();
    let (tmpout, tmpoutpath) = open_tmp_file();
    let (tmperr, tmperrpath) = open_tmp_file();
    tmpin.write_all(b"OK_STDIN").unwrap();
    tmpin.seek(SeekFrom::Start(0)).unwrap();
    let worker_binary = get_worker_bin_path();
    let mut worker = Worker::new(&policy, &worker_binary, &[&worker_binary], &[], Some(file_as_handle(&tmpin)), Some(file_as_handle(&tmpout)), Some(file_as_handle(&tmperr))).expect("worker creation failed");
    assert_eq!(worker.wait_for_exit(), Ok(0), "worker wait_for_exit failed");
    assert_eq!(std::fs::read_to_string(&tmpoutpath).expect("failed to read stdout"), "OK_STDOUT\n".to_owned(), "unexpected value from stdout");
    assert_eq!(std::fs::read_to_string(&tmperrpath).expect("failed to read stderr"), "OK_STDERR\n".to_owned(), "unexpected value from stderr");
    cleanup_tmp_file(&tmpinpath);
    cleanup_tmp_file(&tmpoutpath);
    cleanup_tmp_file(&tmperrpath);
}

