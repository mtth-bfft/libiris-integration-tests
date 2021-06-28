#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use core::ptr::null_mut;
use std::fs::File;
use std::convert::TryInto;
use std::ffi::CString;
use std::os::windows::io::AsRawHandle;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::processthreadsapi::{OpenProcess, GetCurrentProcess};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{DuplicateHandle, CloseHandle};
use winapi::um::winnt::{PROCESS_DUP_HANDLE, DBG_CONTINUE, DUPLICATE_SAME_ACCESS};
use winapi::shared::ntdef::{HANDLE, NTSTATUS, WCHAR, USHORT, PVOID, PWSTR, ULONG, PULONG};
use winapi::shared::minwindef::{BYTE, DWORD};
use winapi::shared::ntstatus::{STATUS_SUCCESS, STATUS_INFO_LENGTH_MISMATCH};
use winapi::um::debugapi::{DebugActiveProcess, WaitForDebugEvent, ContinueDebugEvent, DebugActiveProcessStop};
use winapi::um::minwinbase::{EXCEPTION_DEBUG_EVENT, DEBUG_EVENT, EXCEPTION_BREAKPOINT};
use winapi::um::winbase::INFINITE;
use iris::Worker;

const MAX_NT_OBJECT_PATH_LEN: usize = 2048;
const SystemHandleInformation: ULONG = 16;

#[repr(u32)]
enum SYSTEM_INFORMATION_CLASS {
    SystemHandleInformation = 16,
}

#[repr(u32)]
enum OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation = 0,
    ObjectNameInformation = 1,
    ObjectTypeInformation = 2,
    ObjectAllInformation = 3,
}

#[derive(Debug, Clone)]
#[repr(C)]
struct SYSTEM_HANDLE {
    ProcessId: ULONG,
    ObjectTypeNumber: BYTE,
    Flags: BYTE,
    Handle: USHORT,
    Object: PVOID,
    GrantedAccess: DWORD,
}

#[repr(C)]
struct SYSTEM_HANDLE_INFORMATION {
    HandleCount: ULONG,
    Handles: [SYSTEM_HANDLE; 1],
}

#[repr(C)]
struct UNICODE_STRING {
    Length: USHORT,
    MaximumLength: USHORT,
    Buffer: PWSTR,
}

#[repr(C)]
struct PUBLIC_OBJECT_TYPE_INFORMATION {
    TypeName: UNICODE_STRING,
    Reserved: [ULONG; 22],
}

#[repr(C)]
struct OBJECT_NAME_INFORMATION {
    Name: UNICODE_STRING,
    Buffer: [WCHAR; MAX_NT_OBJECT_PATH_LEN],
}

#[repr(C)]
struct OBJECT_TYPE_INFORMATION {
    Name: UNICODE_STRING,
    Opaque: [u8; 88], // these struct are stored consecutively as an array, so we need to get their size right
}

#[repr(C)]
struct OBJECT_TYPES_INFORMATION {
    NumberOfObjectTypes: ULONG,
    ObjectTypes: [OBJECT_TYPE_INFORMATION; 256], // types are indexed in the kernel using a UCHAR so there can be only 256
   Opaque: [u8; 256 * 65536], // room for the UNICODE_STRING buffers from ObjectTypes[], whose size is indexed on USHORT (max 65536 bytes)
}

type FnNtQuerySystemInformation = unsafe extern "C" fn(SystemInformationClass: SYSTEM_INFORMATION_CLASS, SystemInformation: PVOID, SystemInformationLength: ULONG, ReturnLength: PULONG) -> NTSTATUS;
type FnNtQueryObject = unsafe extern "C" fn(Handle: HANDLE, ObjectInformationClass: OBJECT_INFORMATION_CLASS, ObjectInformation: PVOID, ObjectInformationLength: ULONG, ReturnLength: PULONG) -> NTSTATUS;

pub fn file_as_handle(f: &File) -> u64 {
    f.as_raw_handle() as u64
}

pub fn check_worker_handles(worker: &Worker) {

    // Freeze the worker process, so that we can atomically inspect its handles
    // Do it as early as possible, so that if we panic!(), the worker dies with us
    let res = unsafe { DebugActiveProcess(worker.get_pid().try_into().unwrap()) };
    assert_ne!(res, 0, "DebugActiveProcess({}) failed with error {}", worker.get_pid(), unsafe { GetLastError() });

    let hworker = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, worker.get_pid().try_into().unwrap()) };
    assert_ne!(hworker, null_mut(), "OpenProcess(PROCESS_DUP_HANDLE, worker) failed with error {}", unsafe { GetLastError() });

    // Wait for the worker to DebugBreak(), so that we know the process is fully initialized and in main()
    println!("Waiting for child to break into debugger...");
    let mut dbg_event: DEBUG_EVENT = unsafe { std::mem::zeroed() };
    let mut initial_breakpoint_hit = false;
    loop {
        let res = unsafe { WaitForDebugEvent(&mut dbg_event as *mut _, INFINITE) };
        assert_ne!(res, 0, "WaitForDebugEvent() failed with error {}", unsafe { GetLastError() });
        if dbg_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && unsafe { dbg_event.u.Exception() }.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT {
            if initial_breakpoint_hit {
                println!("Worker hit breakpoint, beginning inspection");
                break;
            }
            initial_breakpoint_hit = true;
        }
        // Resume the worker, otherwise it will hang at the first event (process creation) and never reach its main()
        unsafe { ContinueDebugEvent(dbg_event.dwProcessId, dbg_event.dwThreadId, DBG_CONTINUE); }
    }

    // Get pointers to NtQuerySystemInformation() and NtQueryObject() (undocumented, required to properly enumerate handles)
    let h_ntdll = unsafe { GetModuleHandleA(CString::new("ntdll.dll").unwrap().as_ptr()) };
    assert_ne!(h_ntdll, null_mut());
    let ntquerysysteminformation: FnNtQuerySystemInformation = unsafe { std::mem::transmute(GetProcAddress(h_ntdll, CString::new("NtQuerySystemInformation").unwrap().as_ptr())) };
    assert_ne!(ntquerysysteminformation as PVOID, null_mut());
    let ntqueryobject: FnNtQueryObject = unsafe { std::mem::transmute(GetProcAddress(h_ntdll, CString::new("NtQueryObject").unwrap().as_ptr())) };
    assert_ne!(ntqueryobject as PVOID, null_mut());

    // Fetch object type names (undocumented, but eases debugging by printing each handle's object type instead of an integer)
    // We can't just call NtQueryObject(NULL, ObjectAllInformation, NULL, 0, &getMeTheSize)
    // because the first 4 userland bytes are directly used as the final counter by the kernel,
    // so it needs them be allocated... Plus the returned "required buffer size" is not
    // computed correctly, which often triggers 16-byte heap overflows/corruption...
    // This syscall is so broken, at this point it's safer to use a "larger than will ever be
    // necessary" hardcoded buffer size.
    let mut return_length: ULONG = 0;
    let mut object_types: Vec<String> = vec![];
    unsafe {
        let mut buffer = vec![0u8; std::mem::size_of::<OBJECT_TYPES_INFORMATION>()];
        let res = ntqueryobject(null_mut(), OBJECT_INFORMATION_CLASS::ObjectAllInformation, buffer.as_mut_ptr() as *mut _, buffer.len().try_into().unwrap(), &mut return_length as *mut _);
        assert_eq!(res, STATUS_SUCCESS, "NtQueryObject(ObjectAllInformation) failed with status 0x{:X}", res);
        let buffer = buffer.as_ptr() as *const OBJECT_TYPES_INFORMATION;
        let number_of_object_types = (*buffer).NumberOfObjectTypes as usize;
        let mut ptr = &((*buffer).ObjectTypes) as *const OBJECT_TYPE_INFORMATION;
        for _ in 0..number_of_object_types {
            let slice = std::slice::from_raw_parts((*ptr).Name.Buffer, (*ptr).Name.Length as usize / 2);
            object_types.push(String::from_utf16_lossy(slice));
            let offset_to_next = ((*ptr).Name.MaximumLength as usize + std::mem::size_of::<PVOID>() - 1) & !(std::mem::size_of::<PVOID>() - 1);
            ptr = ((*ptr).Name.Buffer as *const u8).add(offset_to_next) as *const OBJECT_TYPE_INFORMATION;
        }
    }

    let mut buffer_size = 0x10000;
    let mut buffer = vec![0u8; buffer_size];
    let mut res = STATUS_INFO_LENGTH_MISMATCH;
    // The required buffer size returned by each call is obsolete as soon as it reaches us
    // (handles come and go). Grow exponentially until it fits, so that we have the guarantee
    // that the loop terminates in finite (log(N)) time
    while buffer_size <= 1024 * 1024 * 10 {
        res = unsafe { ntquerysysteminformation(SYSTEM_INFORMATION_CLASS::SystemHandleInformation, buffer.as_mut_ptr() as *mut _, buffer.len().try_into().unwrap(), &mut return_length as *mut _) };
        if res != STATUS_INFO_LENGTH_MISMATCH {
            break;
        }
        buffer_size *= 2;
        buffer.resize(buffer_size, 0);
    }
    assert_eq!(res, STATUS_SUCCESS);

    let handle_info = buffer.as_ptr() as *const _ as *const SYSTEM_HANDLE_INFORMATION;
    let handle_count = unsafe { (*handle_info).HandleCount } as usize;
    println!("{} handles reported by NtQuerySystemInformation", handle_count);
    let mut handles = vec![SYSTEM_HANDLE {
        ProcessId: 0,
        ObjectTypeNumber: 0,
        Flags: 0,
        Handle: 0,
        Object: null_mut(),
        GrantedAccess: 0,
    }; handle_count];
    unsafe { std::ptr::copy_nonoverlapping(&((*handle_info).Handles[0]) as *const SYSTEM_HANDLE, handles.as_mut_ptr(), handle_count); }

    // Find the worker process kernel object address, so that we can distinguish process handles to
    // itself and to other processes
    let mut worker_process_object = None;
    for handle in &handles {
        if handle.ProcessId == std::process::id() && handle.Handle == (hworker as usize).try_into().unwrap() {
            worker_process_object = Some(handle.Object);
            break;
        }
    }
    let worker_process_object = worker_process_object.expect("failed to enumerate system handles: handle to worker process not found");

    for handle in &handles {
        if u64::from(handle.ProcessId) != worker.get_pid() {
            continue;
        }
        // Get as much information as possible about that handle
        let obj_type = object_types[handle.ObjectTypeNumber as usize - 2].to_lowercase();
        let mut name = None;
        let mut copy: Option<HANDLE> = None;
        let mut other_holder_processes = Vec::new();
        for other_handle in &handles {
            if other_handle.Object != handle.Object || other_handle.ProcessId == handle.ProcessId {
                continue;
            }
            other_holder_processes.push(other_handle.ProcessId);
        }
        unsafe {
            let mut h_tmp: HANDLE = null_mut();
            let res = DuplicateHandle(hworker, handle.Handle as HANDLE, GetCurrentProcess(), &mut h_tmp as *mut _, 0, 0, DUPLICATE_SAME_ACCESS);
            if res != 0 {
                copy = Some(h_tmp);
            }
        }
        if let Some(copy) = copy {
            let mut name_info = OBJECT_NAME_INFORMATION {
                Name: UNICODE_STRING { Length: 0, MaximumLength: 0, Buffer: null_mut() },
                Buffer: [0; MAX_NT_OBJECT_PATH_LEN],
            };
            let mut res_len: ULONG = 0;
            let res = unsafe { ntqueryobject(copy, OBJECT_INFORMATION_CLASS::ObjectNameInformation, &mut name_info as *mut _ as *mut _, std::mem::size_of_val(&name_info) as u32, &mut res_len as *mut _) };
            if res == STATUS_SUCCESS && name_info.Name.Length > 0 {
                name = Some(String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(name_info.Name.Buffer, name_info.Name.Length as usize / 2) }));
            }
        }
        // Only tolerate an allow-list of types, each with type-specific conditions
        println!("> {} at {:?} number 0x{:X} granted access 0x{:X}", obj_type, handle.Object, handle.Handle, handle.GrantedAccess);
        if obj_type == "event" {
            // Tolerate named events if they can be opened with the worker's token
            if let Some(name) = name {
                unimplemented!("named event check");
            }
            // Tolerate anonymous events if they are not shared with outside processes
            else {
                assert_eq!(other_holder_processes, vec![], "anonymous event {} shared with other processes: {:?}", handle.Handle, other_holder_processes);
            }
        }
        else if obj_type == "waitcompletionpacket" || obj_type == "iocompletion" {
            // Exposed to userland through I/O completion ports
            println!("FIXME"); // see NtCreateIoCompletionPort() and NtOpenIoCompletionPort()
        }
        else if obj_type == "tpworkerfactory" {
            // We should not hold a handle to another process' thread pool, otherwise we could create arbitrary threads in it.
            // (even though documented APIs only allow creating a thread pool in the calling process, DuplicateHandle() works
            // on TpWorkerFactory handles, and NtCreateWorkerFactory() takes an abritrary process ID
            // (see https://www.microsoftpressstore.com/articles/article.aspx?p=2233328&seqNum=6)
            assert_eq!(other_holder_processes, vec![], "thread pool shared with other processes: {:?}", other_holder_processes);
        }
        else if obj_type == "irtimer" {
            // NtCreateIRTimer() calls are redirected in the kernel to NtCreateTimer2()
            // (see https://processhacker.sourceforge.io/doc/ntexapi_8h_source.html for an undocumented prototype)
            // Tolerate them as long as they are purely internal to our process (otherwise we might fire events in another process)
            assert_eq!(other_holder_processes, vec![], "irtimer shared with other processes: {:?}", other_holder_processes);
        }
        else if obj_type == "etwregistration" {
            // This object type cannot be duplicated between processes, so we cannot inspect it further.
            // Just make sure it stays this way.
            assert_ne!(copy.is_some(), true, "EtwRegistration handles should not be duplicatable between processes");
        }
        else if obj_type == "directory" {
            // /!\ This is a kernel object directory, not a file directory
            // Since this is a named object (can be opened by NtOpenDirectoryObject()), just check
            // that the process token allows opening it
            println!("/!\\ FIXME");
        }
        else if obj_type == "file" {
            // This can be a file, file directory, or named pipe
            println!("/!\\ FIXME");
        }
        else if obj_type == "key" {
            // A named registry key can be opened by name via NtCreateKey(), just check that the
            // process token allows opening it
        }
        else if obj_type == "alpc port" {
            // ALPC ports usually don't have security in themselves
            println!("/!\\ FIXME");
        }
        else if obj_type == "process" {
            // Only accept process handles to the worker process itself
            assert_eq!(handle.Object, worker_process_object, "worker should not hold a handle to another process");
        }
        else {
            panic!("unexpected object type {} (name: {}) (duplicatable: {})", obj_type, if let Some(name) = &name { name } else { "(none)" }, copy.is_some());
        }
        if let Some(copy) = copy {
            unsafe { CloseHandle(copy); }
        }
    }

    unsafe { CloseHandle(hworker); }

    // Unfreeze the worker process before we wait() for it to exit, otherwise we will hang
    unsafe { ContinueDebugEvent(dbg_event.dwProcessId, dbg_event.dwThreadId, DBG_CONTINUE); }
    let res = unsafe { DebugActiveProcessStop(worker.get_pid().try_into().unwrap()) };
    assert_ne!(res, 0, "DebugActiveProcessStop({}) failed with error {}", worker.get_pid(), unsafe { GetLastError() });
}

