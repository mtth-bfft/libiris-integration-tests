#[cfg(windows)]
fn main()
{
    use winapi::um::debugapi::{IsDebuggerPresent, DebugBreak};
    // Just wait for our parent to finish checking which resources
    // we currently hold then kill us.
    while unsafe { IsDebuggerPresent() } == 0 {
        ()
    }
    unsafe { DebugBreak(); }
}

#[cfg(unix)]
fn main()
{
    unimplemented!();
}

