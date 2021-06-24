fn main()
{
    // Just wait for our parent to finish checking which resources
    // we currently hold then kill us.
    std::thread::sleep(std::time::Duration::new(5, 0));
}

