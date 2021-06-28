const FORBIDDEN_VARS: &[&str] = &[
    "PATH",
    "HOME",
    "HOMEPATH",
    "OneDrive",
];

fn main()
{
    for (var, val) in std::env::vars() {
        if FORBIDDEN_VARS.contains(&var.as_str()) {
            panic!("{} leaked in environment: {}", var, val);
        }
    }
}

