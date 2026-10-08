fn main() {
    std::process::exit(simple_connect_core::ssh::helper::run_if_helper().unwrap_or(2));
}
