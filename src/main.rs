mod diff;
mod scanner;
mod config;
mod output;

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    // exit codes: 0 = no secrets, 1 = secrets found, 2 = internal error
    0
}
