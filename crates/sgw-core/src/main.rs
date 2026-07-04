use sgw_core::ExecuteRequest;
use std::io::{self, Read};

fn main() {
    let command = std::env::args().nth(1).unwrap_or_default();
    if command == "--version" || command == "version" {
        println!("sgw-core {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if command != "execute" {
        fail("Usage: sgw-core execute");
    }

    let mut input = Vec::new();
    if io::stdin().read_to_end(&mut input).is_err() {
        fail("Unable to read the execution request.");
    }
    let request: ExecuteRequest = match serde_json::from_slice(&input) {
        Ok(value) => value,
        Err(_) => fail("Invalid execution request."),
    };

    match sgw_core::execute(request) {
        Ok(summary) => match serde_json::to_string(&summary) {
            Ok(output) => println!("{output}"),
            Err(_) => fail("Unable to encode the execution result."),
        },
        Err(message) => fail(&message),
    }
}

fn fail(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}
