#![allow(unreachable_code)]
#[macro_use]
extern crate rouille;

use std::process;

fn main() {
    println!("Running server: port=8080, process_id={}", process::id());

    // The `start_server` starts listening forever on the given address.
    rouille::start_server("0.0.0.0:8080", move |request| {
        // The closure passed to `start_server` will be called once for each client request. It
        // will be called multiple times concurrently when there are multiple clients.

        // Here starts the real handler for the request.
        //
        // The `router!` macro is very similar to a `match` expression in core Rust. The macro
        // takes the request as parameter and will jump to the first block that matches the
        // request.
        //
        // Each of the possible blocks builds a `Response` object. Just like most things in Rust,
        // the `router!` macro is an expression whose value is the `Response` built by the block
        // that was called. Since `router!` is the last piece of code of this closure, the
        // `Response` is then passed back to the `start_server` function and sent to the client.
        router!(request,
            (GET) (/ping) => {
                rouille::Response::text("PONG!")
            },

            // The code block is called if none of the other blocks matches the request.
            // We return an empty response with a 404 status code.
            _ => rouille::Response::empty_404()
        )
    });
}