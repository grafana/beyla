use std::io::{BufRead, BufReader, Error, Write};
use std::net::{TcpListener, TcpStream};

// Dummy single-file, zero-dependency web server that just replies OK to anything

fn handle_client(mut stream: TcpStream) -> Result<(), Error> {
    let mut input = BufReader::new(&mut stream);

    // log first line of request
    let mut req_content = String::new();
    let _ = input.read_line(&mut req_content);
    println!("{}", req_content);

    // send a hello world! response
    let msg = "Hello world!\n";
    write!(stream, "HTTP/1.1 200 OK\r\n\
                    Content-Type: text/plain\r\n\
                    Content-Length: {}\r\n\
                    Connection: close\r\n\
                    \r\n\
                    {}", msg.len(), msg)?;
    Ok(())
}

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8080")?;
    println!("Listening on http://localhost:8080");
    // accept connections and process them serially
    for stream in listener.incoming() {
        if let Err(e) = handle_client(stream?) {
            println!("unexpected error {e}")
        }
    }
    Ok(())
}