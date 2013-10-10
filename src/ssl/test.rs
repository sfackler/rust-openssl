extern mod ssl;

use std::rt::io::{Writer, Reader};
use std::rt::io::extensions::{ReaderUtil};
use std::rt::io::net::tcp::TcpStream;
use std::vec;
use std::str;

use ssl::{Sslv23, SslCtx, SslStream};

#[test]
fn test_new_ctx() {
    SslCtx::new(Sslv23);
}

#[test]
fn test_new_sslstream() {
    let stream = TcpStream::connect(FromStr::from_str("127.0.0.1:15418").unwrap()).unwrap();
    SslStream::new(SslCtx::new(Sslv23), stream);
}

#[test]
fn test_write() {
    let stream = TcpStream::connect(FromStr::from_str("127.0.0.1:15418").unwrap()).unwrap();
    let mut stream = SslStream::new(SslCtx::new(Sslv23), stream);
    stream.write("hello".as_bytes());
    stream.flush();
    stream.write(" there".as_bytes());
    stream.flush();
    stream.shutdown();
}

#[test]
fn test_read() {
    let stream = TcpStream::connect(FromStr::from_str("127.0.0.1:15418").unwrap()).unwrap();
    let mut stream = SslStream::new(SslCtx::new(Sslv23), stream);
    stream.write("GET /\r\n\r\n".as_bytes());
    stream.flush();
    let buf = stream.read_to_end();
    print!("{}", str::from_utf8(buf));
}
