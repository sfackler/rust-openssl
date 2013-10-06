extern mod ssl;

use std::rt::io::{Writer, Reader};
use std::rt::io::net::tcp::TcpStream;
use std::vec;

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
