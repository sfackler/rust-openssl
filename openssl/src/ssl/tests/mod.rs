#![allow(unused_imports)]

use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io::{self, BufReader};
use std::iter;
use std::mem;
use std::net::{TcpStream, TcpListener, SocketAddr};
use std::path::Path;
use std::process::{Command, Child, Stdio, ChildStdin};
use std::thread;
use std::time::Duration;

use net2::TcpStreamExt;
use tempdir::TempDir;

use crypto::hash::Type::SHA256;
use ssl;
use ssl::SSL_VERIFY_PEER;
use ssl::SslMethod::Tls;
use ssl::{SslMethod, HandshakeError};
use ssl::error::Error;
use ssl::{SslContext, SslStream};
use x509::X509StoreContext;
use x509::X509FileType;
use x509::X509;
use crypto::pkey::PKey;

#[cfg(feature="dtlsv1")]
use std::net::UdpSocket;
#[cfg(feature="dtlsv1")]
use ssl::SslMethod::Dtlsv1;
#[cfg(feature="sslv2")]
use ssl::SslMethod::Sslv2;
#[cfg(feature="dtlsv1")]
use net2::UdpSocketExt;

mod select;

fn next_addr() -> SocketAddr {
    use std::sync::atomic::{AtomicUsize, ATOMIC_USIZE_INIT, Ordering};
    static PORT: AtomicUsize = ATOMIC_USIZE_INIT;
    let port = 15411 + PORT.fetch_add(1, Ordering::SeqCst);

    format!("127.0.0.1:{}", port).parse().unwrap()
}

struct Server {
    p: Child,
    _temp: TempDir,
}

impl Server {
    fn spawn(args: &[&str], input: Option<Box<FnMut(ChildStdin) + Send>>) -> (Server, SocketAddr) {
        static CERT: &'static [u8] = include_bytes!("../../../test/cert.pem");
        static KEY: &'static [u8] = include_bytes!("../../../test/key.pem");


        let td = TempDir::new("openssl").unwrap();
        let cert = td.path().join("cert.pem");
        let key = td.path().join("key.pem");
        File::create(&cert).unwrap().write_all(CERT).unwrap();
        File::create(&key).unwrap().write_all(KEY).unwrap();

        let addr = next_addr();
        let mut child = Command::new("openssl")
                            .arg("s_server")
                            .arg("-accept")
                            .arg(addr.port().to_string())
                            .args(args)
                            .arg("-cert")
                            .arg(&cert)
                            .arg("-key")
                            .arg(&key)
                            .arg("-no_dhe")
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .stdin(Stdio::piped())
                            .spawn()
                            .unwrap();
        let stdin = child.stdin.take().unwrap();
        if let Some(mut input) = input {
            thread::spawn(move || input(stdin));
        }
        (Server { p: child, _temp: td }, addr)
    }

    fn new_tcp(args: &[&str]) -> (Server, TcpStream) {
        let (server, addr) = Server::spawn(args, None);
        for _ in 0..20 {
            match TcpStream::connect(&addr) {
                Ok(s) => return (server, s),
                Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                    thread::sleep(Duration::from_millis(100));
                }
                Err(e) => panic!("wut: {}", e),
            }
        }
        panic!("server never came online");
    }

    fn new() -> (Server, TcpStream) {
        Server::new_tcp(&["-www"])
    }

    #[cfg(all(any(feature = "alpn", feature = "npn"), not(ossl101)))]
    fn new_alpn() -> (Server, TcpStream) {
        Server::new_tcp(&["-www",
                          "-nextprotoneg",
                          "http/1.1,spdy/3.1",
                          "-alpn",
                          "http/1.1,spdy/3.1"])
    }

    #[cfg(feature = "dtlsv1")]
    fn new_dtlsv1<I>(input: I) -> (Server, UdpConnected)
        where I: IntoIterator<Item = &'static str>,
              I::IntoIter: Send + 'static
    {
        let mut input = input.into_iter();
        let (s, addr) = Server::spawn(&["-dtls1"],
                                      Some(Box::new(move |mut io| {
                                          for s in input.by_ref() {
                                              if io.write_all(s.as_bytes()).is_err() {
                                                  break;
                                              }
                                          }
                                      })));
        // Need to wait for the UDP socket to get bound in our child process,
        // but don't currently have a great way to do that so just wait for a
        // bit.
        thread::sleep(Duration::from_millis(100));
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect(&addr).unwrap();
        (s, UdpConnected(socket))
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.p.kill();
        let _ = self.p.wait();
    }
}

#[cfg(feature = "dtlsv1")]
#[derive(Debug)]
struct UdpConnected(UdpSocket);

#[cfg(feature = "dtlsv1")]
impl Read for UdpConnected {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.recv_from(buf).map(|(s, _)| s)
    }
}

#[cfg(feature = "dtlsv1")]
impl Write for UdpConnected {
    #[cfg(unix)]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        use std::os::unix::prelude::*;
        use libc;
        let n = unsafe {
            libc::send(self.0.as_raw_fd(),
                       buf.as_ptr() as *const _,
                       buf.len() as libc::size_t,
                       0)
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    #[cfg(windows)]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        use std::os::windows::prelude::*;
        use libc;
        let n = unsafe {
            libc::send(self.0.as_raw_socket(),
                       buf.as_ptr() as *const _,
                       buf.len() as libc::c_int,
                       0)
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

macro_rules! run_test(
    ($module:ident, $blk:expr) => (
        #[cfg(test)]
        mod $module {
            use std::io;
            use std::io::prelude::*;
            use std::path::Path;
            use std::net::UdpSocket;
            use std::net::TcpStream;
            use ssl;
            use ssl::SslMethod;
            use ssl::{SslContext, Ssl, SslStream};
            use ssl::SSL_VERIFY_PEER;
            use crypto::hash::Type::{SHA1, SHA256};
            use x509::X509StoreContext;
            use serialize::hex::FromHex;
            use super::Server;

            #[test]
            fn sslv23() {
                let (_s, stream) = Server::new();
                $blk(SslMethod::Tls, stream);
            }

            #[test]
            #[cfg(feature="dtlsv1")]
            fn dtlsv1() {
                let (_s, stream) = Server::new_dtlsv1(Some("hello"));
                $blk(SslMethod::Dtlsv1, stream);
            }
        }
    );
);

run_test!(new_ctx, |method, _| {
    SslContext::new(method).unwrap();
});

run_test!(new_sslstream, |method, stream| {
    SslStream::connect(&SslContext::new(method).unwrap(), stream).unwrap();
});

run_test!(verify_untrusted, |method, stream| {
    let mut ctx = SslContext::new(method).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);

    match SslStream::connect(&ctx, stream) {
        Ok(_) => panic!("expected failure"),
        Err(err) => println!("error {:?}", err),
    }
});

run_test!(verify_trusted, |method, stream| {
    let mut ctx = SslContext::new(method).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);

    match ctx.set_CA_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    match SslStream::connect(&ctx, stream) {
        Ok(_) => (),
        Err(err) => panic!("Expected success, got {:?}", err),
    }
});

run_test!(verify_untrusted_callback_override_ok, |method, stream| {
    let mut ctx = SslContext::new(method).unwrap();
    ctx.set_verify_callback(SSL_VERIFY_PEER, |_, _| true);

    match SslStream::connect(&ctx, stream) {
        Ok(_) => (),
        Err(err) => panic!("Expected success, got {:?}", err),
    }
});

run_test!(verify_untrusted_callback_override_bad, |method, stream| {
    let mut ctx = SslContext::new(method).unwrap();
    ctx.set_verify_callback(SSL_VERIFY_PEER, |_, _| false);

    assert!(SslStream::connect(&ctx, stream).is_err());
});

run_test!(verify_trusted_callback_override_ok, |method, stream| {
    let mut ctx = SslContext::new(method).unwrap();
    ctx.set_verify_callback(SSL_VERIFY_PEER, |_, _| true);

    match ctx.set_CA_file(&Path::new("test/cert.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    match SslStream::connect(&ctx, stream) {
        Ok(_) => (),
        Err(err) => panic!("Expected success, got {:?}", err),
    }
});

run_test!(verify_trusted_callback_override_bad, |method, stream| {
    let mut ctx = SslContext::new(method).unwrap();
    ctx.set_verify_callback(SSL_VERIFY_PEER, |_, _| false);

    match ctx.set_CA_file(&Path::new("test/cert.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    assert!(SslStream::connect(&ctx, stream).is_err());
});

run_test!(verify_callback_load_certs, |method, stream| {
    let mut ctx = SslContext::new(method).unwrap();
    ctx.set_verify_callback(SSL_VERIFY_PEER, |_, x509_ctx| {
        assert!(x509_ctx.current_cert().is_some());
        true
    });

    assert!(SslStream::connect(&ctx, stream).is_ok());
});

run_test!(verify_trusted_get_error_ok, |method, stream| {
    let mut ctx = SslContext::new(method).unwrap();
    ctx.set_verify_callback(SSL_VERIFY_PEER, |_, x509_ctx| {
        assert!(x509_ctx.error().is_none());
        true
    });

    match ctx.set_CA_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    assert!(SslStream::connect(&ctx, stream).is_ok());
});

run_test!(verify_trusted_get_error_err, |method, stream| {
    let mut ctx = SslContext::new(method).unwrap();
    ctx.set_verify_callback(SSL_VERIFY_PEER, |_, x509_ctx| {
        assert!(x509_ctx.error().is_some());
        false
    });

    assert!(SslStream::connect(&ctx, stream).is_err());
});

run_test!(verify_callback_data, |method, stream| {
    let mut ctx = SslContext::new(method).unwrap();

    // Node id was generated as SHA256 hash of certificate "test/cert.pem"
    // in DER format.
    // Command: openssl x509 -in test/cert.pem  -outform DER | openssl dgst -sha256
    // Please update if "test/cert.pem" will ever change
    let node_hash_str = "59172d9313e84459bcff27f967e79e6e9217e584";
    let node_id = node_hash_str.from_hex().unwrap();
    ctx.set_verify_callback(SSL_VERIFY_PEER, move |_preverify_ok, x509_ctx| {
        let cert = x509_ctx.current_cert();
        match cert {
            None => false,
            Some(cert) => {
                let fingerprint = cert.fingerprint(SHA1).unwrap();
                fingerprint == node_id
            }
        }
    });
    ctx.set_verify_depth(1);

    match SslStream::connect(&ctx, stream) {
        Ok(_) => (),
        Err(err) => panic!("Expected success, got {:?}", err),
    }
});

run_test!(ssl_verify_callback, |method, stream| {
    use std::sync::atomic::{AtomicUsize, ATOMIC_USIZE_INIT, Ordering};
    use ssl::IntoSsl;

    static CHECKED: AtomicUsize = ATOMIC_USIZE_INIT;

    let ctx = SslContext::new(method).unwrap();
    let mut ssl = ctx.into_ssl().unwrap();

    let node_hash_str = "59172d9313e84459bcff27f967e79e6e9217e584";
    let node_id = node_hash_str.from_hex().unwrap();
    ssl.set_verify_callback(SSL_VERIFY_PEER, move |_, x509| {
        CHECKED.store(1, Ordering::SeqCst);
        match x509.current_cert() {
            None => false,
            Some(cert) => {
                let fingerprint = cert.fingerprint(SHA1).unwrap();
                fingerprint == node_id
            }
        }
    });

    match SslStream::connect(ssl, stream) {
        Ok(_) => (),
        Err(err) => panic!("Expected success, got {:?}", err),
    }

    assert_eq!(CHECKED.load(Ordering::SeqCst), 1);
});

// Make sure every write call translates to a write call to the underlying socket.
#[test]
fn test_write_hits_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let guard = thread::spawn(move || {
        let ctx = SslContext::new(Tls).unwrap();
        let stream = TcpStream::connect(addr).unwrap();
        let mut stream = SslStream::connect(&ctx, stream).unwrap();

        stream.write_all(b"hello").unwrap();
        stream
    });

    let mut ctx = SslContext::new(Tls).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);
    ctx.set_certificate_file(&Path::new("test/cert.pem"), X509FileType::PEM).unwrap();
    ctx.set_private_key_file(&Path::new("test/key.pem"), X509FileType::PEM).unwrap();
    let stream = listener.accept().unwrap().0;
    let mut stream = SslStream::accept(&ctx, stream).unwrap();

    let mut buf = [0; 5];
    assert_eq!(5, stream.read(&mut buf).unwrap());
    assert_eq!(&b"hello"[..], &buf[..]);
    guard.join().unwrap();
}

#[test]
fn test_set_certificate_and_private_key() {
    let key = include_bytes!("../../../test/key.pem");
    let key = PKey::private_key_from_pem(key).unwrap();
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    let mut ctx = SslContext::new(Tls).unwrap();
    ctx.set_private_key(&key).unwrap();
    ctx.set_certificate(&cert).unwrap();

    assert!(ctx.check_private_key().is_ok());
}

run_test!(get_ctx_options, |method, _| {
    let ctx = SslContext::new(method).unwrap();
    ctx.options();
});

run_test!(set_ctx_options, |method, _| {
    let mut ctx = SslContext::new(method).unwrap();
    let opts = ctx.set_options(ssl::SSL_OP_NO_TICKET);
    assert!(opts.contains(ssl::SSL_OP_NO_TICKET));
});

run_test!(clear_ctx_options, |method, _| {
    let mut ctx = SslContext::new(method).unwrap();
    ctx.set_options(ssl::SSL_OP_ALL);
    let opts = ctx.clear_options(ssl::SSL_OP_ALL);
    assert!(!opts.contains(ssl::SSL_OP_ALL));
});

#[test]
fn test_write() {
    let (_s, stream) = Server::new();
    let mut stream = SslStream::connect(&SslContext::new(Tls).unwrap(), stream).unwrap();
    stream.write_all("hello".as_bytes()).unwrap();
    stream.flush().unwrap();
    stream.write_all(" there".as_bytes()).unwrap();
    stream.flush().unwrap();
}

#[test]
fn test_write_direct() {
    let (_s, stream) = Server::new();
    let mut stream = SslStream::connect(&SslContext::new(Tls).unwrap(), stream).unwrap();
    stream.write_all("hello".as_bytes()).unwrap();
    stream.flush().unwrap();
    stream.write_all(" there".as_bytes()).unwrap();
    stream.flush().unwrap();
}

run_test!(get_peer_certificate, |method, stream| {
    let stream = SslStream::connect(&SslContext::new(method).unwrap(), stream).unwrap();
    let cert = stream.ssl().peer_certificate().unwrap();
    let fingerprint = cert.fingerprint(SHA1).unwrap();
    let node_hash_str = "59172d9313e84459bcff27f967e79e6e9217e584";
    let node_id = node_hash_str.from_hex().unwrap();
    assert_eq!(node_id, fingerprint)
});

#[test]
#[cfg(feature = "dtlsv1")]
fn test_write_dtlsv1() {
    let (_s, stream) = Server::new_dtlsv1(iter::repeat("y\n"));

    let mut stream = SslStream::connect(&SslContext::new(Dtlsv1).unwrap(), stream).unwrap();
    stream.write_all(b"hello").unwrap();
    stream.flush().unwrap();
    stream.write_all(b" there").unwrap();
    stream.flush().unwrap();
}

#[test]
fn test_read() {
    let (_s, tcp) = Server::new();
    let mut stream = SslStream::connect(&SslContext::new(Tls).unwrap(), tcp).unwrap();
    stream.write_all("GET /\r\n\r\n".as_bytes()).unwrap();
    stream.flush().unwrap();
    io::copy(&mut stream, &mut io::sink()).ok().expect("read error");
}

#[test]
fn test_read_direct() {
    let (_s, tcp) = Server::new();
    let mut stream = SslStream::connect(&SslContext::new(Tls).unwrap(), tcp).unwrap();
    stream.write_all("GET /\r\n\r\n".as_bytes()).unwrap();
    stream.flush().unwrap();
    io::copy(&mut stream, &mut io::sink()).ok().expect("read error");
}

#[test]
fn test_pending() {
    let (_s, tcp) = Server::new();
    let mut stream = SslStream::connect(&SslContext::new(Tls).unwrap(), tcp).unwrap();
    stream.write_all("GET /\r\n\r\n".as_bytes()).unwrap();
    stream.flush().unwrap();

    // wait for the response and read first byte...
    let mut buf = [0u8; 16 * 1024];
    stream.read(&mut buf[..1]).unwrap();

    let pending = stream.ssl().pending();
    let len = stream.read(&mut buf[1..]).unwrap();

    assert_eq!(pending, len);

    stream.read(&mut buf[..1]).unwrap();

    let pending = stream.ssl().pending();
    let len = stream.read(&mut buf[1..]).unwrap();
    assert_eq!(pending, len);
}

#[test]
fn test_state() {
    let (_s, tcp) = Server::new();
    let stream = SslStream::connect(&SslContext::new(Tls).unwrap(), tcp).unwrap();
    assert_eq!(stream.ssl().state_string(), "SSLOK ");
    assert_eq!(stream.ssl().state_string_long(),
               "SSL negotiation finished successfully");
}

/// Tests that connecting with the client using ALPN, but the server not does not
/// break the existing connection behavior.
#[test]
#[cfg(all(feature = "alpn", not(ossl101)))]
fn test_connect_with_unilateral_alpn() {
    let (_s, stream) = Server::new();
    let mut ctx = SslContext::new(Tls).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);
    ctx.set_alpn_protocols(&[b"http/1.1", b"spdy/3.1"]);
    match ctx.set_CA_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    let stream = match SslStream::connect(&ctx, stream) {
        Ok(stream) => stream,
        Err(err) => panic!("Expected success, got {:?}", err),
    };
    // Since the socket to which we connected is not configured to use ALPN,
    // there should be no selected protocol...
    assert!(stream.ssl().selected_alpn_protocol().is_none());
}

/// Tests that connecting with the client using NPN, but the server not does not
/// break the existing connection behavior.
#[test]
#[cfg(all(feature = "npn", not(ossl101)))]
fn test_connect_with_unilateral_npn() {
    let (_s, stream) = Server::new();
    let mut ctx = SslContext::new(Tls).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);
    ctx.set_npn_protocols(&[b"http/1.1", b"spdy/3.1"]);
    match ctx.set_CA_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    let stream = match SslStream::connect(&ctx, stream) {
        Ok(stream) => stream,
        Err(err) => panic!("Expected success, got {:?}", err),
    };
    // Since the socket to which we connected is not configured to use NPN,
    // there should be no selected protocol...
    assert!(stream.ssl().selected_npn_protocol().is_none());
}

/// Tests that when both the client as well as the server use ALPN and their
/// lists of supported protocols have an overlap, the correct protocol is chosen.
#[test]
#[cfg(all(feature = "alpn", not(ossl101)))]
fn test_connect_with_alpn_successful_multiple_matching() {
    let (_s, stream) = Server::new_alpn();
    let mut ctx = SslContext::new(Tls).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);
    ctx.set_alpn_protocols(&[b"spdy/3.1", b"http/1.1"]);
    match ctx.set_CA_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    let stream = match SslStream::connect(&ctx, stream) {
        Ok(stream) => stream,
        Err(err) => panic!("Expected success, got {:?}", err),
    };
    // The server prefers "http/1.1", so that is chosen, even though the client
    // would prefer "spdy/3.1"
    assert_eq!(b"http/1.1", stream.ssl().selected_alpn_protocol().unwrap());
}

/// Tests that when both the client as well as the server use NPN and their
/// lists of supported protocols have an overlap, the correct protocol is chosen.
#[test]
#[cfg(all(feature = "npn", not(ossl101)))]
fn test_connect_with_npn_successful_multiple_matching() {
    let (_s, stream) = Server::new_alpn();
    let mut ctx = SslContext::new(Tls).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);
    ctx.set_npn_protocols(&[b"spdy/3.1", b"http/1.1"]);
    match ctx.set_CA_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    let stream = match SslStream::connect(&ctx, stream) {
        Ok(stream) => stream,
        Err(err) => panic!("Expected success, got {:?}", err),
    };
    // The server prefers "http/1.1", so that is chosen, even though the client
    // would prefer "spdy/3.1"
    assert_eq!(b"http/1.1", stream.ssl().selected_npn_protocol().unwrap());
}

/// Tests that when both the client as well as the server use ALPN and their
/// lists of supported protocols have an overlap -- with only ONE protocol
/// being valid for both.
#[test]
#[cfg(all(feature = "alpn", not(ossl101)))]
fn test_connect_with_alpn_successful_single_match() {
    let (_s, stream) = Server::new_alpn();
    let mut ctx = SslContext::new(Tls).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);
    ctx.set_alpn_protocols(&[b"spdy/3.1"]);
    match ctx.set_CA_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    let stream = match SslStream::connect(&ctx, stream) {
        Ok(stream) => stream,
        Err(err) => panic!("Expected success, got {:?}", err),
    };
    // The client now only supports one of the server's protocols, so that one
    // is used.
    assert_eq!(b"spdy/3.1", stream.ssl().selected_alpn_protocol().unwrap());
}


/// Tests that when both the client as well as the server use NPN and their
/// lists of supported protocols have an overlap -- with only ONE protocol
/// being valid for both.
#[test]
#[cfg(all(feature = "npn", not(ossl101)))]
fn test_connect_with_npn_successful_single_match() {
    let (_s, stream) = Server::new_alpn();
    let mut ctx = SslContext::new(Tls).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);
    ctx.set_npn_protocols(&[b"spdy/3.1"]);
    match ctx.set_CA_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    let stream = match SslStream::connect(&ctx, stream) {
        Ok(stream) => stream,
        Err(err) => panic!("Expected success, got {:?}", err),
    };
    // The client now only supports one of the server's protocols, so that one
    // is used.
    assert_eq!(b"spdy/3.1", stream.ssl().selected_npn_protocol().unwrap());
}

/// Tests that when the `SslStream` is created as a server stream, the protocols
/// are correctly advertised to the client.
#[test]
#[cfg(all(feature = "npn", not(ossl101)))]
fn test_npn_server_advertise_multiple() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let localhost = listener.local_addr().unwrap();
    // We create a different context instance for the server...
    let listener_ctx = {
        let mut ctx = SslContext::new(Tls).unwrap();
        ctx.set_verify(SSL_VERIFY_PEER);
        ctx.set_npn_protocols(&[b"http/1.1", b"spdy/3.1"]);
        assert!(ctx.set_certificate_file(&Path::new("test/cert.pem"), X509FileType::PEM)
                   .is_ok());
        ctx.set_private_key_file(&Path::new("test/key.pem"), X509FileType::PEM)
           .unwrap();
        ctx
    };
    // Have the listener wait on the connection in a different thread.
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let _ = SslStream::accept(&listener_ctx, stream).unwrap();
    });

    let mut ctx = SslContext::new(Tls).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);
    ctx.set_npn_protocols(&[b"spdy/3.1"]);
    match ctx.set_CA_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    // Now connect to the socket and make sure the protocol negotiation works...
    let stream = TcpStream::connect(localhost).unwrap();
    let stream = match SslStream::connect(&ctx, stream) {
        Ok(stream) => stream,
        Err(err) => panic!("Expected success, got {:?}", err),
    };
    // SPDY is selected since that's the only thing the client supports.
    assert_eq!(b"spdy/3.1", stream.ssl().selected_npn_protocol().unwrap());
}

/// Tests that when the `SslStream` is created as a server stream, the protocols
/// are correctly advertised to the client.
#[test]
#[cfg(all(feature = "alpn", not(ossl101)))]
fn test_alpn_server_advertise_multiple() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let localhost = listener.local_addr().unwrap();
    // We create a different context instance for the server...
    let listener_ctx = {
        let mut ctx = SslContext::new(Tls).unwrap();
        ctx.set_verify(SSL_VERIFY_PEER);
        ctx.set_alpn_protocols(&[b"http/1.1", b"spdy/3.1"]);
        assert!(ctx.set_certificate_file(&Path::new("test/cert.pem"), X509FileType::PEM)
                   .is_ok());
        ctx.set_private_key_file(&Path::new("test/key.pem"), X509FileType::PEM)
           .unwrap();
        ctx
    };
    // Have the listener wait on the connection in a different thread.
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let _ = SslStream::accept(&listener_ctx, stream).unwrap();
    });

    let mut ctx = SslContext::new(Tls).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);
    ctx.set_alpn_protocols(&[b"spdy/3.1"]);
    match ctx.set_CA_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    // Now connect to the socket and make sure the protocol negotiation works...
    let stream = TcpStream::connect(localhost).unwrap();
    let stream = match SslStream::connect(&ctx, stream) {
        Ok(stream) => stream,
        Err(err) => panic!("Expected success, got {:?}", err),
    };
    // SPDY is selected since that's the only thing the client supports.
    assert_eq!(b"spdy/3.1", stream.ssl().selected_alpn_protocol().unwrap());
}

/// Test that Servers supporting ALPN don't report a protocol when none of their protocols match
/// the client's reported protocol.
#[test]
#[cfg(all(feature = "alpn", not(ossl101)))]
fn test_alpn_server_select_none() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let localhost = listener.local_addr().unwrap();
    // We create a different context instance for the server...
    let listener_ctx = {
        let mut ctx = SslContext::new(Tls).unwrap();
        ctx.set_verify(SSL_VERIFY_PEER);
        ctx.set_alpn_protocols(&[b"http/1.1", b"spdy/3.1"]);
        assert!(ctx.set_certificate_file(&Path::new("test/cert.pem"), X509FileType::PEM)
                   .is_ok());
        ctx.set_private_key_file(&Path::new("test/key.pem"), X509FileType::PEM)
           .unwrap();
        ctx
    };
    // Have the listener wait on the connection in a different thread.
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let _ = SslStream::accept(&listener_ctx, stream).unwrap();
    });

    let mut ctx = SslContext::new(Tls).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);
    ctx.set_alpn_protocols(&[b"http/2"]);
    match ctx.set_CA_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    // Now connect to the socket and make sure the protocol negotiation works...
    let stream = TcpStream::connect(localhost).unwrap();
    let stream = match SslStream::connect(&ctx, stream) {
        Ok(stream) => stream,
        Err(err) => panic!("Expected success, got {:?}", err),
    };

    // Since the protocols from the server and client don't overlap at all, no protocol is selected
    assert_eq!(None, stream.ssl().selected_alpn_protocol());
}


#[cfg(feature="dtlsv1")]
#[cfg(test)]
mod dtlsv1 {
    use serialize::hex::FromHex;
    use std::net::TcpStream;
    use std::thread;

    use crypto::hash::Type::SHA256;
    use ssl::SslMethod;
    use ssl::SslMethod::Dtlsv1;
    use ssl::{SslContext, SslStream};
    use ssl::SSL_VERIFY_PEER;
    use x509::X509StoreContext;

    const PROTOCOL: SslMethod = Dtlsv1;

    #[test]
    fn test_new_ctx() {
        SslContext::new(PROTOCOL).unwrap();
    }
}

#[test]
#[cfg(feature = "dtlsv1")]
fn test_read_dtlsv1() {
    let (_s, stream) = Server::new_dtlsv1(Some("hello"));

    let mut stream = SslStream::connect(&SslContext::new(Dtlsv1).unwrap(), stream).unwrap();
    let mut buf = [0u8; 100];
    assert!(stream.read(&mut buf).is_ok());
}

#[test]
#[cfg(feature = "sslv2")]
fn test_sslv2_connect_failure() {
    let (_s, tcp) = Server::new_tcp(&["-no_ssl2", "-www"]);
    SslStream::connect(&SslContext::new(Sslv2).unwrap(), tcp)
        .err()
        .unwrap();
}

fn wait_io(stream: &TcpStream, read: bool, timeout_ms: u32) -> bool {
    unsafe {
        let mut set: select::fd_set = mem::zeroed();
        select::fd_set(&mut set, stream);

        let write = if read {
            0 as *mut _
        } else {
            &mut set as *mut _
        };
        let read = if !read {
            0 as *mut _
        } else {
            &mut set as *mut _
        };
        select::select(stream, read, write, 0 as *mut _, timeout_ms).unwrap()
    }
}

fn handshake(res: Result<SslStream<TcpStream>, HandshakeError<TcpStream>>)
             -> SslStream<TcpStream> {
    match res {
        Ok(s) => s,
        Err(HandshakeError::Interrupted(s)) => {
            wait_io(s.get_ref(), true, 1_000);
            handshake(s.handshake())
        }
        Err(err) => panic!("error on handshake {:?}", err),
    }
}

#[test]
fn test_write_nonblocking() {
    let (_s, stream) = Server::new();
    stream.set_nonblocking(true).unwrap();
    let cx = SslContext::new(Tls).unwrap();
    let mut stream = handshake(SslStream::connect(&cx, stream));

    let mut iterations = 0;
    loop {
        iterations += 1;
        if iterations > 7 {
            // Probably a safe assumption for the foreseeable future of
            // openssl.
            panic!("Too many read/write round trips in handshake!!");
        }
        let result = stream.ssl_write(b"hello");
        match result {
            Ok(_) => {
                break;
            }
            Err(Error::WantRead(_)) => {
                assert!(wait_io(stream.get_ref(), true, 1000));
            }
            Err(Error::WantWrite(_)) => {
                assert!(wait_io(stream.get_ref(), false, 1000));
            }
            Err(other) => {
                panic!("Unexpected SSL Error: {:?}", other);
            }
        }
    }

    // Second write should succeed immediately--plenty of space in kernel
    // buffer, and handshake just completed.
    stream.write(" there".as_bytes()).unwrap();
}

#[test]
#[cfg_attr(windows, ignore)] // FIXME flickers on appveyor
fn test_read_nonblocking() {
    let (_s, stream) = Server::new();
    stream.set_nonblocking(true).unwrap();
    let cx = SslContext::new(Tls).unwrap();
    let mut stream = handshake(SslStream::connect(&cx, stream));

    let mut iterations = 0;
    loop {
        iterations += 1;
        if iterations > 7 {
            // Probably a safe assumption for the foreseeable future of
            // openssl.
            panic!("Too many read/write round trips in handshake!!");
        }
        let result = stream.ssl_write(b"GET /\r\n\r\n");
        match result {
            Ok(n) => {
                assert_eq!(n, 9);
                break;
            }
            Err(Error::WantRead(..)) => {
                assert!(wait_io(stream.get_ref(), true, 1000));
            }
            Err(Error::WantWrite(..)) => {
                assert!(wait_io(stream.get_ref(), false, 1000));
            }
            Err(other) => {
                panic!("Unexpected SSL Error: {:?}", other);
            }
        }
    }
    let mut input_buffer = [0u8; 1500];
    let result = stream.ssl_read(&mut input_buffer);
    let bytes_read = match result {
        Ok(n) => {
            // This branch is unlikely, but on an overloaded VM with
            // unlucky context switching, the response could actually
            // be in the receive buffer before we issue the read() syscall...
            n
        }
        Err(Error::WantRead(..)) => {
            assert!(wait_io(stream.get_ref(), true, 3000));
            // Second read should return application data.
            stream.read(&mut input_buffer).unwrap()
        }
        Err(other) => {
            panic!("Unexpected SSL Error: {:?}", other);
        }
    };
    assert!(bytes_read >= 5);
    assert_eq!(&input_buffer[..5], b"HTTP/");
}

#[test]
#[should_panic(expected = "blammo")]
fn write_panic() {
    struct ExplodingStream(TcpStream);

    impl Read for ExplodingStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for ExplodingStream {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            panic!("blammo");
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    let (_s, stream) = Server::new();
    let stream = ExplodingStream(stream);

    let ctx = SslContext::new(SslMethod::Tls).unwrap();
    let _ = SslStream::connect(&ctx, stream);
}

#[test]
#[should_panic(expected = "blammo")]
fn read_panic() {
    struct ExplodingStream(TcpStream);

    impl Read for ExplodingStream {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("blammo");
        }
    }

    impl Write for ExplodingStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    let (_s, stream) = Server::new();
    let stream = ExplodingStream(stream);

    let ctx = SslContext::new(SslMethod::Tls).unwrap();
    let _ = SslStream::connect(&ctx, stream);
}

#[test]
#[should_panic(expected = "blammo")]
fn flush_panic() {
    struct ExplodingStream(TcpStream);

    impl Read for ExplodingStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for ExplodingStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            panic!("blammo");
        }
    }

    let (_s, stream) = Server::new();
    let stream = ExplodingStream(stream);

    let ctx = SslContext::new(SslMethod::Tls).unwrap();
    let mut stream = SslStream::connect(&ctx, stream).ok().unwrap();
    let _ = stream.flush();
}

#[test]
fn refcount_ssl_context() {
    let mut ssl = {
        let ctx = SslContext::new(SslMethod::Tls).unwrap();
        ssl::Ssl::new(&ctx).unwrap()
    };

    {
        let new_ctx_a = SslContext::new(SslMethod::Tls).unwrap();
        let _new_ctx_b = ssl.set_ssl_context(&new_ctx_a);
    }
}

#[test]
#[cfg_attr(windows, ignore)] // don't have a trusted CA list easily available :(
fn default_verify_paths() {
    let mut ctx = SslContext::new(SslMethod::Tls).unwrap();
    ctx.set_default_verify_paths().unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);
    let s = TcpStream::connect("google.com:443").unwrap();
    let mut socket = SslStream::connect(&ctx, s).unwrap();

    socket.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut result = vec![];
    socket.read_to_end(&mut result).unwrap();

    println!("{}", String::from_utf8_lossy(&result));
    assert!(result.starts_with(b"HTTP/1.0"));
    assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
}

#[test]
fn add_extra_chain_cert() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let mut ctx = SslContext::new(SslMethod::Tls).unwrap();
    ctx.add_extra_chain_cert(&cert).unwrap();
}
