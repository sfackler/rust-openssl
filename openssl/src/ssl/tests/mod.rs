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
use tempdir::TempDir;

use hash::MessageDigest;
use ssl;
use ssl::SSL_VERIFY_PEER;
use ssl::{SslMethod, HandshakeError};
use ssl::{SslContext, SslStream, Ssl, ShutdownResult, SslConnectorBuilder, SslAcceptorBuilder,
          Error};
use x509::{X509StoreContext, X509, X509Name, X509_FILETYPE_PEM};
#[cfg(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))]
use x509::verify::X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS;
use pkey::PKey;

use std::net::UdpSocket;

mod select;

static CERT: &'static [u8] = include_bytes!("../../../test/cert.pem");
static KEY: &'static [u8] = include_bytes!("../../../test/key.pem");

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
        (Server {
            p: child,
            _temp: td,
        },
         addr)
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

    fn new_alpn() -> (Server, TcpStream) {
        Server::new_tcp(&["-www",
                          "-nextprotoneg",
                          "http/1.1,spdy/3.1",
                          "-alpn",
                          "http/1.1,spdy/3.1"])
    }

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

#[derive(Debug)]
struct UdpConnected(UdpSocket);

impl Read for UdpConnected {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.recv(buf)
    }
}

impl Write for UdpConnected {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.send(buf)
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
            use hash::MessageDigest;
            use x509::X509StoreContext;
            use hex::FromHex;
            use types::OpenSslTypeRef;
            use super::Server;

            #[test]
            fn sslv23() {
                let (_s, stream) = Server::new();
                $blk(SslMethod::tls(), stream);
            }

            #[test]
            #[cfg_attr(any(windows, target_arch = "arm"), ignore)] // FIXME(#467)
            fn dtlsv1() {
                let (_s, stream) = Server::new_dtlsv1(Some("hello"));
                $blk(SslMethod::dtls(), stream);
            }
        }
    );
);

run_test!(new_ctx, |method, _| {
    SslContext::builder(method).unwrap();
});

run_test!(verify_untrusted, |method, stream| {
    let mut ctx = SslContext::builder(method).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);

    match Ssl::new(&ctx.build()).unwrap().connect(stream) {
        Ok(_) => panic!("expected failure"),
        Err(err) => println!("error {:?}", err),
    }
});

run_test!(verify_trusted, |method, stream| {
    let mut ctx = SslContext::builder(method).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);

    match ctx.set_ca_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    match Ssl::new(&ctx.build()).unwrap().connect(stream) {
        Ok(_) => (),
        Err(err) => panic!("Expected success, got {:?}", err),
    }
});

run_test!(verify_untrusted_callback_override_ok, |method, stream| {
    let mut ctx = SslContext::builder(method).unwrap();
    ctx.set_verify_callback(SSL_VERIFY_PEER, |_, _| true);

    match Ssl::new(&ctx.build()).unwrap().connect(stream) {
        Ok(_) => (),
        Err(err) => panic!("Expected success, got {:?}", err),
    }
});

run_test!(verify_untrusted_callback_override_bad, |method, stream| {
    let mut ctx = SslContext::builder(method).unwrap();
    ctx.set_verify_callback(SSL_VERIFY_PEER, |_, _| false);

    assert!(Ssl::new(&ctx.build()).unwrap().connect(stream).is_err());
});

run_test!(verify_trusted_callback_override_ok, |method, stream| {
    let mut ctx = SslContext::builder(method).unwrap();
    ctx.set_verify_callback(SSL_VERIFY_PEER, |_, _| true);

    match ctx.set_ca_file(&Path::new("test/cert.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    match Ssl::new(&ctx.build()).unwrap().connect(stream) {
        Ok(_) => (),
        Err(err) => panic!("Expected success, got {:?}", err),
    }
});

run_test!(verify_trusted_callback_override_bad, |method, stream| {
    let mut ctx = SslContext::builder(method).unwrap();
    ctx.set_verify_callback(SSL_VERIFY_PEER, |_, _| false);

    match ctx.set_ca_file(&Path::new("test/cert.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    assert!(Ssl::new(&ctx.build()).unwrap().connect(stream).is_err());
});

run_test!(verify_callback_load_certs, |method, stream| {
    let mut ctx = SslContext::builder(method).unwrap();
    ctx.set_verify_callback(SSL_VERIFY_PEER, |_, x509_ctx| {
        assert!(x509_ctx.current_cert().is_some());
        true
    });

    assert!(Ssl::new(&ctx.build()).unwrap().connect(stream).is_ok());
});

run_test!(verify_trusted_get_error_ok, |method, stream| {
    let mut ctx = SslContext::builder(method).unwrap();
    ctx.set_verify_callback(SSL_VERIFY_PEER, |_, x509_ctx| {
        assert!(x509_ctx.error().is_none());
        true
    });

    match ctx.set_ca_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    assert!(Ssl::new(&ctx.build()).unwrap().connect(stream).is_ok());
});

run_test!(verify_trusted_get_error_err, |method, stream| {
    let mut ctx = SslContext::builder(method).unwrap();
    ctx.set_verify_callback(SSL_VERIFY_PEER, |_, x509_ctx| {
        assert!(x509_ctx.error().is_some());
        false
    });

    assert!(Ssl::new(&ctx.build()).unwrap().connect(stream).is_err());
});

run_test!(verify_callback_data, |method, stream| {
    let mut ctx = SslContext::builder(method).unwrap();

// Node id was generated as SHA256 hash of certificate "test/cert.pem"
// in DER format.
// Command: openssl x509 -in test/cert.pem  -outform DER | openssl dgst -sha256
// Please update if "test/cert.pem" will ever change
    let node_hash_str = "59172d9313e84459bcff27f967e79e6e9217e584";
    let node_id = Vec::from_hex(node_hash_str).unwrap();
    ctx.set_verify_callback(SSL_VERIFY_PEER, move |_preverify_ok, x509_ctx| {
        let cert = x509_ctx.current_cert();
        match cert {
            None => false,
            Some(cert) => {
                let fingerprint = cert.fingerprint(MessageDigest::sha1()).unwrap();
                fingerprint == node_id
            }
        }
    });
    ctx.set_verify_depth(1);

    match Ssl::new(&ctx.build()).unwrap().connect(stream) {
        Ok(_) => (),
        Err(err) => panic!("Expected success, got {:?}", err),
    }
});

run_test!(ssl_verify_callback, |method, stream| {
    use std::sync::atomic::{AtomicUsize, ATOMIC_USIZE_INIT, Ordering};

    static CHECKED: AtomicUsize = ATOMIC_USIZE_INIT;

    let ctx = SslContext::builder(method).unwrap();
    let mut ssl = Ssl::new(&ctx.build()).unwrap();

    let node_hash_str = "59172d9313e84459bcff27f967e79e6e9217e584";
    let node_id = Vec::from_hex(node_hash_str).unwrap();
    ssl.set_verify_callback(SSL_VERIFY_PEER, move |_, x509| {
        CHECKED.store(1, Ordering::SeqCst);
        match x509.current_cert() {
            None => false,
            Some(cert) => {
                let fingerprint = cert.fingerprint(MessageDigest::sha1()).unwrap();
                fingerprint == node_id
            }
        }
    });

    match ssl.connect(stream) {
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
        let ctx = SslContext::builder(SslMethod::tls()).unwrap();
        let stream = TcpStream::connect(addr).unwrap();
        let mut stream = Ssl::new(&ctx.build()).unwrap().connect(stream).unwrap();

        stream.write_all(b"hello").unwrap();
        stream
    });

    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);
    ctx.set_certificate_file(&Path::new("test/cert.pem"), X509_FILETYPE_PEM).unwrap();
    ctx.set_private_key_file(&Path::new("test/key.pem"), X509_FILETYPE_PEM).unwrap();
    let stream = listener.accept().unwrap().0;
    let mut stream = Ssl::new(&ctx.build()).unwrap().accept(stream).unwrap();

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

    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_private_key(&key).unwrap();
    ctx.set_certificate(&cert).unwrap();

    assert!(ctx.check_private_key().is_ok());
}

run_test!(get_ctx_options, |method, _| {
    let ctx = SslContext::builder(method).unwrap();
    ctx.options();
});

run_test!(set_ctx_options, |method, _| {
    let mut ctx = SslContext::builder(method).unwrap();
    let opts = ctx.set_options(ssl::SSL_OP_NO_TICKET);
    assert!(opts.contains(ssl::SSL_OP_NO_TICKET));
});

run_test!(clear_ctx_options, |method, _| {
    let mut ctx = SslContext::builder(method).unwrap();
    ctx.set_options(ssl::SSL_OP_ALL);
    let opts = ctx.clear_options(ssl::SSL_OP_ALL);
    assert!(!opts.contains(ssl::SSL_OP_ALL));
});

#[test]
fn test_write() {
    let (_s, stream) = Server::new();
    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let mut stream = Ssl::new(&ctx.build()).unwrap().connect(stream).unwrap();
    stream.write_all("hello".as_bytes()).unwrap();
    stream.flush().unwrap();
    stream.write_all(" there".as_bytes()).unwrap();
    stream.flush().unwrap();
}

run_test!(get_peer_certificate, |method, stream| {
    let ctx = SslContext::builder(method).unwrap();
    let stream = Ssl::new(&ctx.build()).unwrap().connect(stream).unwrap();
    let cert = stream.ssl().peer_certificate().unwrap();
    let fingerprint = cert.fingerprint(MessageDigest::sha1()).unwrap();
    let node_hash_str = "59172d9313e84459bcff27f967e79e6e9217e584";
    let node_id = Vec::from_hex(node_hash_str).unwrap();
    assert_eq!(node_id, fingerprint)
});

#[test]
#[cfg_attr(any(windows, target_arch = "arm"), ignore)] // FIXME(#467)
fn test_write_dtlsv1() {
    let (_s, stream) = Server::new_dtlsv1(iter::repeat("y\n"));
    let ctx = SslContext::builder(SslMethod::dtls()).unwrap();
    let mut stream = Ssl::new(&ctx.build()).unwrap().connect(stream).unwrap();
    stream.write_all(b"hello").unwrap();
    stream.flush().unwrap();
    stream.write_all(b" there").unwrap();
    stream.flush().unwrap();
}

#[test]
fn test_read() {
    let (_s, tcp) = Server::new();
    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let mut stream = Ssl::new(&ctx.build()).unwrap().connect(tcp).unwrap();
    stream.write_all("GET /\r\n\r\n".as_bytes()).unwrap();
    stream.flush().unwrap();
    io::copy(&mut stream, &mut io::sink()).ok().expect("read error");
}

#[test]
fn test_pending() {
    let (_s, tcp) = Server::new();
    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let mut stream = Ssl::new(&ctx.build()).unwrap().connect(tcp).unwrap();
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
    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let stream = Ssl::new(&ctx.build()).unwrap().connect(tcp).unwrap();
    assert_eq!(stream.ssl().state_string(), "SSLOK ");
    assert_eq!(stream.ssl().state_string_long(),
               "SSL negotiation finished successfully");
}

/// Tests that connecting with the client using ALPN, but the server not does not
/// break the existing connection behavior.
#[test]
#[cfg(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))]
fn test_connect_with_unilateral_alpn() {
    let (_s, stream) = Server::new();
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);
    ctx.set_alpn_protocols(&[b"http/1.1", b"spdy/3.1"]).unwrap();
    match ctx.set_ca_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    let stream = match Ssl::new(&ctx.build()).unwrap().connect(stream) {
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
fn test_connect_with_unilateral_npn() {
    let (_s, stream) = Server::new();
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);
    ctx.set_npn_protocols(&[b"http/1.1", b"spdy/3.1"]).unwrap();
    match ctx.set_ca_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    let stream = match Ssl::new(&ctx.build()).unwrap().connect(stream) {
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
#[cfg(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))]
fn test_connect_with_alpn_successful_multiple_matching() {
    let (_s, stream) = Server::new_alpn();
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);
    ctx.set_alpn_protocols(&[b"spdy/3.1", b"http/1.1"]).unwrap();
    match ctx.set_ca_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    let stream = match Ssl::new(&ctx.build()).unwrap().connect(stream) {
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
#[cfg(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))]
fn test_connect_with_npn_successful_multiple_matching() {
    let (_s, stream) = Server::new_alpn();
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);
    ctx.set_npn_protocols(&[b"spdy/3.1", b"http/1.1"]).unwrap();
    match ctx.set_ca_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    let stream = match Ssl::new(&ctx.build()).unwrap().connect(stream) {
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
#[cfg(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))]
fn test_connect_with_alpn_successful_single_match() {
    let (_s, stream) = Server::new_alpn();
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);
    ctx.set_alpn_protocols(&[b"spdy/3.1"]).unwrap();
    match ctx.set_ca_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    let stream = match Ssl::new(&ctx.build()).unwrap().connect(stream) {
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
#[cfg(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))]
fn test_connect_with_npn_successful_single_match() {
    let (_s, stream) = Server::new_alpn();
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);
    ctx.set_npn_protocols(&[b"spdy/3.1"]).unwrap();
    match ctx.set_ca_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    let stream = match Ssl::new(&ctx.build()).unwrap().connect(stream) {
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
fn test_npn_server_advertise_multiple() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let localhost = listener.local_addr().unwrap();
    // We create a different context instance for the server...
    let listener_ctx = {
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_verify(SSL_VERIFY_PEER);
        ctx.set_npn_protocols(&[b"http/1.1", b"spdy/3.1"]).unwrap();
        assert!(ctx.set_certificate_file(&Path::new("test/cert.pem"), X509_FILETYPE_PEM)
                   .is_ok());
        ctx.set_private_key_file(&Path::new("test/key.pem"), X509_FILETYPE_PEM)
            .unwrap();
        ctx.build()
    };
    // Have the listener wait on the connection in a different thread.
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        Ssl::new(&listener_ctx).unwrap().accept(stream).unwrap();
    });

    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);
    ctx.set_npn_protocols(&[b"spdy/3.1"]).unwrap();
    match ctx.set_ca_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    // Now connect to the socket and make sure the protocol negotiation works...
    let stream = TcpStream::connect(localhost).unwrap();
    let stream = match Ssl::new(&ctx.build()).unwrap().connect(stream) {
        Ok(stream) => stream,
        Err(err) => panic!("Expected success, got {:?}", err),
    };
    // SPDY is selected since that's the only thing the client supports.
    assert_eq!(b"spdy/3.1", stream.ssl().selected_npn_protocol().unwrap());
}

/// Tests that when the `SslStream` is created as a server stream, the protocols
/// are correctly advertised to the client.
#[test]
#[cfg(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))]
fn test_alpn_server_advertise_multiple() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let localhost = listener.local_addr().unwrap();
    // We create a different context instance for the server...
    let listener_ctx = {
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_verify(SSL_VERIFY_PEER);
        ctx.set_alpn_protocols(&[b"http/1.1", b"spdy/3.1"]).unwrap();
        assert!(ctx.set_certificate_file(&Path::new("test/cert.pem"), X509_FILETYPE_PEM)
                   .is_ok());
        ctx.set_private_key_file(&Path::new("test/key.pem"), X509_FILETYPE_PEM)
            .unwrap();
        ctx.build()
    };
    // Have the listener wait on the connection in a different thread.
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        Ssl::new(&listener_ctx).unwrap().accept(stream).unwrap();
    });

    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);
    ctx.set_alpn_protocols(&[b"spdy/3.1"]).unwrap();
    match ctx.set_ca_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    // Now connect to the socket and make sure the protocol negotiation works...
    let stream = TcpStream::connect(localhost).unwrap();
    let stream = match Ssl::new(&ctx.build()).unwrap().connect(stream) {
        Ok(stream) => stream,
        Err(err) => panic!("Expected success, got {:?}", err),
    };
    // SPDY is selected since that's the only thing the client supports.
    assert_eq!(b"spdy/3.1", stream.ssl().selected_alpn_protocol().unwrap());
}

/// Test that Servers supporting ALPN don't report a protocol when none of their protocols match
/// the client's reported protocol.
#[test]
#[cfg(all(feature = "v102", ossl102))]
fn test_alpn_server_select_none() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let localhost = listener.local_addr().unwrap();
    // We create a different context instance for the server...
    let listener_ctx = {
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_verify(SSL_VERIFY_PEER);
        ctx.set_alpn_protocols(&[b"http/1.1", b"spdy/3.1"]).unwrap();
        assert!(ctx.set_certificate_file(&Path::new("test/cert.pem"), X509_FILETYPE_PEM)
                   .is_ok());
        ctx.set_private_key_file(&Path::new("test/key.pem"), X509_FILETYPE_PEM)
            .unwrap();
        ctx.build()
    };
    // Have the listener wait on the connection in a different thread.
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        Ssl::new(&listener_ctx).unwrap().accept(stream).unwrap();
    });

    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);
    ctx.set_alpn_protocols(&[b"http/2"]).unwrap();
    ctx.set_ca_file(&Path::new("test/root-ca.pem")).unwrap();
    // Now connect to the socket and make sure the protocol negotiation works...
    let stream = TcpStream::connect(localhost).unwrap();
    let stream = Ssl::new(&ctx.build()).unwrap().connect(stream).unwrap();

    // Since the protocols from the server and client don't overlap at all, no protocol is selected
    assert_eq!(None, stream.ssl().selected_alpn_protocol());
}

// In 1.1.0, ALPN negotiation failure is a fatal error
#[test]
#[cfg(all(feature = "v110", ossl110))]
fn test_alpn_server_select_none() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let localhost = listener.local_addr().unwrap();
    // We create a different context instance for the server...
    let listener_ctx = {
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_verify(SSL_VERIFY_PEER);
        ctx.set_alpn_protocols(&[b"http/1.1", b"spdy/3.1"]).unwrap();
        assert!(ctx.set_certificate_file(&Path::new("test/cert.pem"), X509_FILETYPE_PEM)
                   .is_ok());
        ctx.set_private_key_file(&Path::new("test/key.pem"), X509_FILETYPE_PEM)
            .unwrap();
        ctx.build()
    };
    // Have the listener wait on the connection in a different thread.
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        assert!(Ssl::new(&listener_ctx).unwrap().accept(stream).is_err());
    });

    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);
    ctx.set_alpn_protocols(&[b"http/2"]).unwrap();
    ctx.set_ca_file(&Path::new("test/root-ca.pem")).unwrap();
    // Now connect to the socket and make sure the protocol negotiation works...
    let stream = TcpStream::connect(localhost).unwrap();
    assert!(Ssl::new(&ctx.build()).unwrap().connect(stream).is_err());
}

#[test]
#[cfg_attr(any(windows, target_arch = "arm"), ignore)] // FIXME(#467)
fn test_read_dtlsv1() {
    let (_s, stream) = Server::new_dtlsv1(Some("hello"));

    let ctx = SslContext::builder(SslMethod::dtls()).unwrap();
    let mut stream = Ssl::new(&ctx.build()).unwrap().connect(stream).unwrap();
    let mut buf = [0u8; 100];
    assert!(stream.read(&mut buf).is_ok());
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

fn handshake(res: Result<SslStream<TcpStream>, HandshakeError<TcpStream>>) -> SslStream<TcpStream> {
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
    let cx = SslContext::builder(SslMethod::tls()).unwrap().build();
    let mut stream = handshake(Ssl::new(&cx).unwrap().connect(stream));

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
#[cfg_attr(any(windows, target_arch = "arm"), ignore)] // FIXME(#467)
fn test_read_nonblocking() {
    let (_s, stream) = Server::new();
    stream.set_nonblocking(true).unwrap();
    let cx = SslContext::builder(SslMethod::tls()).unwrap().build();
    let mut stream = handshake(Ssl::new(&cx).unwrap().connect(stream));

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

    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let _ = Ssl::new(&ctx.build()).unwrap().connect(stream);
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

    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let _ = Ssl::new(&ctx.build()).unwrap().connect(stream);
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

    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let mut stream = Ssl::new(&ctx.build()).unwrap().connect(stream).ok().unwrap();
    let _ = stream.flush();
}

#[test]
fn refcount_ssl_context() {
    let mut ssl = {
        let ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ssl::Ssl::new(&ctx.build()).unwrap()
    };

    {
        let new_ctx_a = SslContext::builder(SslMethod::tls()).unwrap().build();
        let _new_ctx_b = ssl.set_ssl_context(&new_ctx_a);
    }
}

#[test]
fn default_verify_paths() {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_default_verify_paths().unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);
    let s = TcpStream::connect("google.com:443").unwrap();
    let mut socket = Ssl::new(&ctx.build()).unwrap().connect(s).unwrap();

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
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.add_extra_chain_cert(cert).unwrap();
}

#[test]
#[cfg(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))]
fn verify_valid_hostname() {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_default_verify_paths().unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);

    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    ssl.param_mut().set_hostflags(X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    ssl.param_mut().set_host("google.com").unwrap();

    let s = TcpStream::connect("google.com:443").unwrap();
    let mut socket = ssl.connect(s).unwrap();

    socket.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut result = vec![];
    socket.read_to_end(&mut result).unwrap();

    println!("{}", String::from_utf8_lossy(&result));
    assert!(result.starts_with(b"HTTP/1.0"));
    assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
}

#[test]
#[cfg(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))]
fn verify_invalid_hostname() {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_default_verify_paths().unwrap();
    ctx.set_verify(SSL_VERIFY_PEER);

    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    ssl.param_mut().set_hostflags(X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    ssl.param_mut().set_host("foobar.com").unwrap();

    let s = TcpStream::connect("google.com:443").unwrap();
    assert!(ssl.connect(s).is_err());
}

#[test]
fn connector_valid_hostname() {
    let connector = SslConnectorBuilder::new(SslMethod::tls()).unwrap().build();

    let s = TcpStream::connect("google.com:443").unwrap();
    let mut socket = connector.connect("google.com", s).unwrap();

    socket.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut result = vec![];
    socket.read_to_end(&mut result).unwrap();

    println!("{}", String::from_utf8_lossy(&result));
    assert!(result.starts_with(b"HTTP/1.0"));
    assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
}

#[test]
fn connector_invalid_hostname() {
    let connector = SslConnectorBuilder::new(SslMethod::tls()).unwrap().build();

    let s = TcpStream::connect("google.com:443").unwrap();
    assert!(connector.connect("foobar.com", s).is_err());
}

#[test]
fn connector_client_server_mozilla_intermediate() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let t = thread::spawn(move || {
        let key = PKey::private_key_from_pem(KEY).unwrap();
        let cert = X509::from_pem(CERT).unwrap();
        let connector =
            SslAcceptorBuilder::mozilla_intermediate(SslMethod::tls(), &key, &cert, None::<X509>)
                .unwrap()
                .build();
        let stream = listener.accept().unwrap().0;
        let mut stream = connector.accept(stream).unwrap();

        stream.write_all(b"hello").unwrap();
    });

    let mut connector = SslConnectorBuilder::new(SslMethod::tls()).unwrap();
    connector.builder_mut().set_ca_file("test/root-ca.pem").unwrap();
    let connector = connector.build();

    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut stream = connector.connect("foobar.com", stream).unwrap();

    let mut buf = [0; 5];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(b"hello", &buf);

    t.join().unwrap();
}

#[test]
fn connector_client_server_mozilla_modern() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let t = thread::spawn(move || {
        let key = PKey::private_key_from_pem(KEY).unwrap();
        let cert = X509::from_pem(CERT).unwrap();
        let connector =
            SslAcceptorBuilder::mozilla_modern(SslMethod::tls(), &key, &cert, None::<X509>)
                .unwrap()
                .build();
        let stream = listener.accept().unwrap().0;
        let mut stream = connector.accept(stream).unwrap();

        stream.write_all(b"hello").unwrap();
    });

    let mut connector = SslConnectorBuilder::new(SslMethod::tls()).unwrap();
    connector.builder_mut().set_ca_file("test/root-ca.pem").unwrap();
    let connector = connector.build();

    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut stream = connector.connect("foobar.com", stream).unwrap();

    let mut buf = [0; 5];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(b"hello", &buf);

    t.join().unwrap();
}

#[test]
fn shutdown() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    thread::spawn(move || {
        let stream = listener.accept().unwrap().0;
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_certificate_file(&Path::new("test/cert.pem"), X509_FILETYPE_PEM).unwrap();
        ctx.set_private_key_file(&Path::new("test/key.pem"), X509_FILETYPE_PEM).unwrap();
        let ssl = Ssl::new(&ctx.build()).unwrap();
        let mut stream = ssl.accept(stream).unwrap();

        stream.write_all(b"hello").unwrap();
        let mut buf = [0; 1];
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
        assert_eq!(stream.shutdown().unwrap(), ShutdownResult::Received);
    });

    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let ssl = Ssl::new(&ctx.build()).unwrap();
    let mut stream = ssl.connect(stream).unwrap();

    let mut buf = [0; 5];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(b"hello", &buf);

    assert_eq!(stream.shutdown().unwrap(), ShutdownResult::Sent);
    assert_eq!(stream.shutdown().unwrap(), ShutdownResult::Received);
}

#[test]
fn client_ca_list() {
    let names = X509Name::load_client_ca_file("test/root-ca.pem").unwrap();
    assert_eq!(names.len(), 1);

    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_client_ca_list(names);
}

fn _check_kinds() {
    fn is_send<T: Send>() {}
    fn is_sync<T: Sync>() {}

    is_send::<SslStream<TcpStream>>();
    is_sync::<SslStream<TcpStream>>();
}
