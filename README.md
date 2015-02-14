# rust-openssl

[![Build Status](https://travis-ci.org/sfackler/rust-openssl.svg?branch=master)](https://travis-ci.org/sfackler/rust-openssl)

See the [rustdoc output](https://sfackler.github.io/rust-openssl/doc/openssl).

## Building

rust-openssl depends on both the OpenSSL runtime libraries and headers.

### Linux

On Linux, you can install OpenSSL via your package manager. The headers are
sometimes provided in a separate package than the runtime libraries - look for
something like `openssl-devel` or `libssl-dev`.

```bash
# On Ubuntu
sudo apt-get install libssl-dev
# On Arch Linux
sudo pacman -S openssl
```

### OSX

OpenSSL 0.9.8 is preinstalled on OSX. Some features are only available when
linking against OpenSSL 1.0.0 or greater; see below on how to point
rust-openssl to a separate installation.

### Windows

Install OpenSSL from [here][1]. Cargo will not be able to find OpenSSL if it's
installed to the default location. You can either copy the `include/openssl`
directory, `libssl32.dll`, and `libeay32.dll` to locations that Cargo can find
or pass the location to Cargo via environment variables:

```bash
env OPENSSL_LIB_DIR=/c/OpenSSL-Win64 OPENSSL_INCLUDE_DIR=/c/OpenSSL-Win64/include cargo build
```

### Manual configuration

rust-openssl's build script will by default attempt to locate OpenSSL via
pkg-config. This will not work in some situations, for example, on systems that
don't have pkg-config, when cross compiling, or when using a copy of OpenSSL
other than the normal system install.

The build script can be configured via environment variables:
* `OPENSSL_LIB_DIR` - If specified, a directory that will be used to find
    OpenSSL runtime libraries.
* `OPENSSL_INCLUDE_DIR` - If specified, a directory that will be used to find
    OpenSSL headers.
* `OPENSSL_STATIC` - If specified, OpenSSL libraries will be statically rather
    than dynamically linked.

If either `OPENSSL_LIB_DIR` or `OPENSSL_INCLUDE_DIR` are specified, then the
build script will skip the pkg-config step.

## Testing
Several tests expect a local test server to be running to bounce requests off
of. It's easy to do this. Open a separate terminal window and `cd` to the
rust-openssl directory. Then run one of the following commands:

* Windows: `openssl s_server -accept 15418 -www -cert test/cert.pem -key
  test/key.pem > NUL`
* Linux: `openssl s_server -accept 15418 -www -cert test/cert.pem -key
  test/key.pem >/dev/null`

Then in the original terminal, run `cargo test`. If everything is set up
correctly, all tests should pass. You might get some warnings in the `openssl
s_server` window. Those aren't anything to worry about. You can stop the server
using Control-C.

[1]: http://slproweb.com/products/Win32OpenSSL.html
