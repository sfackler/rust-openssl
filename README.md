# rust-openssl

[![Build Status](https://travis-ci.org/sfackler/rust-openssl.svg?branch=master)](https://travis-ci.org/sfackler/rust-openssl)

[Documentation](https://sfackler.github.io/rust-openssl/doc/v0.6.4/openssl).

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

On Windows, build with [mingw-w64](http://mingw-w64.org/).
Build script will try to find mingw in `PATH` environment variable to provide
Cargo with location where openssl libs from mingw-w64 package may be found.
If you followed guide [Building on Windows](https://github.com/rust-lang/rust#building-on-windows)
from rust repo, then you should have [MSYS2](http://msys2.github.io/) with
`mingw-w64-openssl` installed as part of `mingw-w64-x86_64-toolchain`
(or `mingw-w64-i686-toolchain`) package.

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
rust-openssl directory. Then run one of the following command:

```bash
./openssl/test/test.sh
```

This will boot a bunch of `openssl s_server` processes that the tests connect
to. Then in the original terminal, run `cargo test`. If everything is set up
correctly, all tests should pass. You can stop the servers with `killall
openssl`.

[1]: http://slproweb.com/products/Win32OpenSSL.html
