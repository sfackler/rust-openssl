# rust-openssl

[![Build Status](https://travis-ci.org/sfackler/rust-openssl.svg?branch=master)](https://travis-ci.org/sfackler/rust-openssl)

[Documentation](https://sfackler.github.io/rust-openssl/doc/v0.7.14/openssl).

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
# On Fedora
sudo dnf install openssl-devel
```

### OSX

OpenSSL 0.9.8 is preinstalled on OSX. Some features are only available when
linking against OpenSSL 1.0.0 or greater; see below on how to point
rust-openssl to a separate installation. OSX releases starting at 10.11, "El
Capitan", no longer include OpenSSL headers which will prevent the `openssl`
crate from compiling.

For OSX 10.11 you can use brew to install OpenSSL and then set the environment variables
as described below.
```bash
brew install openssl
export OPENSSL_INCLUDE_DIR=`brew --prefix openssl`/include
export OPENSSL_LIB_DIR=`brew --prefix openssl`/lib
```

### Windows

On Windows, consider building with [mingw-w64](http://mingw-w64.org/).
Build script will try to find mingw in `PATH` environment variable to provide
Cargo with location where openssl libs from mingw-w64 package may be found.

mingw-w64 can be easily installed by using [MSYS2](http://msys2.github.io/). Install MSYS2 according to the instructions, and then, from an MSYS2 Shell, install mingw-w64:

32-bit:
```bash
pacman -S mingw-w64-i686-gcc
``` 

64-bit
```bash
pacman -S mingw-w64-x86_64-gcc
```

and then install the mingw-w64 toolchain.

32-bit:
```bash
pacman -S mingw-w64-i686-toolchain
```

64-bit:
```bash
pacman -S mingw-w64-x86_64-toolchain
```

Alternatively, install OpenSSL from [here][1]. Cargo will not be able to find OpenSSL if it's
installed to the default location. You can either copy the `include/openssl`
directory, `libssl32.dll`, and `libeay32.dll` to locations that Cargo can find
or pass the location to Cargo via environment variables:

```bash
env OPENSSL_LIB_DIR=C:/OpenSSL-Win64 OPENSSL_INCLUDE_DIR=C:/OpenSSL-Win64/include cargo build
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

[1]: http://slproweb.com/products/Win32OpenSSL.html
