# rust-openssl

[![Build Status](https://travis-ci.org/sfackler/rust-openssl.svg?branch=master)](https://travis-ci.org/sfackler/rust-openssl)

[Documentation](https://sfackler.github.io/rust-openssl/doc/v0.8.3/openssl).

## Building

rust-openssl depends on the OpenSSL runtime libraries version 1.0.1 or above.
Currently the libraries need to be present in the build environment before this
crate is compiled, and some instructions of how to do this are in the sections
below.

### Linux

On Linux, you can typically install OpenSSL via your package manager. The
headers are sometimes provided in a separate package than the runtime libraries
- look for something like `openssl-devel` or `libssl-dev`.

```bash
# On Ubuntu
sudo apt-get install libssl-dev
# On Arch Linux
sudo pacman -S openssl
# On Fedora
sudo dnf install openssl-devel
```

If installation via a package manager is not possible, or if you're cross
compiling to a separate target, you'll typically need to compile OpenSSL from
source. That can normally be done with:

```
curl -O https://www.openssl.org/source/openssl-1.1.0b.tar.gz
tar xf openssl-1.1.0b.tar.gz
cd openssl-1.1.0b
export CC=...
./Configure --prefix=... linux-x86_64 -fPIC
make -j$(nproc)
make install
```

### OSX

Although OpenSSL 0.9.8 is preinstalled on OSX this library is being phased out
of OSX and this crate also does not support this version of OpenSSL. To use this
crate on OSX you'll need to install OpenSSL via some alternate means, typically
homebrew:

```bash
brew install openssl
```

### Windows MSVC

On MSVC it's unfortunately not always a trivial process acquiring OpenSSL.
Perhaps the easiest way to do this right now is to download [precompiled
binaries] and install them on your system. Currently it's recommended to
install the 1.1.0b light installation if you're choosing this route.

[precompiled binaries]: http://slproweb.com/products/Win32OpenSSL.html

Once a precompiled binary is installed you can configure this crate to find the
installation via an environment variable:

```
set OPENSSL_DIR=C:\OpenSSL-Win64
```

After that, you're just a `cargo build` away!

### Windows GNU (MinGW)

The easiest way to acquire OpenSSL when working with MinGW is to ensure you're
using [MSYS2](http://msys2.github.io) and to then execute:

```
# 32-bit
pacman -S mingw-w64-i686-openssl

# 64-bit
pacman -S mingw-w64-x86_64-openssl
```

And after that, a `cargo build` should be all you need!

### Manual configuration

rust-openssl's build script will by default attempt to locate OpenSSL via
pkg-config or other system-specific mechanisms. This will not work in some
situations however, for example cross compiling or when using a copy of OpenSSL
other than the normal system install.

The build script can be configured via environment variables:

* `OPENSSL_DIR` - If specified, a directory that will be used to find
  OpenSSL installation. It's expected that under this directory the `include`
  folder has header files and a `lib` folder has the runtime libraries.
* `OPENSSL_STATIC` - If specified, OpenSSL libraries will be statically rather
  than dynamically linked.

If `OPENSSL_DIR` is specified, then the build script will skip the pkg-config
step.
