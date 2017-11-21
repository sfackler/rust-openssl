# rust-openssl

[![CircleCI](https://circleci.com/gh/sfackler/rust-openssl.svg?style=shield)](https://circleci.com/gh/sfackler/rust-openssl) [![Build status](https://ci.appveyor.com/api/projects/status/d1knobws948pyynk/branch/master?svg=true)](https://ci.appveyor.com/project/sfackler/rust-openssl/branch/master)

[Documentation](https://docs.rs/openssl).

## Warning

This README does not correspond to rust-openssl 0.7.x or 0.8.x. See
[here](https://github.com/sfackler/rust-openssl/blob/b8fb29db5c246175a096260eacca38180cd77dd0/README.md)
for that README.

## Building

rust-openssl depends on OpenSSL version 1.0.1 or above, or LibreSSL. Both the
libraries and headers need to be present in the build environment before this
crate is compiled, and some instructions of how to do this are in the sections
below.

### Linux

On Linux, you can typically install OpenSSL via your package manager. The
headers are sometimes provided in a separate package than the runtime libraries
- look for something like `openssl-devel` or `libssl-dev`. You will also need the
regular development utilities, like `pkg-config`, as the custom build script relies
on them.

```bash
# On Debian and Ubuntu
sudo apt-get install pkg-config libssl-dev
# On Arch Linux
sudo pacman -S openssl
# On Fedora
sudo dnf install openssl-devel
```

If installation via a package manager is not possible, or if you're cross
compiling to a separate target, you'll typically need to compile OpenSSL from
source. That can normally be done with:

```
curl -O https://www.openssl.org/source/openssl-1.1.0f.tar.gz
tar xf openssl-1.1.0f.tar.gz
cd openssl-1.1.0f
export CC=...
./Configure --prefix=... linux-x86_64 -fPIC
make -j$(nproc)
make install
```

### OSX

Although OpenSSL 0.9.8 is preinstalled on OSX this library is being phased out
of OSX and this crate also does not support that version of OpenSSL. To use this
crate on OSX you'll need to install OpenSSL via some alternate means, typically
Homebrew:

```bash
brew install openssl
```

Occasionally an update of XCode or MacOS will cause the linker to fail after compilation, to rectify this you may want to try and run:

```bash
xcode-select --install
```

If Homebrew is installed to the default location of `/usr/local`, OpenSSL will be
automatically detected.

### Windows MSVC

On MSVC it's unfortunately not always a trivial process acquiring OpenSSL. A couple of possibilities
are downloading precompiled binaries for OpenSSL 1.1.0, or installing OpenSSL 1.0.2 using vcpkg.

#### Installing OpenSSL 1.1.0 using precompiled binaries

Perhaps the easiest way to do this right now is to download [precompiled
binaries] and install them on your system. Currently it's recommended to
install the 1.1.0 (non-light) installation if you're choosing this route.

[precompiled binaries]: http://slproweb.com/products/Win32OpenSSL.html

Once a precompiled binary is installed you can configure this crate to find the
installation via an environment variable:

```
set OPENSSL_DIR=C:\OpenSSL-Win64
```

During the installation process if you select "Copy OpenSSL DLLs to: The OpenSSL binaries (/bin)
directory", you will need to add them to the `PATH` environment variable:

```
set PATH=%PATH%;C:\OpenSSL-Win64\bin
```

Now you will need to [install root certificates.](#acquiring-root-certificates)

#### Installing OpenSSL 1.0.2 using vcpkg

Install [vcpkg](https://github.com/Microsoft/vcpkg), and install the OpenSSL port like this:

```Batchfile
vcpkg install openssl:x64-windows
set VCPKG_ROOT=c:\path\to\vcpkg\installation
cargo build
```

For more information see the vcpkg build helper [documentation](http://docs.rs/vcpkg).
To finsh setting up OpenSSL you will need to [install root certificates.](#acquiring-root-certificates)

#### Acquiring Root Certificates

Neither of the above OpenSSL distributions ship with any root certificates.
So to make requests to servers on the internet, you have to install them
manually. Download the [cacert.pem file from here], copy it somewhere safe
(`C:\OpenSSL-Win64\certs` is a good place) and point the `SSL_CERT_FILE`
environment variable there:

```
set SSL_CERT_FILE=C:\OpenSSL-Win64\certs\cacert.pem
```

[cacert.pem file from here]: https://curl.haxx.se/docs/caextract.html

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
* `OPENSSL_LIB_DIR` - If specified, a directory that will be used to find
  OpenSSL libraries. Overrides the `lib` folder implied by `OPENSSL_DIR`
  (if specified).
* `OPENSSL_INCLUDE_DIR` - If specified, a directory that will be used to find
  OpenSSL header files. Overrides the `include` folder implied by `OPENSSL_DIR`
  (if specified).
* `OPENSSL_STATIC` - If specified, OpenSSL libraries will be statically rather
  than dynamically linked.
* `OPENSSL_LIBS` - If specified, the names of the OpenSSL libraries that will be
  linked, e.g. `ssl:crypto`.

If `OPENSSL_DIR` or `OPENSSL_LIB_DIR` and `OPENSSL_INCLUDE_DIR` is specified,
then the build script will skip the pkg-config step.

For target-specific configuration, each of these environment variables can be
prefixed by an upper-cased target, for example,
`X86_64_UNKNOWN_LINUX_GNU_OPENSSL_DIR`. This can be useful in cross compilation
contexts.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed under the terms of both the Apache License,
Version 2.0 and the MIT license without any additional terms or conditions.
