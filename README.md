rust-openssl [![Build Status](https://travis-ci.org/sfackler/rust-openssl.svg?branch=master)](https://travis-ci.org/sfackler/rust-openssl)
============

See the [rustdoc output](https://sfackler.github.io/doc/openssl).

Building
--------

rust-openssl needs to link against the OpenSSL devleopment libraries on your system. It's very easy to get them on Linux.  
For some reason, the OpenSSL distribution for Windows is structured differently, so it's a little more involved, but it *is* possible to build rust-openssl successfully on Windows.

###Linux

1. Run `sudo apt-get install libssl-dev`.
2. Run `cargo build`.

###Android
1. Follow the steps [here](wiki.openssl.org/index.php/Android) to build OpenSSL for android
2. Provide the path to the libssl and libcrypto binaries via `$OPENSSL_PATH`
3. Build the package with `cargo build`

###Windows

1. Grab the latest Win32 OpenSSL installer [here][1]. At the time of this writing, it's v1.0.1i. If you're using 64-bit Rust (coming to Windows soon), then you should get the Win64 installer instead.
2. Run the installer, making note of where it's installing OpenSSL. The option to copy the libraries to the Windows system directory or `[OpenSSL folder]/bin` is your choice. The latter is probably preferable, and the default.
3. Navigate to `[OpenSSL folder]/lib/MinGW/`, and copy `libeay32.a` and `ssleay32.a` (If 64-bit, then they will have `64` instead of `32`.) to your Rust install's libs folder. The default should be: 
  * 32-bit: `C:\Program Files (x86)\Rust\bin\rustlib\i686-pc-mingw32\lib`
  * 64-bit: `C:\Program Files (x86)\Rust\bin\rustlib\x86_64-pc-windows-gnu\lib`
4. Rename `libeay32.a` and `ssleay32.a` to `libcrypto.a` and `libssl.a`, respectively. 
5. Run `cargo build`.

###OS X

OS X is shipped with extremely outdated openssl. We recommend to update it. If you're using Homebrew it should be as easy as:

```bash
brew install openssl
brew link openssl --force
```

Note that you need to execute `cargo clean` in your project directory to rebuild `rust-openssl` with the new version of `openssl`.

###Testing
Several tests expect a local test server to be running to bounce requests off of. It's easy to do this. Open a separate terminal window and `cd` to the rust-openssl directory. Then run one of the following commands:

* Windows: `openssl s_server -accept 15418 -www -cert test/cert.pem -key test/key.pem > NUL`
* Linux: `openssl s_server -accept 15418 -www -cert test/cert.pem -key test/key.pem >/dev/null`

Then in the original terminal, run `cargo test`. If everything is set up correctly, all tests should pass. You might get some warnings in the `openssl s_server` window. Those aren't anything to worry about. You can stop the server using Control-C.

[1]: http://slproweb.com/products/Win32OpenSSL.html
