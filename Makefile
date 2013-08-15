
crypto: $(wildcard *.rs)
	rustc crypto.rs
	rustc --test crypto.rs

clean:
	rm -f crypto libcrypto-*.so
	rm -f libcrypto-*.dylib
	rm -rf *.dSYM
