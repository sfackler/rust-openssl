
crypto: crypto.rc $(wildcard *.rs)
	rustc crypto.rc
	rustc --test crypto.rc

clean:
	rm -f crypto libcrypto-*.so
	rm -f libcrypto-*.dylib
	rm -rf *.dSYM
