RUSTPKG ?= rustpkg
RUSTC ?= rustc
RUST_FLAGS ?= -Z debug-info -O

all:
	$(RUSTPKG) $(RUST_FLAGS) install

test:
	$(RUSTC) $(RUST_FLAGS) --test lib.rs
	./rust-openssl

clean:
	rm -rf bin/ lib/ build/ src/crypto/lib
