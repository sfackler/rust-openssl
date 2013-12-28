RUSTPKG ?= rustpkg
RUSTC ?= rustc
RUST_FLAGS ?= -Z debug-info -O

all:
	$(RUSTPKG) $(RUST_FLAGS) install crypto

test:
	$(RUSTC) $(RUST_FLAGS) --test src/crypto/lib.rs
	./src/crypto/crypto

clean:
	rm -rf bin/ lib/ build/ src/crypto/lib
