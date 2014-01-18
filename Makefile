RUSTC = rustc
BUILDDIR = build
RUSTFLAGS = -O -Z debug-info

OPENSSL_LIB = lib.rs
OPENSSL = $(BUILDDIR)/$(shell $(RUSTC) --crate-file-name $(OPENSSL_LIB))
OPENSSL_TEST = $(BUILDDIR)/$(shell $(RUSTC) --test --crate-file-name $(OPENSSL_LIB))

all: $(OPENSSL)

-include $(BUILDDIR)/openssl.d
-include $(BUILDDIR)/openssl_test.d

$(BUILDDIR):
	mkdir -p $@

$(OPENSSL): $(OPENSSL_LIB) | $(BUILDDIR)
	$(RUSTC) $(RUSTFLAGS) --dep-info $(@D)/openssl.d --out-dir $(@D) $<

check: $(OPENSSL_TEST)
	$<

$(OPENSSL_TEST): $(OPENSSL_LIB) | $(BUILDDIR)
	$(RUSTC) $(RUSTFLAGS) --test --dep-info $(@D)/openssl_test.d \
		--out-dir $(@D) $<

clean:
	rm -rf $(BUILDDIR)

.PHONY: all check clean
