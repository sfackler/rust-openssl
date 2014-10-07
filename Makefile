default:
	rm -f $(OUT_DIR)/libbn_is_zero.a
	$(CC) -c -O2 native/bn_is_zero.c -o bn_is_zero.o
	ar rcs libbn_is_zero.a bn_is_zero.o
	mv libbn_is_zero.a $(OUT_DIR)
	rm -f bn_is_zero.o
