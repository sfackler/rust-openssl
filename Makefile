default:
	rm -f $(OUT_DIR)/bin_is_zero.o
	$(CC) -O -shared native/bn_is_zero.c -o bn_is_zero.o
	mv bn_is_zero.o $(OUT_DIR)
