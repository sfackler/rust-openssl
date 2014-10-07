ifneq ($(findstring i686,$(TARGET)),)
	CFLAGS += -m32
else
	CFLAGS += -m64
endif

default:
	$(CC) $(CFLAGS) -c native/bn_is_zero.c -o $(OUT_DIR)/bn_is_zero.o
	$(AR) crus $(OUT_DIR)/libwrapped.a $(OUT_DIR)/bn_is_zero.o
