TARGET = denat
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_OBJ = ${TARGET:=.bpf.o}
USER_C = ${TARGET:=.c}
USER_SKEL = ${TARGET:=.skel.h}
BPF_H = ${TARGET:=.bpf.h}
LIBBPF_DIR ?= ./libbpf/src
LIBBPF_INCLUDES = $(LIBBPF_DIR)
LIBBPF_STATIC_LIB = $(LIBBPF_DIR)/libbpf.a

CFLAGS=-Wall
ifdef DENAT_VERBOSE
	CFLAGS+= -DDENAT_VERBOSE
endif
ifdef DENAT_EXTRA_LOG
	CFLAGS+= -DDENAT_EXTRA_LOG
endif
ifdef DENAT_VERIFIER
	CFLAGS+= -DDENAT_VERIFIER
endif

.PHONY: all
all: clean $(LIBBPF_STATIC_LIB) $(BPF_OBJ) $(TARGET)

.PHONY: clean
dev: clean all
	rsync -ahv --exclude '.git' ./* mlk@ubu-ebpf3:/home/mlk/dev/denat

$(TARGET): $(USER_C) $(USER_SKEL) commons.h
	gcc $(CFLAGS) \
	-o $(TARGET) \
	$(USER_C) \
	-L$(LIBBPF_DIR) \
	-l:libbpf.a -lelf -lz

$(BPF_OBJ): %.o: %.c $(BPF_H) vmlinux.h commons.h
	clang $(CFLAGS) \
	    -target bpf \
	    -D__BPF_TRACING__ \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-I$(LIBBPF_INCLUDES) \
		-Wno-macro-redefined \
	    -O2  \
	    -g \
	    -o $@ -c $<
	 llvm-strip -g $@

$(USER_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

$(LIBBPF_STATIC_LIB): $(wildcard $(LIBBPF_DIR)/*.c) $(wildcard $(LIBBPF_DIR)/*.h)
	BUILD_STATIC_ONLY=y $(MAKE) -C $(LIBBPF_DIR)

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	- rm $(BPF_OBJ)
	- rm $(TARGET)
