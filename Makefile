TARGET = denat
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_OBJ = ${TARGET:=.bpf.o}
USER_C = ${TARGET:=.c}
USER_SKEL = ${TARGET:=.skel.h}
BPF_H = ${TARGET:=.bpf.h}

.PHONY: all
all: $(TARGET) $(BPF_OBJ)

$(TARGET): $(USER_C) $(USER_SKEL) commons.h
	gcc -Wall -o $(TARGET) $(USER_C) -L../libbpf/src -l:libbpf.a -lelf -lz

$(BPF_OBJ): %.o: %.c $(BPF_H) vmlinux.h commons.h
	clang \
	    -target bpf \
	    -D __BPF_TRACING__ \
		-I/usr/include/$(shell uname -m)-linux-gnu \
	    -Wall \
	    -O2  \
	    -g \
	    -o $@ -c $<
	 llvm-strip -g $@

$(USER_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	- rm $(BPF_OBJ)
	- rm $(TARGET)
