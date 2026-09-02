# Nightfall DLP — build targets
#
#   make bpf             compile the eBPF LSM enforcer (clang -target bpf)
#   make classify_test   build + run the userspace classifier unit tests
#   make clean           remove build artifacts
#
# The loader target is added once the userspace agent lands.

CC      ?= gcc
CLANG   ?= clang
CFLAGS  ?= -g -O2 -Wall

# uname -m -> BPF target arch macro (x86_64 -> x86)
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

BPF_SRC := bpf/dlp.bpf.c
BPF_OBJ := bpf/dlp.bpf.o
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I bpf

BUILD := build

.PHONY: all clean bpf classify_test

all: bpf classify_test

# --- kernel: eBPF LSM enforcer object ---------------------------------------
$(BPF_OBJ): $(BPF_SRC) bpf/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

bpf: $(BPF_OBJ)

# --- userspace: content classifier unit tests -------------------------------
$(BUILD)/classify_test: test/classify_test.c src/classify.c src/classify.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ test/classify_test.c src/classify.c

classify_test: $(BUILD)/classify_test
	./$(BUILD)/classify_test

clean:
	rm -rf $(BUILD) bpf/*.o
