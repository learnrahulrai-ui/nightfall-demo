# Nightfall DLP — build targets
#
#   make bpf             compile the eBPF LSM enforcer (clang -target bpf)
#   make loader          build the userspace agent (libbpf: -lbpf -lelf -lz)
#   make clipboard       build the X11 clipboard watcher (-lX11 -lXfixes)
#   make classify_test   build + run the userspace classifier unit tests
#   make clean           remove build artifacts

CC      ?= gcc
CLANG   ?= clang
CFLAGS  ?= -g -O2 -Wall

# uname -m -> BPF target arch macro (x86_64 -> x86)
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

BPF_SRC := bpf/dlp.bpf.c
BPF_OBJ := bpf/dlp.bpf.o
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I bpf

BUILD := build

.PHONY: all clean bpf loader classify_test clipboard filewatch fanotify identity ssl agent sensors demos

all: bpf loader classify_test

# build every userspace sensor
sensors: filewatch fanotify identity ssl clipboard
# build the whole thing: kernel + loader + sensors + unified agent
demos: all sensors agent

# --- kernel: eBPF LSM enforcer object ---------------------------------------
$(BPF_OBJ): $(BPF_SRC) bpf/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

bpf: $(BPF_OBJ)

# --- userspace: libbpf loader/agent -----------------------------------------
$(BUILD)/loader: src/loader.c src/classify.c src/classify.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -Isrc -o $@ src/loader.c src/classify.c -lbpf -lelf -lz

loader: $(BUILD)/loader

# --- userspace: X11 clipboard watcher (DLP source #3) -----------------------
$(BUILD)/clipboard_watch: clipboard/clipboard_watch.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ clipboard/clipboard_watch.c -lX11 -lXfixes

clipboard: $(BUILD)/clipboard_watch

# --- userspace: content classifier unit tests -------------------------------
$(BUILD)/classify_test: test/classify_test.c src/classify.c src/classify.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ test/classify_test.c src/classify.c

classify_test: $(BUILD)/classify_test
	./$(BUILD)/classify_test

# --- extra userspace sensors (each self-contained with its own classify) -----
$(BUILD)/filewatch: file/file_watch.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ file/file_watch.c
filewatch: $(BUILD)/filewatch

$(BUILD)/fanotify: file/fanotify_gate.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ file/fanotify_gate.c
fanotify: $(BUILD)/fanotify

$(BUILD)/identity: identity/identity.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ identity/identity.c
identity: $(BUILD)/identity

# --- SSL_write interpose: content above the TLS layer (links shared classify) -
$(BUILD)/dlp_ssl.so: network/ssl_preload.c common/classify.c common/policy.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -shared -fPIC -o $@ network/ssl_preload.c common/classify.c common/policy.c -ldl
ssl: $(BUILD)/dlp_ssl.so

# --- unified agent: all sensors under one epoll loop ------------------------
$(BUILD)/agent: agent/agent.c common/classify.c common/policy.c bpf
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -Icommon -o $@ agent/agent.c common/classify.c common/policy.c -lbpf -lelf -lz -lX11 -lXfixes
agent: $(BUILD)/agent

clean:
	rm -rf $(BUILD) bpf/*.o
