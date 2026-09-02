# Nightfall DLP — build targets
#
#   make classify_test   build + run the userspace classifier unit tests
#   make clean           remove build artifacts
#
# More targets (bpf, loader) are added as the agent is assembled.

CC      ?= gcc
CFLAGS  ?= -g -O2 -Wall

BUILD := build

.PHONY: all clean classify_test

all: classify_test

# --- userspace: content classifier unit tests -------------------------------
$(BUILD)/classify_test: test/classify_test.c src/classify.c src/classify.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ test/classify_test.c src/classify.c

classify_test: $(BUILD)/classify_test
	./$(BUILD)/classify_test

clean:
	rm -rf $(BUILD) bpf/*.o
