CARGO ?= cargo
CARGO_FLAGS ?=
CC := arm-none-eabi-gcc
CFLAGS ?= -mcpu=cortex-m0 -mthumb -O0 -g -fno-inline -ffreestanding -nostdlib \
	-Wall -Wextra
ROOT := ../..
ARTIFACTS := artifacts
ELF := $(ARTIFACTS)/cortex-m0-isr.elf
TOOL := $(CARGO) run --quiet $(CARGO_FLAGS) --manifest-path $(ROOT)/Cargo.toml -p elf2tdg --

.PHONY: all analyze clean

all: analyze

$(ARTIFACTS):
	mkdir -p $@

$(ELF): main.c linker.ld | $(ARTIFACTS)
	$(CC) $(CFLAGS) -T linker.ld -Wl,--emit-relocs -o $@ main.c

analyze: $(ELF)
	$(TOOL) $(ELF) --cpu cortex-m0 --freq 48MHz --format json \
		--output $(ARTIFACTS)/tdg.json --verbose
	$(TOOL) $(ELF) --cpu cortex-m0 --freq 48MHz --format dot --legend \
		--output $(ARTIFACTS)/tdg-full.dot
	dot -Tsvg $(ARTIFACTS)/tdg-full.dot -o $(ARTIFACTS)/tdg-full.svg
	$(TOOL) $(ELF) --cpu cortex-m0 --freq 48MHz --format dot \
		--output $(ARTIFACTS)/tdg-full-compact.dot
	dot -Tsvg $(ARTIFACTS)/tdg-full-compact.dot \
		-o $(ARTIFACTS)/tdg-full-compact.svg
	$(TOOL) $(ELF) --cpu cortex-m0 --freq 48MHz --format mermaid --legend \
		--output $(ARTIFACTS)/tdg-full.mmd

clean:
	rm -rf $(ARTIFACTS)
