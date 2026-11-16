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
	$(TOOL) $(ELF) --cpu cortex-m0 --freq 48MHz --view cfg --format json \
		--function main --output $(ARTIFACTS)/cfg-main.json
	$(TOOL) $(ELF) --cpu cortex-m0 --freq 48MHz --view cfg --format dot \
		--function main --output $(ARTIFACTS)/cfg-main.dot
	dot -Tsvg $(ARTIFACTS)/cfg-main.dot -o $(ARTIFACTS)/cfg-main.svg
	$(TOOL) $(ELF) --cpu cortex-m0 --freq 48MHz --view cfg --format mermaid \
		--function main --output $(ARTIFACTS)/cfg-main.mmd
	$(TOOL) $(ELF) --view elf --output $(ARTIFACTS)/elf-layout.mmd
	$(TOOL) $(ELF) --cpu cortex-m0 --freq 48MHz --view cfg --format json \
		--output $(ARTIFACTS)/cfg-system.json
	$(TOOL) $(ELF) --cpu cortex-m0 --freq 48MHz --view cfg --format dot \
		--output $(ARTIFACTS)/cfg-system.dot
	dot -Tsvg $(ARTIFACTS)/cfg-system.dot -o $(ARTIFACTS)/cfg-system.svg
	$(TOOL) $(ELF) --cpu cortex-m0 --freq 48MHz --view cfg --format mermaid \
		--output $(ARTIFACTS)/cfg-system.mmd

clean:
	rm -rf $(ARTIFACTS)
