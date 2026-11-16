CARGO ?= cargo
CARGO_FLAGS ?=
ROOT := ../..
ARTIFACTS := artifacts
RUSTC ?= rustc

ELF_O0 := $(ARTIFACTS)/rust-concurrency-o0.elf
ELF_O2 := $(ARTIFACTS)/rust-concurrency-o2.elf
TOOL := $(CARGO) run --quiet $(CARGO_FLAGS) --manifest-path $(ROOT)/Cargo.toml -p elf2tdg --

.PHONY: all analyze clean

all: analyze

$(ARTIFACTS):
	mkdir -p $@

$(ELF_O0): main.rs | $(ARTIFACTS)
	$(RUSTC) --edition=2021 -C opt-level=0 -g -o $@ $<

$(ELF_O2): main.rs | $(ARTIFACTS)
	$(RUSTC) --edition=2021 -C opt-level=2 -g -o $@ $<

analyze: $(ELF_O0) $(ELF_O2)
	$(TOOL) $(ELF_O0) --format json --output $(ARTIFACTS)/tdg-o0.json --verbose
	$(TOOL) $(ELF_O0) --format dot --projection concurrency --legend \
		--output $(ARTIFACTS)/tdg-o0-concurrency.dot
	dot -Tsvg $(ARTIFACTS)/tdg-o0-concurrency.dot \
		-o $(ARTIFACTS)/tdg-o0-concurrency.svg
	$(TOOL) $(ELF_O0) --format dot --projection concurrency \
		--output $(ARTIFACTS)/tdg-o0-concurrency-compact.dot
	dot -Tsvg $(ARTIFACTS)/tdg-o0-concurrency-compact.dot \
		-o $(ARTIFACTS)/tdg-o0-concurrency-compact.svg
	$(TOOL) $(ELF_O0) --format mermaid --projection concurrency --legend \
		--output $(ARTIFACTS)/tdg-o0-concurrency.mmd
	$(TOOL) $(ELF_O2) --format json --output $(ARTIFACTS)/tdg-o2.json --verbose
	$(TOOL) $(ELF_O2) --format dot --projection concurrency --legend \
		--output $(ARTIFACTS)/tdg-o2-concurrency.dot
	dot -Tsvg $(ARTIFACTS)/tdg-o2-concurrency.dot \
		-o $(ARTIFACTS)/tdg-o2-concurrency.svg
	$(TOOL) $(ELF_O2) --format dot --projection concurrency \
		--output $(ARTIFACTS)/tdg-o2-concurrency-compact.dot
	dot -Tsvg $(ARTIFACTS)/tdg-o2-concurrency-compact.dot \
		-o $(ARTIFACTS)/tdg-o2-concurrency-compact.svg
	$(TOOL) $(ELF_O2) --format mermaid --projection concurrency --legend \
		--output $(ARTIFACTS)/tdg-o2-concurrency.mmd

clean:
	rm -rf $(ARTIFACTS)
