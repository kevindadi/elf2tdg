CARGO ?= cargo
CARGO_FLAGS ?=
ROOT := ../..
ARTIFACTS := artifacts

ELF_ANALYSIS := $(ARTIFACTS)/rust-concurrency-analysis.elf
ANALYSIS_BIN := target/analysis/rust-concurrency
MAIN_ANALYSIS := rust_concurrency::main
TOOL := $(CARGO) run --quiet $(CARGO_FLAGS) --manifest-path $(ROOT)/Cargo.toml -p elf2tdg --

.PHONY: all analysis clean

all: analysis

$(ARTIFACTS):
	mkdir -p $@

$(ANALYSIS_BIN): main.rs Cargo.toml
	$(CARGO) build $(CARGO_FLAGS) --profile analysis --manifest-path Cargo.toml

$(ELF_ANALYSIS): $(ANALYSIS_BIN) | $(ARTIFACTS)
	cp $< $@

analysis: $(ELF_ANALYSIS)
	$(TOOL) $(ELF_ANALYSIS) --format json \
		--output $(ARTIFACTS)/tdg-analysis.json --verbose
	$(TOOL) $(ELF_ANALYSIS) --format dot --projection concurrency --legend \
		--output $(ARTIFACTS)/tdg-analysis-concurrency.dot
	dot -Tsvg $(ARTIFACTS)/tdg-analysis-concurrency.dot \
		-o $(ARTIFACTS)/tdg-analysis-concurrency.svg
	$(TOOL) $(ELF_ANALYSIS) --format dot --projection concurrency \
		--output $(ARTIFACTS)/tdg-analysis-concurrency-compact.dot
	dot -Tsvg $(ARTIFACTS)/tdg-analysis-concurrency-compact.dot \
		-o $(ARTIFACTS)/tdg-analysis-concurrency-compact.svg
	$(TOOL) $(ELF_ANALYSIS) --format mermaid --projection concurrency --legend \
		--output $(ARTIFACTS)/tdg-analysis-concurrency.mmd
	$(TOOL) $(ELF_ANALYSIS) --view cfg --format json \
		--function $(MAIN_ANALYSIS) \
		--output $(ARTIFACTS)/cfg-analysis-main.json
	$(TOOL) $(ELF_ANALYSIS) --view cfg --format dot \
		--function $(MAIN_ANALYSIS) \
		--output $(ARTIFACTS)/cfg-analysis-main.dot
	dot -Tsvg $(ARTIFACTS)/cfg-analysis-main.dot \
		-o $(ARTIFACTS)/cfg-analysis-main.svg
	$(TOOL) $(ELF_ANALYSIS) --view cfg --format mermaid \
		--function $(MAIN_ANALYSIS) \
		--output $(ARTIFACTS)/cfg-analysis-main.mmd
	$(TOOL) $(ELF_ANALYSIS) --view elf --elf-max-insns 128 \
		--output $(ARTIFACTS)/elf-layout-analysis.mmd

clean:
	rm -rf $(ARTIFACTS) target
