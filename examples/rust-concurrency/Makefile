CARGO ?= cargo
CARGO_FLAGS ?=
ROOT := ../..
TARGET := thumbv7em-none-eabi
ARTIFACTS := artifacts

ELF_ANALYSIS := $(ARTIFACTS)/rust-concurrency-analysis.elf
ANALYSIS_BIN := target/$(TARGET)/analysis/rust-concurrency
MAIN_ANALYSIS := rust_concurrency::start_tasks
EXECUTOR_ANALYSIS := Executor>::run
TASK_ANALYSIS := sensor_task
TIMING := --cpu cortex-m4 --freq 168MHz
TOOL := CARGO_BUILD_TARGET=x86_64-unknown-linux-gnu $(CARGO) run --quiet $(CARGO_FLAGS) --manifest-path $(ROOT)/Cargo.toml -p elf2tdg --

.PHONY: all analysis clean

all: analysis

$(ARTIFACTS):
	mkdir -p $@

$(ANALYSIS_BIN): main.rs Cargo.toml Cargo.lock memory.x .cargo/config.toml
	$(CARGO) build $(CARGO_FLAGS) --profile analysis --target $(TARGET) --manifest-path Cargo.toml

$(ELF_ANALYSIS): $(ANALYSIS_BIN) | $(ARTIFACTS)
	cp $< $@

analysis: $(ELF_ANALYSIS)
	$(TOOL) $(ELF_ANALYSIS) $(TIMING) --view cfg --format json \
		--function $(MAIN_ANALYSIS) \
		--output $(ARTIFACTS)/cfg-analysis-main.json
	$(TOOL) $(ELF_ANALYSIS) $(TIMING) --view cfg --format dot \
		--function $(MAIN_ANALYSIS) \
		--output $(ARTIFACTS)/cfg-analysis-main.dot
	dot -Tsvg $(ARTIFACTS)/cfg-analysis-main.dot \
		-o $(ARTIFACTS)/cfg-analysis-main.svg
	$(TOOL) $(ELF_ANALYSIS) $(TIMING) --view cfg --format mermaid \
		--function $(MAIN_ANALYSIS) \
		--output $(ARTIFACTS)/cfg-analysis-main.mmd
	$(TOOL) $(ELF_ANALYSIS) $(TIMING) --view cfg --format json \
		--function '$(EXECUTOR_ANALYSIS)' \
		--output $(ARTIFACTS)/cfg-analysis-executor.json
	$(TOOL) $(ELF_ANALYSIS) $(TIMING) --view cfg --format dot \
		--function '$(EXECUTOR_ANALYSIS)' \
		--output $(ARTIFACTS)/cfg-analysis-executor.dot
	dot -Tsvg $(ARTIFACTS)/cfg-analysis-executor.dot \
		-o $(ARTIFACTS)/cfg-analysis-executor.svg
	$(TOOL) $(ELF_ANALYSIS) $(TIMING) --view cfg --format mermaid \
		--function '$(EXECUTOR_ANALYSIS)' \
		--output $(ARTIFACTS)/cfg-analysis-executor.mmd
	$(TOOL) $(ELF_ANALYSIS) $(TIMING) --view cfg --format json \
		--function '$(TASK_ANALYSIS)' \
		--output $(ARTIFACTS)/cfg-analysis-sensor.json
	$(TOOL) $(ELF_ANALYSIS) $(TIMING) --view cfg --format dot \
		--function '$(TASK_ANALYSIS)' \
		--output $(ARTIFACTS)/cfg-analysis-sensor.dot
	dot -Tsvg $(ARTIFACTS)/cfg-analysis-sensor.dot \
		-o $(ARTIFACTS)/cfg-analysis-sensor.svg
	$(TOOL) $(ELF_ANALYSIS) $(TIMING) --view cfg --format mermaid \
		--function '$(TASK_ANALYSIS)' \
		--output $(ARTIFACTS)/cfg-analysis-sensor.mmd
	$(TOOL) $(ELF_ANALYSIS) --view elf --elf-max-insns 128 \
		--output $(ARTIFACTS)/elf-layout-analysis.mmd

clean:
	rm -rf $(ARTIFACTS) target
