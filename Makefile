CARGO ?= cargo
FIXTURE_DIR := tests/fixtures/cortex_m0
FIXTURE_ELF := $(FIXTURE_DIR)/firmware.elf
SPAWN_FIXTURE_DIR := tests/fixtures/cortex_m_spawn
SPAWN_FIXTURE_ELF := $(SPAWN_FIXTURE_DIR)/firmware.elf
ALLOC_FIXTURE_DIR := tests/fixtures/rust_alloc_trait
STATIC_TRAIT_FIXTURE_DIR := tests/fixtures/rust_static_trait

.PHONY: test lint fuzz fuzz-seed fixture alloc-fixture static-trait-fixture examples analyze-fixture analyze-spawn-fixture analyze-cfg-fixture analyze-elf-fixture clean

test:
	$(CARGO) test --workspace

lint:
	$(CARGO) fmt --all --check
	$(CARGO) fmt --manifest-path fuzz/Cargo.toml -- --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings

fuzz-seed:
	mkdir -p fuzz/corpus/elf_analysis
	cp examples/rust-concurrency/artifacts/rust-concurrency-analysis.elf \
		fuzz/corpus/elf_analysis/rust-concurrency.elf
	cp examples/cortex-m0-isr/artifacts/cortex-m0-isr.elf \
		fuzz/corpus/elf_analysis/cortex-m0-isr.elf
	cp tests/fixtures/rust_alloc_trait/firmware.elf \
		fuzz/corpus/elf_analysis/rust-alloc-trait.elf
	cp tests/fixtures/rust_static_trait/firmware.elf \
		fuzz/corpus/elf_analysis/rust-static-trait.elf

fuzz: fuzz-seed
	cargo +nightly fuzz run elf_analysis -- -max_len=2097152

fixture:
	$(MAKE) -C $(FIXTURE_DIR)
	$(MAKE) -C $(SPAWN_FIXTURE_DIR)

alloc-fixture:
	$(MAKE) -C $(ALLOC_FIXTURE_DIR)

static-trait-fixture:
	$(MAKE) -C $(STATIC_TRAIT_FIXTURE_DIR)

examples:
	$(MAKE) -C examples/rust-concurrency
	$(MAKE) -C examples/cortex-m0-isr

analyze-fixture: $(FIXTURE_ELF)
	$(CARGO) run -p elf2tdg -- $(FIXTURE_ELF) --freq 48MHz --format json \
		--output /tmp/elf2tdg-cortex-m0.json --verbose

analyze-spawn-fixture: $(SPAWN_FIXTURE_ELF)
	$(CARGO) run -p elf2tdg -- $(SPAWN_FIXTURE_ELF) --freq 48MHz --format json \
		--output /tmp/elf2tdg-cortex-m-spawn.json --verbose

analyze-cfg-fixture: $(FIXTURE_ELF)
	$(CARGO) run -p elf2tdg -- $(FIXTURE_ELF) --view cfg --format json \
		--function main --output /tmp/elf2tdg-cortex-m0-main.cfg.json --verbose
	$(CARGO) run -p elf2tdg -- $(FIXTURE_ELF) --view cfg --format dot \
		--function main --output /tmp/elf2tdg-cortex-m0-main.dot --verbose

analyze-elf-fixture: $(FIXTURE_ELF)
	$(CARGO) run -p elf2tdg -- $(FIXTURE_ELF) --view elf \
		--output /tmp/elf2tdg-cortex-m0-layout.mmd --verbose

$(FIXTURE_ELF):
	$(MAKE) -C $(FIXTURE_DIR)

$(SPAWN_FIXTURE_ELF):
	$(MAKE) -C $(SPAWN_FIXTURE_DIR)

clean:
	$(CARGO) clean
	rm -rf fuzz/target
	$(MAKE) -C $(FIXTURE_DIR) clean
	$(MAKE) -C $(SPAWN_FIXTURE_DIR) clean
	$(MAKE) -C $(ALLOC_FIXTURE_DIR) clean
	$(MAKE) -C $(STATIC_TRAIT_FIXTURE_DIR) clean
	$(MAKE) -C examples/rust-concurrency clean
	$(MAKE) -C examples/cortex-m0-isr clean
