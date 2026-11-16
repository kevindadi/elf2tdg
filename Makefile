CARGO ?= cargo
FIXTURE_DIR := tests/fixtures/cortex_m0
FIXTURE_ELF := $(FIXTURE_DIR)/firmware.elf
SPAWN_FIXTURE_DIR := tests/fixtures/cortex_m_spawn
SPAWN_FIXTURE_ELF := $(SPAWN_FIXTURE_DIR)/firmware.elf
RUST_FIXTURE_SRC := tests/fixtures/rust_threads/main.rs

.PHONY: schema test lint fixture examples analyze-fixture analyze-spawn-fixture analyze-rust-fixture analyze-rust-fixture-o2 clean

schema:
	$(CARGO) run --quiet -p elf2tdg-schema --example dump_schema > schema/tdg.schema.json

test:
	$(CARGO) test --workspace

lint:
	$(CARGO) fmt --all --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings

fixture:
	$(MAKE) -C $(FIXTURE_DIR)
	$(MAKE) -C $(SPAWN_FIXTURE_DIR)

examples:
	$(MAKE) -C examples/rust-concurrency
	$(MAKE) -C examples/cortex-m0-isr

analyze-fixture: $(FIXTURE_ELF)
	$(CARGO) run -p elf2tdg -- $(FIXTURE_ELF) --freq 48MHz --format json \
		--output /tmp/elf2tdg-cortex-m0.json --verbose

analyze-spawn-fixture: $(SPAWN_FIXTURE_ELF)
	$(CARGO) run -p elf2tdg -- $(SPAWN_FIXTURE_ELF) --freq 48MHz --format json \
		--output /tmp/elf2tdg-cortex-m-spawn.json --verbose

analyze-rust-fixture:
	rustc --edition=2021 -C opt-level=0 -g -o /tmp/elf2tdg-rust-threads $(RUST_FIXTURE_SRC)
	$(CARGO) run -p elf2tdg -- /tmp/elf2tdg-rust-threads --format json \
		--output /tmp/elf2tdg-rust-threads.json --verbose

analyze-rust-fixture-o2:
	rustc --edition=2021 -C opt-level=2 -g -o /tmp/elf2tdg-rust-threads-o2 $(RUST_FIXTURE_SRC)
	$(CARGO) run -p elf2tdg -- /tmp/elf2tdg-rust-threads-o2 --format json \
		--output /tmp/elf2tdg-rust-threads-o2.json --verbose

$(FIXTURE_ELF):
	$(MAKE) -C $(FIXTURE_DIR)

$(SPAWN_FIXTURE_ELF):
	$(MAKE) -C $(SPAWN_FIXTURE_DIR)

clean:
	$(CARGO) clean
	$(MAKE) -C $(FIXTURE_DIR) clean
	$(MAKE) -C $(SPAWN_FIXTURE_DIR) clean
	$(MAKE) -C examples/rust-concurrency clean
	$(MAKE) -C examples/cortex-m0-isr clean
