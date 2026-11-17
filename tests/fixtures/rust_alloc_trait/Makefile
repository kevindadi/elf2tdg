CARGO ?= cargo
CARGO_FLAGS ?=
TARGET := thumbv7em-none-eabi
ELF := firmware.elf
BIN := target/$(TARGET)/analysis/rust-alloc-trait

.PHONY: all clean

all: $(ELF)

$(BIN): main.rs Cargo.toml Cargo.lock memory.x .cargo/config.toml
	$(CARGO) build $(CARGO_FLAGS) --profile analysis --target $(TARGET)

$(ELF): $(BIN)
	cp $< $@

clean:
	rm -rf target $(ELF)
