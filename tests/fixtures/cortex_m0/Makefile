.PHONY: all clean

CC := arm-none-eabi-gcc
CFLAGS ?= -mcpu=cortex-m0 -mthumb -O1 -g -fno-inline -ffreestanding -nostdlib -Wall -Wextra

all: firmware.elf

firmware.elf: main.c linker.ld
	$(CC) $(CFLAGS) -T linker.ld -Wl,--emit-relocs -o $@ main.c

clean:
	rm -f firmware.elf
