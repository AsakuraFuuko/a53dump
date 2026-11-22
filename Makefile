# a53dump — build with the PS5 payload SDK.
#
#   make                     build a53dump.elf
#   make SDK=/path/to/sdk    use a different SDK root
#   make clean

PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

CC      := $(PS5_PAYLOAD_SDK)/bin/prospero-clang
STRIP   := $(PS5_PAYLOAD_SDK)/bin/prospero-strip

CFLAGS  := -Os -Wall -Wextra -Wno-unused-parameter -Wno-unused-function \
           -ffunction-sections -fdata-sections -Isrc
LDFLAGS := -Wl,--gc-sections

ELF := a53dump.elf
SRC := src/main.c src/profile.c src/a53_transport.c

all: $(ELF)

$(ELF): $(SRC) src/profile.h src/a53_transport.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC)
	$(STRIP) --strip-all $@

clean:
	rm -f $(ELF)

.PHONY: all clean
