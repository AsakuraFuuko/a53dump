# a53dump

**English** | [简体中文](README.zh-CN.md)

Dump the `a53.elf` image that runs on the PS5's A53 coprocessor, using a single
SDBGP command that the host can steer without supplying an address.

- **License:** GPL-3.0-or-later — required, not chosen. See [Credits](#credits).
- **Verified on:** firmware 12.00 only.
- **Live result:** all 22 segments of the A53 memory map, 3,862,709 bytes, every
  length exactly matching the console's own layout table. The `.elf` alone is
  1,511,744 bytes and parses with `readelf` (17 program headers).

---

## How it works

A self-contained write-up of the method, including what it is not, lives in
[`docs/METHOD.md`](docs/METHOD.md).


SDBGP command `0x01190201` does **not** accept a host-supplied address. Its
handler builds the read window from A53's own debug-status structure:

```c
base = (u8 *)ds + ds->mds_ttyp_buffer_offset;   /* +0x208 */
len  = ds->mds_ttyp_buffer_count                /* +0x220 */
     ? ds->mds_ttyp_buffer_size                 /*   +0x210 */
     : ds->mds_ttyp_buffer_last;                /*   +0x218 */
```

Three of those fields sit in a host-writable window, so writing them turns the
command into a read of **any** EL3 virtual address:

```
read_base = DS + offset      /* offset is u64; the 2^64 wrap is the mechanism */
read_len  = last
```

Everything else is version independent and was checked across the builds
examined (4.02 … 7.61 … 12.00): the command id, the MDSR field offsets, the
`deci5s_memory_arg` wire format, the response layout (`+0x60` text length,
`+0x68` payload), and the transport discovery chain
(`mp4sc + 0x18` → bushandle `+0x10` → `zcn_bar2`).

Per-build constants live in a *profile*: `DS`, `DS_PA`, `IMAGE`, `SIZE`, and the
landing ranges that are safe to overwrite. See `src/profile.c`.

---

## Safety model

The handler logs a byte range at `landing = read_base + read_len`, which
**destroys** that region. Three gates run before anything is trusted:

| Gate | Check | Runs before |
|---|---|---|
| 1 | `ds` magic == `0xcbb3d18a1aa5daef` | any write, including `base` |
| 2 | `landing` is inside a profile-declared harmless range | arming |
| 3 | read data is ELF (`7f454c46`, `e_machine == 0xb7`, sane `e_phnum`/`e_phoff`) | trusting the result |

An unknown firmware release never reaches the arming code:
`a53_profile_resolve()` returns `-1`, the process exits with code 2, and A53 is
left untouched. Every write is read back and verified before the SDBGP command
is sent.

The spill size is **not** a constant (measured `0x8c` and `0x46` on different
runs) because `last` is A53's own log cursor and it advances between arming and
the handler reading it. `one` therefore truncates the artefact to the declared
`SIZE`; `dump` advances by the measured length.

---

## Build

Requires the [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk) and a
kernel exploit that exposes `kernel_copyin`/`kernel_copyout`.

```bash
make                       # -> a53dump.elf
make SDK=/path/to/sdk
```

## Deploy and run

```bash
PS5=<console-ip>

curl -sS -T a53dump.elf \
  "ftp://$PS5:2121/data/pldmgr/payloads/a53dump/a53dump.elf"

run() {
    printf '%s\n' "$1" > /tmp/m
    curl -sS -T /tmp/m "ftp://$PS5:2121/data/a53dump.mode"
    curl -sS --ftp-create-dirs -T /dev/null "ftp://$PS5:2121/data/a53dump.log"
    curl -s -X POST -H "Origin: http://$PS5:8084" -H 'X-PLDMGR-Request: 1' \
      "http://$PS5:8084/loadpayload:/data/pldmgr/payloads/a53dump/a53dump.elf"
    sleep 10
    curl -s "ftp://$PS5:2121/data/a53dump.log"
}

run base     # zero writes; must print GATE1 OK
run one      # full image
curl -s "ftp://$PS5:2121/data/a53dump.bin" -o a53_image.bin
run restore  # must print VERDICT: RESTORED
```

The payload reads its mode file once at startup, so a mode change needs a fresh
`loadpayload`.

### Dumping every segment

`one` reads whatever `[va, va+len)` you hand it, so a full dump is one call per
segment. The list is the 22 rows of the layout table; each read is complete on
its own — no chunked driver, no state file.

```bash
one() {   # va len
    printf '%s\n' "$1" > /tmp/v; printf '%s\n' "$2" > /tmp/l
    curl -sS -T /tmp/v "ftp://$PS5:2121/data/a53dump.va"
    curl -sS -T /tmp/l "ftp://$PS5:2121/data/a53dump.len"
    run one
    curl -s "ftp://$PS5:2121/data/a53dump.bin" -o "seg_$1.bin"
}

one 0x88000000 0x1eba0    # EL3 entry + L1/L2/L3 tables
one 0x8801f000 0x2218
one 0x88022000 0x159d
one 0x88024000 0xd00
one 0x88025000 0x3d000    # EL1 + both stacks + both page tables
one 0x88100000 0x17e098   # a53.elf, through the section header table
one 0x88400000 0x1140
one 0x88420000 0x18f10
one 0x88440000 0x46980
one 0x88490000 0x227ec
one 0x884c0000 0x2a0
one 0x884d0000 0x4a8
one 0x884e0000 0xd0
one 0x88580000 0x14c40
one 0x88595000 0x12f58
one 0x885a8000 0xc1e4
one 0x885b5000 0x350e8
one 0x88700000 0x70000    # direct map, no write
one 0x88780000 0x70000    # direct map, no write
one 0x887f0000 0x1450     # direct map, no write
one 0x887ffc00 0x298      # direct map, no write

# controller_dev_data has no gap after it: read its neighbour first, then force
one 0x88420000 0x18f10
printf 'forced\n' > /tmp/m
curl -sS -T /tmp/m "ftp://$PS5:2121/data/a53dump.mode"
one 0x88410000 0x10000
```

Verify: every file's size must equal the `len` you asked for, and
`readelf -l seg_0x88100000.bin` must show 17 program headers.

## Modes

| Mode | Writes A53 | Purpose |
|---|---|---|
| `version` | no | read the release string from the console (`GET_CONF`) |
| `scan` | **no** | scan the host MDSR window for the magic, report `ds_pa` candidates |
| `base` | **no** | resolve profile, run gate 1, print the MDSR fields |
| `probe` | **no** | send `0x01190201` once and compare the text length against the ring cursor |
| `one` | depends | read `[va, va+len)`; direct map when it answers, else arm + read |
| `forced` | yes | read a segment whose tail butts the next one (see below) |
| `elfmeta` | yes | read `.shstrtab` and the section header table (outside the image) |
| `dump` | depends | chunked driver; same path selection as `one` per chunk |
| `paddr` | **no** | read through the direct map only, never arm or send a command |
| `wrap` | yes | exercise the `count != 0` branch of `0x01190201` |
| `restore` | yes | restore the saved MDSR fields |

### The segment table

Everything hinges on the console's own layout dump, not on guesswork. EL3 prints
it during boot (`mp4_layout_seg_set_name`): 31 entries inside the G6 window, each
`VA + size = end [PA + size] - name`. That is the list in `src/profile.c`, and
`docs/METHOD.md` §4 covers the gates and why the landing must be a gap.

Two facts in that table are easy to miss and both are load-bearing:

- `0x88000000` begins with the EL3 entry point and holds the L1/L2/L3
  translation tables. The first bytes are live page tables even though they
  read like padding.
- `0x88025000`-`0x88062000` is a **single** region holding EL1, both core stacks
  and both core page tables. It is not several small regions with gaps between
  them.

Writing anywhere in either kills the coprocessor and takes the SMBus channel with
it, so `ftp`/`elfldr` die too and a power cycle is the only way back.

### Two read paths

`0x01190201` requires arming `ds->offset`/`last`, which drags the A53 log cursor
onto the landing point: the landing is always `va + len`, and that is exactly
where A53 writes its log line. Both the `count == 0` and `count != 0` branches
compute it the same way, so neither avoids the write -- `count` only selects the
length source (`+0x218` vs `+0x210`).

What is controllable is *where* the landing falls. Read a segment end-to-end and
the landing sits on its tail, in the gap before the next segment, so the spill
never enters the segment being read. That is the basis of the whole method: 22
segments, each read whole, every landing inside a gap.

Above `A53_DIRECT_LO` (`0x885F0000`) the same memory is reachable with
`kernel_copyout` over the direct map. That path sends no command and writes
nothing at all, so the cursor does not move (measured: +0x0, against +0x8C per
10 s of idle drift). `one` and `dump` use it whenever `copyout` succeeds and fall
back otherwise. The mapped extent is not contiguous -- `0x88600000` answers while
`0x885EB000` does not -- so the copyout result is the test, not a range check.

### `forced`

One segment has no gap after it: `controller_dev_data` (`0x88410000`, 0x10000)
ends exactly at `mm_controller_dram_text`'s first byte, so gate 2 refuses it by
policy. `forced` skips gate 2 and trusts the caller to have read the *next*
segment first -- then the spill lands on bytes already saved. The window itself
is copied out before A53 logs, so the data returned is clean either way.

Do not reach for `forced` as a general escape hatch. It disables the only check
standing between a read and a live structure.

> `dump` is **not** usable for the whole image on 12.00: a chunk's landing point
> necessarily falls inside the region still to be read, so gate 2 refuses it.
> Use `one` per segment below the direct-map floor.

### What not to do

Reverse-order sweeping of large blocks was tried and removed. The reasoning looks
sound -- land on data already copied out -- but the "already copied out" region
still belongs to segments the firmware is executing, and the first landing has to
sit above the whole window, which is outside every mapped segment. On hardware it
wrote past `0x88800000`, killed A53, and took `ftpsrv` and `elfldr` down with it.

Small reverse chunks fail for a different reason: the landing lands inside the
segment being read. Only gaps are safe landings, and gaps come from reading whole
segments in the forward direction.

## Adding a firmware release

`src/profile.c` holds the built-in table. To add a build, see
[`docs/ADDING_A_RELEASE.md`](docs/ADDING_A_RELEASE.md). In short:

1. `run scan` — locate `DS_PA` with zero writes.
2. Derive `DS` from the EL3 segment table (`MM_MDSR`); gate 2 validates it.
3. Locate `IMAGE`/`SIZE` from the boot log (unambiguous) or the `mp4rw`
   candidate list.
4. Write `/data/a53dump.profile`, then run `base` → `probe` → `one`.
5. Add a row to `g_builtin`.

### 13.60

A profile row exists, built from a live 13.60 capture
(`artifacts/external/2026-11-15_kernelkatio_1360/mm_mdsr.txt`, the console's own
`mp4_layout_seg_set_name` output). It is **not** "12.00 with one segment longer":
seven of the 31 G6 entries move, and the comments above the `R13_*` defines list
them. Reusing 12.00's gaps there does not corrupt memory — gate 2 catches it —
but three fixed-code segments become unreachable because their landings no longer
fall in a gap.

What is **not** confirmed for 13.60:

| Item | Status |
|---|---|
| `DS`, `DS_PA`, `IMAGE`, every gap | from the boot log |
| `SIZE` | **unconfirmed** — the table still says `0x171140`, which on 12.00 stops short of `.shstrtab` |
| `A53_DIRECT_LO` (`0x885F0000`) | 12.00 measurement; may differ |
| address-window validator `0x2951C` | 13.60 adds it; 12.00 has none. It may reject reads that cross windows |
| `kernel_data` base | 13.60 is `text+0x0CC0000` where 12.00 is `text+0x0D50000`; both are tried |

So `one` on 13.60 should be checked before a full read is trusted: dump the image,
then read `e_shoff`/`e_shnum`/`e_shentsize` out of the result and confirm the file
you asked for actually covers the section header table. The payload refuses rather
than guesses when a profile is missing, but a profile present with a stale `SIZE`
is only caught that way.

## Files

| Path | Content |
|---|---|
| `/data/a53dump.bin` | `one`: whole image, truncated to `SIZE`; `dump`: appended |
| `/data/a53dump.shstrtab.bin` | `elfmeta`: section name string table |
| `/data/a53dump.shdrs.bin` | `elfmeta`: section header table |
| `/data/a53dump.log` | appended per run |
| `/data/a53dump.save` | MDSR fields as they were before arming |
| `/data/a53dump.state` | `dump` cursor |
| `/data/a53dump.profile` | optional per-build override |

`one` yields the loaded image. To rebuild a `readelf`-able ELF, run `elfmeta`
afterwards and splice the two artefacts in:

> **Read the whole ELF in one call when you can.** `.shstrtab` starts at file
> offset `0x171140`, which is exactly one byte past the end of the segment the
> layout table calls `ELF image (a53.elf)` — so asking for `0x171140` bytes lands
> the spill precisely on the string table's first `0x8c` bytes. Asking for
> `0x17E098` bytes instead (the real extent, through the section header table)
> moves the landing to `0x8827E098`, in the gap, and the ELF comes back intact
> and self-contained. Verified: the raw memory dump patched at that one 70-byte
> span is byte-identical to the assembled file below.

```python
import struct
img = open('a53dump.bin', 'rb').read()
sh  = open('a53dump.shstrtab.bin', 'rb').read()
hd  = bytearray(open('a53dump.shdrs.bin', 'rb').read())

SHSTR_OFF = 0x171140          # .shstrtab file offset, from shdr[shstrndx]
SHOFF     = struct.unpack_from('<Q', img, 0x28)[0]

hd[0:64] = b'\0' * 64        # sec[0] is SHT_NULL by definition
struct.pack_into('<I', hd, 64, 0)  # sec[1].sh_name: head of shstrtab is lost

out = bytearray(b'\0' * (SHOFF + len(hd)))
out[0:len(img)] = img
out[SHSTR_OFF:SHSTR_OFF + len(sh)] = sh
out[SHOFF:SHOFF + len(hd)] = hd
open('a53_complete.elf', 'wb').write(bytes(out))
```

The first `0x8c` bytes of `.shstrtab` are permanent collateral and are zeroed
by `elfmeta`; the affected `sh_name` entries are reported by its self-check.
`readelf -h` reports no warnings either way.

---

## Credits

GPL-3.0-or-later is **mandatory** here: `src/a53_transport.c` is a modified
derivative of [`drakmor/ppr-patch`](https://github.com/drakmor/ppr-patch)'s
`a53_transport.c`, which is GPL-3.0. Publishing this work under MIT would be a
license violation, so the whole work is GPL-3.0-or-later.

- **drakmor/ppr-patch** — the transport layer (`src/a53_transport.c`). The PPR
  patch entry points were removed; only the SDBGP packet path remains.
- **astrelsky/mp4rw** — SDBGP command naming, the `0x43` read idea, and the
  `0x88100000 / 0x88440000 / 0x8A000000` image-base candidate list.

The channel used here was not taken from either project: neither drives
`mds_ttyp_buffer_offset` as an arbitrary EL3 VA base.

## Legal

Research and interoperability work on hardware you own. This repository contains
no Sony code, keys, or firmware blobs. Firmware layouts were derived by reading
structures the device exposes to the host. Distributing dumps produced with this
tool may be restricted by law in your jurisdiction; the authors ship no dump
data.

You are responsible for how you use this and for complying with applicable law
and any agreements that bind your console.
