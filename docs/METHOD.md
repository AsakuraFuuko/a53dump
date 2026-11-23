# How the A53 image is dumped

**Method: retarget an A53-side SDBGP command whose read window comes from A53's own
state, not from the host.**

The key point is that this needs **no new primitive** — no `WRITE_MEMORY`, no page
tables, no exploit of its own. It reuses what the system already exposes.

---

## 1. The command takes no address

SDBGP `0x01190201` (the msgbuf handler) builds its read window entirely from A53's own
debug-status struct, `mp4_debug_status_t`:

```c
base = (u8 *)ds + ds->mds_ttyp_buffer_offset;   /* +0x208 */
len  = ds->mds_ttyp_buffer_count                /* +0x220 */
     ? ds->mds_ttyp_buffer_size                 /*   +0x210 */
     : ds->mds_ttyp_buffer_last;                /*   +0x218 */
```

So the host never supplies an address — which is exactly why every earlier attempt via
`READ_MEMORY` (`mem_type 0x02/0x40/0x43`) failed. Those paths validate the address they
are handed. This one is handed nothing.

## 2. Three of those fields are host-writable

`ds` is A53 EL3 VA `0x88700000`; the same struct is host PA `0x60700000`, inside a 2 MiB
region the host can both read and write. Writing `+0x208` and `+0x218` turns the command
into an arbitrary EL3 VA read:

```
read_base = DS + offset      /* offset is u64; 2^64 wrap is the mechanism, not a bug */
read_len  = last
```

The wrap matters: `offset = va - DS` is negative for anything below `DS`, so it is stored
as its two's-complement and the addition lands exactly on `va`.

## 3. What it actually returns

One request, `len = 0x171140`, yields the full loaded image:

```
1,511,744 bytes = a53.elf
ELF64 / AArch64 / ET_EXEC, phnum=17, shnum=306
sha256 4f3411746d0fd3826c80eefeb4eed1ecea2e632eca377ac015c0d6a6d062f241
```

Byte-identical across runs. The 17 `PT_LOAD` entries match the EL3 boot log's segment
table field for field, and the disassembly opens with a real function prologue:

```
6400000: d10203ff  sub  sp, sp, #0x80
6400004: a9077bfd  stp  x29, x30, [sp, #112]
640002c: b9450408  ldr  w8, [x0, #1284]
```

## 4. The cost, and why it needs gates

The handler logs `0x8c` bytes **at** `landing = read_base + read_len`. That range gets
destroyed. So the landing point has to be chosen deliberately, and the dumper enforces
three gates before trusting anything:

| gate | check |
|---|---|
| 1 | `ds` holds magic `0xcbb3d18a1aa5daef` |
| 2 | `landing` falls in a declared harmless range |
| 3 | result is ELF (`7f454c46`, `e_machine 0xb7`, sane `e_phnum`/`e_phoff`) |

Unknown firmware never reaches the write path — the profile lookup fails and the process
exits with code 2 before touching A53.

### Where the landing may go

Gate 2 is only as good as its range list, and the range list is only as good as the
segment table behind it. Get the segments wrong and the gate happily approves a write
into a live page table.

The table comes from the console itself. EL3 prints it at boot via
`mp4_layout_seg_set_name` — 31 entries in the G6 window, each `VA + size = end
[PA + size] - name`. Deduplicated that is 22 segments, and the safe landings are the
gaps between them.

Reading a segment **end to end** puts the landing on its tail, which is the gap before
the next segment. That is the whole trick: the spill never enters the region being read,
so 22 whole-segment reads cover everything without damaging anything.

Two regions break naive reasoning about "empty space":

- `0x88000000` starts with the EL3 entry point and carries the L1/L2/L3 translation
  tables — live page tables, not padding.
- `0x88025000`–`0x88062000` is **one** segment holding EL1, both core stacks and both
  core page tables. Between them there are no gaps to land in.

Damaging either kills the coprocessor and takes the SMBus channel with it, so `ftpsrv`
and `elfldr` die as well and only a power cycle recovers the console. A reverse-order
sweep in large blocks did exactly this: its first landing had to sit above the whole
window (`0x88800000`), outside every mapped segment, and the write went off the end.

### One segment has no gap

`controller_dev_data` (`0x88410000`, `0x10000`) ends exactly at
`mm_controller_dram_text`'s first byte. `mode=forced` skips gate 2 for it, on the
caller's promise that the next segment was read first — then the spill lands on bytes
already saved. It is not an escape hatch for anything else.

## 5. On "is this generic?"

Only partially, and honestly so.

| | status |
|---|---|
| command id, MDSR field offsets, wire format, transport discovery | identical across 4.02 … 7.61 … 12.00 … 13.60 |
| EL3 VA of `ds`, EL3 VA of the image | **varies per build** |
| 12.00 | verified end to end on hardware |
| 13.60 | verified end to end on hardware (`0x2951C` validator does not reject image/elfmeta reads) |
| 7.61 | static analysis only |
| after 13.60 | **untested** |

## 6. Two things it is not

- **Not a write primitive.** `WRITE_MEMORY 0x01040031` is absent from the 12.00 command
  table entirely — the string appears zero times in the 1.5 MB image — and every
  handler's stores target the response buffer, the stack, or static tables.
- **Does not reach HV or PSP.** The read base is an A53 EL3 VA, not a host PA.
  `0x88100000` resolves only because A53's own G6 table maps TMR12's PA `0x60100000`.
  There is no HV or PSP mapping in that table.

---

## Credits

The transport layer derives from [`drakmor/ppr-patch`](https://github.com/drakmor/ppr-patch)
(GPL-3.0), and the `0x43` idea plus the image-base candidate list come from
[`astrelsky/mp4rw`](https://github.com/astrelsky/mp4rw). Neither drives
`mds_ttyp_buffer_offset` as an arbitrary VA base — that is the part not seen published
before.
