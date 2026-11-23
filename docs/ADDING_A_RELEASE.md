# Adding a firmware release

**English** | [简体中文](ADDING_A_RELEASE.zh-CN.md)

The dumper needs exactly two per-build values beyond what it discovers itself:

| Value | Meaning |
|---|---|
| `DS` | A53-side EL3 VA of `mp4_debug_status_t` — the base `offset` is added to |
| `IMAGE` / `SIZE` | EL3 VA of the loaded `a53.elf`, and its byte length |

Everything else — command id, MDSR field offsets, wire format, response layout,
transport discovery — is shared across every build examined (4.02 … 7.61 … 12.00)
and needs no per-release work.

**Steps 1–3 do not write to A53. Only step 4 does.**

---

## 1. Locate `DS_PA` with `scan` (zero writes)

MDSR instances live in the host-readable window just past TMR12. The scanner
walks it page by page looking for the magic:

```bash
run scan
```

Measured on 12.00:

```
scan window [0x60600000, 0x60800000) for magic1=0xcbb3d18a1aa5daef
HIT ds_pa=0x60700000 off=0x1000 size=0x60000 last=0x9808 count=0
  -> usable core0 candidate
HIT ds_pa=0x60780000 off=0x1000 size=0x60000 last=0x72e3 count=0
  -> usable core1 candidate
VERDICT: SCAN_OK found=2
```

A hit is accepted only when all of these hold, which filters out false positives
from unrelated data:

```
page[0..8)      == 0xcbb3d18a1aa5daef
+0x208 (offset) <= 0x10000
+0x210 (size)   in (0, 0x1000000]
+0x220 (count)  == 0            /* ring not wrapped */
```

`core0` is the one the dumper uses; `core1` is the IO side.

If `SCAN_EMPTY`, the window moved. Adjust `SCAN_LO`/`SCAN_HI` at the top of
`src/main.c`, or first confirm the window with a read-only page scanner.

## 2. Derive `DS`

`DS` is the base for `offset`, and it must come from the **A53 segment table**,
not from a guess.

On 12.00 the relation is `DS = DS_PA + 0x28000000` (`0x60700000` →
`0x88700000`). That delta is the G6-to-host-PA mapping; **it is not verified to
be stable across releases**, so confirm it one of two ways:

| Path | How |
|---|---|
| A — segment table available | read the `MM_MDSR` line out of the EL3 boot log (12.00: `0x88700000`, mli 19) |
| B — no log | start from `DS = DS_PA + 0x28000000` and let the gates check it |

Path B is safe because of how the gates are ordered: gate 1 reads `ds_pa`, so a
wrong `DS_PA` is caught immediately; gate 2 computes the landing point from
`DS`, and a wrong `DS` puts it outside every declared range, so it is refused
**before** arming. Neither failure mode can corrupt A53.

## 3. Locate `IMAGE` and `SIZE`

`SIZE` must be exact; `one` truncates the artefact with it.

| Release | `SIZE` |
|---|---|
| 4.02 / 4.03 | `0x1116B8` |
| 4.50 | `0x111100` |
| 5.10 … 7.61 | `0x1212F8` |
| 12.00 | `0x171140` |
| 13.60 | `0x171140` |

For `IMAGE`, prefer these sources in order:

1. **EL3 boot log** — states it outright (12.00: `a53.elf @ host PA 0x60100000 /
   G6 0x88100000`). This is the only unambiguous source; use it when you can.
2. **mp4rw candidate list** — `0x88100000`, `0x88440000`, `0x8A000000`.
3. **Segment-table offset** — the image usually sits near
   `DS + 0x28000000 - 0x6000000` (12.00: `0x88700000 - 0x6000000 = 0x88100000`).

There is deliberately **no** automatic ELF-magic scanner for `IMAGE`. Locating it
requires the read primitive, and the read primitive requires a profile — a
bootstrap loop. Use the boot log.

## 4. Write a profile and validate it

```bash
cat > /tmp/a53dump.profile <<EOF
DS=0x88700000
DS_PA=0x60700000
IMAGE=0x88100000
SIZE=0x171140
RANGE0=0x88271140 0x88400000
RANGE1=0x885EA0E8 0x88700000
RANGE2=0x88701000 0x88770000
RANGE3=0x88781000 0x887e0000
EOF
curl -sS -T /tmp/a53dump.profile "ftp://$PS5:2121/data/a53dump.profile"
```

`RANGE*` must contain the landing point `IMAGE + SIZE` for a whole-image read.
Prefer the hole between the segment table's `pmax` and `LIMIT` — A53 does not use
it. Otherwise fall back to a log ring (`DS + 0x1000`, `0x60000` bytes).

Now walk the gates in order:

```bash
run base     # must print GATE1 OK
run probe    # must print PROBE_OK
run one      # must print GATE2 OK, GATE3 OK, READ_OK
```

Check the artefact:

```bash
curl -s "ftp://$PS5:2121/data/a53dump.bin" -o new.bin
xxd -l 64 new.bin          # 7f 45 4c 46 ...
sha256sum new.bin          # record it as this release's baseline
```

## 5. Add a row to the built-in table

In `src/profile.c`:

```c
#define R13_0 { 0x88XXXXXXULL, 0x88YYYYYYULL }   /* landing range from step 4 */

...
    { "13.60", 0x88700000ULL, 0x60700000ULL, 0x88100000ULL, 0x1A0000ULL,
      0x885EA0E8ULL, 0x88700000ULL, 1, { R13_0 } },
```

**Do not add the row before `one` succeeds.** A wrong `DS` is caught by gate 1,
but a right `DS` with a wrong `RANGE` would let `one` read memory it should not.

---

## Known risks past 13.60

| Risk | Evidence | Impact |
|---|---|---|
| Address-window validator | 13.60 adds `0x2951C`; 12.00 has no such function. It checks an address against a descriptor table of windows. | **none on 13.60** (`one` and `elfmeta` succeeded); may still affect future releases |
| Handler relocation | `0x01190201` handler: `0x1123E4` (4.02) → `0x111C60` (5.10) → `0x111AE0` (7.61) → `0x111764` (12.00) | **none** — the dumper never calls a handler by address |
| Command table location | `0x1221D8` (4.02) → `0x11F1D8` (7.61) → `0x11F1E0` (12.00) | **none** — the dumper does not read the table |

The dumper depends only on `DS`, `IMAGE` and `SIZE`. Everything else is either
discovered at runtime or version independent, which is why adding a release costs
just the five steps above.
