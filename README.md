# a53dump

**English** | [简体中文](README.zh-CN.md)

Dump the `a53.elf` image that runs on the PS5's A53 coprocessor, using a single
SDBGP command that the host can steer without supplying an address.

- **License:** GPL-3.0-or-later — required, not chosen. See [Credits](#credits).
- **Verified on:** firmware 12.00 only.
- **Live result:** 1,511,744 bytes, byte-identical across runs
  (`sha256 4f3411746d0fd3826c80eefeb4eed1ecea2e632eca377ac015c0d6a6d062f241`).

---

## How it works

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

## Modes

| Mode | Writes A53 | Purpose |
|---|---|---|
| `version` | no | read the release string from the console (`GET_CONF`) |
| `scan` | **no** | scan the host MDSR window for the magic, report `ds_pa` candidates |
| `base` | **no** | resolve profile, run gate 1, print the MDSR fields |
| `probe` | **no** | send `0x01190201` once and compare the text length against the ring cursor |
| `one` | yes | arm, read the whole image, restore, truncate to `SIZE` |
| `dump` | yes | chunked driver; only usable when `landing` falls *outside* the region read |
| `restore` | yes | restore the saved MDSR fields |

> `dump` is **not** usable for the whole image on 12.00: a chunk's landing point
> necessarily falls inside the region still to be read, so gate 2 refuses it.
> Use `one`.

## Adding a firmware release

`src/profile.c` holds the built-in table. To add a build, see
[`docs/ADDING_A_RELEASE.md`](docs/ADDING_A_RELEASE.md). In short:

1. `run scan` — locate `DS_PA` with zero writes.
2. Derive `DS` from the EL3 segment table (`MM_MDSR`); gate 2 validates it.
3. Locate `IMAGE`/`SIZE` from the boot log (unambiguous) or the `mp4rw`
   candidate list.
4. Write `/data/a53dump.profile`, then run `base` → `probe` → `one`.
5. Add a row to `g_builtin`.

No release after 12.00 has been tested. The handler referenced by `0x01190201`
lives at an EL3 VA that is not inside any dump we hold, so it cannot be
confirmed statically; 13.60 additionally adds an address-window validator
(`0x2951C`) that 12.00 does not have. The payload refuses rather than guesses.

## Files

| Path | Content |
|---|---|
| `/data/a53dump.bin` | `one`: whole image, truncated to `SIZE`; `dump`: appended |
| `/data/a53dump.log` | appended per run |
| `/data/a53dump.save` | MDSR fields as they were before arming |
| `/data/a53dump.state` | `dump` cursor |
| `/data/a53dump.profile` | optional per-build override |

The dump is the loaded image only. Rebuilding a `readelf`-able ELF additionally
needs the section header table and `.shstrtab`, both of which live outside the
image.

---

## Credits

GPL-3.0-or-later is **mandatory** here: `src/a53_transport.c` is a modified
derivative of [`drakmor/ppr-patch`](https://github.com/drakmor/ppr-patch)'s
`a53_transport.c`, which is GPL-3.0. Publishing this work under MIT would be a
license violation, so the whole work is GPL-3.0-or-later.

- **drakmor/ppr-patch** — transport layer, `ppr_patch.h`, PPR profile layouts.
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
