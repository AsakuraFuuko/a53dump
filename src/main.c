/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 a53dump contributors
 *
 * This program links against a53_transport.c, which is derived from
 * drakmor/ppr-patch (GPL-3.0). The whole work is therefore distributed
 * under the GNU General Public License v3 or later. See LICENSE.
 *
 * a53dump -- dump the loaded a53.elf image out of the A53 coprocessor.
 *
 * Channel
 * -------
 * SDBGP command 0x01190201 does not take a host-supplied address. Its handler
 * builds the read window from A53's own mp4_debug_status_t:
 *
 *     base = (u8 *)ds + ds->mds_ttyp_buffer_offset    (+0x208)
 *     len  = ds->mds_ttyp_buffer_count                (+0x220)
 *          ? ds->mds_ttyp_buffer_size                 (+0x210)
 *          : ds->mds_ttyp_buffer_last                 (+0x218)
 *
 * Three of those fields live in the host-writable window [0x605F0000,
 * 0x60800000), so arming them turns the command into a read of any EL3 VA:
 *
 *     read_base = DS + offset        (offset is u64, 2^64 wrap is intended)
 *     read_len  = last
 *
 * Versions
 * --------
 * DS / IMAGE / SIZE differ per build; see profile.c. Everything else --
 * command id, MDSR field offsets, wire format, response layout, transport
 * discovery -- is shared across every build examined (4.02 .. 7.61 .. 12.00).
 *
 * Modes
 * -----
 *   base    read-only: identify release, resolve profile, print MDSR fields.
 *           Zero writes. This is the safe first command on an unknown build.
 *   probe   read-only: send 0x01190201 once and compare text_len against the
 *           MDSR ring cursor. Confirms the handler folds +0x218 on this
 *           build without arming anything.
 *   one     arm + read + restore in a single run. Default dump primitive;
 *           writes at most one image-sized window.
 *   elfmeta read the ELF metadata that lives outside the loaded image:
 *           .shstrtab and the section header table. Needs the image on disk
 *           (OUT_PATH) to learn e_shoff/e_shnum/e_shstrndx, then writes
 *           META_SHSTR and META_SHDRS, which splice into the image directly.
 *   scan    read-only: scan the host-visible MDSR window for the magic and
 *           report usable ds_pa candidates. Zero writes; use it to add a build.
 *   dump    multi-run driver: arm, read one chunk, restore, record the cursor
 *           in /data/a53dump.state. Only usable when the landing point falls
 *           outside the region being read -- generally NOT the whole image.
 *   restore restore DS fields from /data/a53dump.save.
 *
 * Safety
 * ------
 * The handler writes 0x8c bytes of log at `landing` (read_base + read_len).
 * A dump therefore corrupts [landing, landing + 0x8c), so every landing is
 * gated against the profile's harmless ranges and the arming step refuses to
 * run when the gate fails. Unknown releases never reach the arming code.
 */
#include <ps5/kernel.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

#include "a53_transport.h"
#include "profile.h"

#define LOG_PATH   "/data/a53dump.log"
#define MODE_PATH  "/data/a53dump.mode"
#define SAVE_PATH  "/data/a53dump.save"
#define STATE_PATH "/data/a53dump.state"
#define OUT_PATH   "/data/a53dump.bin"
#define VA_PATH    "/data/a53dump.va"
#define LEN_PATH   "/data/a53dump.len"
#define META_SHSTR "/data/a53dump.shstrtab.bin"
#define META_SHDRS "/data/a53dump.shdrs.bin"

#define CMD_MSGBUF  0x01190201U
#define CMD_GET_CONF 0x01010010U

/* MDSR field offsets. Verified identical on every build examined. */
#define F_OFF   0x208ULL
#define F_SIZE  0x210ULL
#define F_LAST  0x218ULL
#define F_CNT   0x220ULL

#define MDSR_MAGIC 0xcbb3d18a1aa5daefULL

/* A53 log byte budget per read; measured constant, not a tuning knob. */
#define LANDING_SPILL 0x8cULL

/* Read cap. The handler is armed with F_LAST = len <= this; the response
 * buffer must hold 0x68 header + len + spill. */
/* Upper bound for one request. The A53 side accepts a larger window than the
 * original 0x1F0000 guess: the only hard limits are the response buffer and
 * the landing range. Raised so that regions far below the whitelist can be
 * read in one go, with the landing point kept on a range already proven safe
 * (0x88271140) instead of inventing a new one. */
#define READ_MAX 0x280000U
static uint8_t g_raw[0x290000];

static FILE *g_log;

static void lg(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (g_log) vfprintf(g_log, fmt, ap);
    va_end(ap);
    if (g_log) { fputc('\n', g_log); fflush(g_log); }
    va_list aq;
    va_start(aq, fmt);
    vprintf(fmt, aq);
    va_end(aq);
    putchar('\n');
    fflush(stdout);
}

static uint64_t kread64(uint64_t a) {
    uint64_t v = 0;
    if (kernel_copyout((intptr_t)a, &v, 8) != 0) return ~0ULL;
    return v;
}

static uint32_t rd32(const uint8_t *p, size_t off) {
    return (uint32_t)p[off] | ((uint32_t)p[off + 1] << 8) |
           ((uint32_t)p[off + 2] << 16) | ((uint32_t)p[off + 3] << 24);
}

/* Direct-map offset for the host side of the A53 DRAM window. */
static uint64_t dmap_from_kdata(void) {
    uint64_t data = (uint64_t)(uintptr_t)KERNEL_ADDRESS_DATA_BASE;
    uint64_t text = (uint64_t)(uintptr_t)KERNEL_ADDRESS_TEXT_BASE;
    if (!data || data <= text) data = text + 0x0D50000ULL;
    uint64_t hi = kread64(data + 0x2e1cfb8ULL + 0x20);
    uint64_t lo = kread64(data + 0x2e1cfb8ULL + 0x28);
    if (hi == ~0ULL || lo == ~0ULL) return 0;
    return hi - lo;
}

/* ------------------------------------------------------------------ gates */

/* Gate 1: the MDSR structure must be where the profile says it is.
 * Read-only; runs before any arming so an unknown build cannot be touched. */
static int gate_mdsr(uint64_t dmap, const struct a53_profile *p) {
    uint64_t base = dmap + p->ds_pa;
    unsigned char m[8] = {0};
    if (kernel_copyout((intptr_t)base, m, 8) != 0) {
        lg("GATE1 FAIL: cannot read ds=%#llx", (unsigned long long)p->ds);
        return -1;
    }
    uint64_t magic = 0;
    memcpy(&magic, m, 8);
    if (magic != MDSR_MAGIC) {
        lg("GATE1 FAIL: ds magic=%#llx expected %#llx",
           (unsigned long long)magic, (unsigned long long)MDSR_MAGIC);
        return -1;
    }
    lg("GATE1 OK: ds=%#llx magic=%#llx",
       (unsigned long long)p->ds, (unsigned long long)magic);
    return 0;
}

static void mdsr_fields(uint64_t dmap, const struct a53_profile *p,
                         uint64_t *off, uint64_t *size, uint64_t *last,
                         uint64_t *cnt) {
    uint64_t base = dmap + p->ds_pa;
    if (off)  *off  = kread64(base + F_OFF);
    if (size) *size = kread64(base + F_SIZE);
    if (last) *last = kread64(base + F_LAST);
    if (cnt)  *cnt  = kread64(base + F_CNT);
}

static void print_mdsr(uint64_t dmap, const struct a53_profile *p,
                        const char *tag) {
    uint64_t off = 0, size = 0, last = 0, cnt = 0;
    mdsr_fields(dmap, p, &off, &size, &last, &cnt);
    lg("%s: off=%#llx size=%#llx last=%#llx count=%llu (last==size? %s)",
       tag, (unsigned long long)off, (unsigned long long)size,
       (unsigned long long)last, (unsigned long long)cnt,
       last == size ? "YES" : "no");
}

/* Gate 2 (structural): the landing point must be inside a declared harmless
 * range. Cheap, and runs before every arming. */
static int gate_landing(const struct a53_profile *p, uint64_t va, uint64_t len) {
    uint64_t landing = va + len;
    if (!a53_profile_landing_ok(p, landing)) {
        lg("GATE2 FAIL: landing=%#llx (va=%#llx len=%#llx) not in a safe range",
           (unsigned long long)landing, (unsigned long long)va,
           (unsigned long long)len);
        return -1;
    }
    lg("GATE2 OK: landing=%#llx spills [%#llx, %#llx)",
       (unsigned long long)landing, (unsigned long long)landing,
       (unsigned long long)(landing + LANDING_SPILL));
    return 0;
}

/* Gate 3 (content): the bytes we just read must actually be the image. Only
 * a whole-image read can check the ELF header, so this runs after arming. */
static int gate_elf(const uint8_t *buf, size_t len, int strict) {
    if (len < 4) {
        lg("GATE3 FAIL: short read (%zu)", len);
        return -1;
    }
    if (!(buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F')) {
        lg("GATE3 FAIL: no ELF magic (got %02x %02x %02x %02x)",
           buf[0], buf[1], buf[2], buf[3]);
        return -1;
    }
    if (!strict) {
        lg("GATE3 OK: ELF magic");
        return 0;
    }
    if (len < 0x40) {
        lg("GATE3 FAIL: truncated header (%zu)", len);
        return -1;
    }
    uint16_t machine = (uint16_t)buf[0x12] | ((uint16_t)buf[0x13] << 8);
    uint16_t phnum   = (uint16_t)buf[0x38] | ((uint16_t)buf[0x39] << 8);
    uint64_t phoff   = 0;
    for (int i = 0; i < 8; i++) phoff |= (uint64_t)buf[0x20 + i] << (8 * i);
    if (machine != 0xb7) {
        lg("GATE3 FAIL: e_machine=%#x, expected 0xb7 (AArch64)", machine);
        return -1;
    }
    if (phnum == 0 || phnum > 64) {
        lg("GATE3 FAIL: e_phnum=%u implausible", phnum);
        return -1;
    }
    if (phoff < 0x40 || phoff >= len) {
        lg("GATE3 FAIL: e_phoff=%#llx outside image", (unsigned long long)phoff);
        return -1;
    }
    lg("GATE3 OK: ELF64 AArch64 phnum=%u phoff=%#llx",
       phnum, (unsigned long long)phoff);
    return 0;
}

static int transport_up(void) {
    struct a53_transport_options opts;
    memset(&opts, 0, sizeof(opts));
    if (a53_transport_initialize(&opts) != 0) {
        lg("FATAL: transport init failed (kstuff loaded?)");
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------- io */

static uint64_t read_hex_file(const char *path, uint64_t dflt) {
    FILE *f = fopen(path, "r");
    if (!f) return dflt;
    unsigned long long v = 0;
    int got = fscanf(f, "%llx", &v);
    fclose(f);
    return got == 1 ? (uint64_t)v : dflt;
}

static void write_hex_file(const char *path, uint64_t v) {
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "%llx\n", (unsigned long long)v);
    fclose(f);
}

static int save_fields(uint64_t off, uint64_t size, uint64_t last) {
    FILE *f = fopen(SAVE_PATH, "w");
    if (!f) { lg("FATAL: cannot write %s", SAVE_PATH); return -1; }
    fprintf(f, "%llx %llx %llx\n", (unsigned long long)off,
            (unsigned long long)size, (unsigned long long)last);
    fclose(f);
    return 0;
}

static int load_fields(uint64_t *off, uint64_t *size, uint64_t *last) {
    FILE *f = fopen(SAVE_PATH, "r");
    if (!f) { lg("FATAL: no %s", SAVE_PATH); return -1; }
    unsigned long long o = 0, s = 0, l = 0;
    int n = fscanf(f, "%llx %llx %llx", &o, &s, &l);
    fclose(f);
    if (n != 3) { lg("FATAL: bad %s", SAVE_PATH); return -1; }
    *off = o; *size = s; *last = l;
    return 0;
}

static void restore_baseline(uint64_t dmap, const struct a53_profile *p) {
    uint64_t base = dmap + p->ds_pa;
    uint64_t off = 0x1000ULL, size = 0x60000ULL, last = 0ULL;
    (void)kernel_copyin(&off,  (intptr_t)(base + F_OFF),  8);
    (void)kernel_copyin(&size, (intptr_t)(base + F_SIZE), 8);
    (void)kernel_copyin(&last, (intptr_t)(base + F_LAST), 8);
    uint64_t o = 0, s = 0, l = 0, c = 0;
    mdsr_fields(dmap, p, &o, &s, &l, &c);
    lg("RESTORE_BASELINE off=%#llx size=%#llx last=%#llx count=%llu",
       (unsigned long long)o, (unsigned long long)s, (unsigned long long)l,
       (unsigned long long)c);
}

/* Arm DS fields for one read of [va, va+len). Writes are verified by readback
 * before the SDBGP command is sent. */
static int arm(uint64_t dmap, const struct a53_profile *p,
               uint64_t va, uint64_t len) {
    uint64_t base = dmap + p->ds_pa;
    uint64_t cnt = kread64(base + F_CNT);
    if (cnt != 0) {
        lg("ABORT: mds_ttyp_buffer_count=%llu; the wrapped branch reads +0x210 "
           "instead of +0x218 and would need a different arm shape",
           (unsigned long long)cnt);
        return -1;
    }

    uint64_t cur_off = 0, cur_size = 0, cur_last = 0;
    mdsr_fields(dmap, p, &cur_off, &cur_size, &cur_last, NULL);
    if (save_fields(cur_off, cur_size, cur_last) != 0) return -1;
    lg("saved off=%#llx size=%#llx last=%#llx",
       (unsigned long long)cur_off, (unsigned long long)cur_size,
       (unsigned long long)cur_last);

    /* offset is (va - DS) in two's complement: the wrap is the mechanism. */
    uint64_t off = va - p->ds;
    /* size is pushed far away so the ring never appears wrapped and the
     * handler only ever takes the +0x218 branch. */
    uint64_t big = 0x10000000ULL;

    int r1 = kernel_copyin(&off,  (intptr_t)(base + F_OFF),  8);
    int r2 = kernel_copyin(&big,  (intptr_t)(base + F_SIZE), 8);
    int r3 = kernel_copyin(&len,  (intptr_t)(base + F_LAST), 8);
    if (r1 || r2 || r3) {
        lg("FATAL: arm copyin failed (%d/%d/%d)", r1, r2, r3);
        return -1;
    }
    uint64_t rb1 = 0, rb2 = 0, rb3 = 0;
    mdsr_fields(dmap, p, &rb1, &rb2, &rb3, NULL);
    if (rb1 != off || rb2 != big || rb3 != len) {
        lg("FATAL: arm readback mismatch off=%#llx/%#llx size=%#llx/%#llx "
           "last=%#llx/%#llx",
           (unsigned long long)rb1, (unsigned long long)off,
           (unsigned long long)rb2, (unsigned long long)big,
           (unsigned long long)rb3, (unsigned long long)len);
        restore_baseline(dmap, p);
        return -1;
    }
    lg("ARMED va=%#llx len=%#llx (off=%#llx)", (unsigned long long)va,
       (unsigned long long)len, (unsigned long long)off);
    return 0;
}

/* One 0x01190201 round trip with the window already armed.
 * Returns the number of payload bytes appended to `out`, or -1. */
static int fetch_once(uint64_t *out_len, uint8_t *out, size_t out_cap) {
    size_t got = 0;
    memset(g_raw, 0, sizeof(g_raw));
    int rc = a53_transport_query_raw(CMD_MSGBUF, 0, 0, 0, 5,
                                    0x020100U, 0, 0, g_raw, sizeof(g_raw), &got);
    if (rc <= 0) {
        lg("next: no reply (rc=%d)", rc);
        return -1;
    }
    uint32_t pkt = rd32(g_raw, 8);
    if ((size_t)pkt > (size_t)rc || pkt < 0x68) {
        lg("next: malformed packet pkt=%#x rc=%d", pkt, rc);
        return -1;
    }
    /* text_len is the length the handler actually used. It exceeds the armed
     * value by the spill A53 wrote between arming and the handler. */
    uint32_t tlen = rd32(g_raw, 0x60);
    if (tlen == 0) {
        lg("next: empty text (tlen=0)");
        return -1;
    }
    if (tlen > out_cap) {
        lg("next: tlen=%#x exceeds buffer %#zx", tlen, out_cap);
        return -1;
    }
    memcpy(out, g_raw + 0x68, tlen);
    if (out_len) *out_len = tlen;
    return 0;
}

/* --------------------------------------------------------------- modes */

/* mode=paddr -- read A53 memory straight through the direct map.
 *
 * Everything so far went through 0x01190201, which requires arming DS fields
 * and therefore drags the A53 log cursor onto the landing point. But GATE1 has
 * always read the very same memory with kernel_copyout(dmap + ds_pa) and never
 * armed anything. If the A53 window is linearly mapped (VA-PA is a constant
 * 0x28000000 here), the whole image is reachable without the SDBGP command at
 * all -- no arming, no cursor movement, nothing written.
 *
 * This mode tests exactly that: copy [va, va+len) via the direct map and write
 * the bytes out for comparison against the 0x01190201 path.
 */
static int mode_paddr(uint64_t dmap, const struct a53_profile *p) {
    uint64_t va  = read_hex_file(VA_PATH,  p->ds);
    uint64_t len = read_hex_file(LEN_PATH, 0x1000);
    remove(VA_PATH);
    remove(LEN_PATH);
    if (len == 0 || len > READ_MAX) {
        lg("FATAL: bad len=%#llx", (unsigned long long)len);
        return 1;
    }
    /* The mapping GATE1 already relies on. */
    uint64_t pa = va - p->ds + p->ds_pa;
    lg("paddr va=%#llx -> pa=%#llx len=%#llx", (unsigned long long)va,
       (unsigned long long)pa, (unsigned long long)len);

    static uint8_t buf[READ_MAX];
    memset(buf, 0, sizeof(buf));
    if (kernel_copyout((intptr_t)(dmap + pa), buf, (size_t)len) != 0) {
        lg("VERDICT: PADDR_FAILED (copyout rejected %#llx)",
           (unsigned long long)pa);
        return 1;
    }
    FILE *f = fopen(OUT_PATH, "wb");
    if (f) { fwrite(buf, 1, (size_t)len, f); fclose(f); }
    lg("wrote %s (%llu B)", OUT_PATH, (unsigned long long)len);

    uint64_t magic = 0;
    memcpy(&magic, buf, 8);
    lg("paddr magic=%#llx expected=%#llx", (unsigned long long)magic,
       (unsigned long long)MDSR_MAGIC);
    lg("VERDICT: %s", magic == MDSR_MAGIC ? "PADDR_OK" : "PADDR_NO_MAGIC");
    return magic == MDSR_MAGIC ? 0 : 1;
}

static int mode_base(uint64_t dmap, const struct a53_profile *p) {
    print_mdsr(dmap, p, "core0");
    lg("VERDICT: BASELINE_ONLY");
    return 0;
}

static int mode_probe(uint64_t dmap, const struct a53_profile *p) {
    if (transport_up() != 0) return 1;

    uint64_t before = 0, after = 0;
    mdsr_fields(dmap, p, NULL, NULL, &before, NULL);
    lg("probe: last before=%#llx", (unsigned long long)before);

    size_t got = 0;
    memset(g_raw, 0, sizeof(g_raw));
    int rc = a53_transport_query_raw(CMD_MSGBUF, 0, 0, 0, 5,
                                    0x020100U, 0, 0, g_raw, sizeof(g_raw), &got);
    if (rc <= 0) { lg("VERDICT: NO_REPLY"); return 1; }
    uint32_t tlen = rd32(g_raw, 0x60);
    mdsr_fields(dmap, p, NULL, NULL, &after, NULL);
    lg("probe: text_len=%#x last after=%#llx",
       tlen, (unsigned long long)after);

    /* Criterion: the read window must sit between the cursor we saw before
     * the call and the one we see after it. Nothing was armed, so a match
     * proves the handler folds +0x218 on this build. */
    if (tlen >= before && tlen <= after) {
        lg("VERDICT: PROBE_OK (handler reads +0x218)");
        return 0;
    }
    lg("VERDICT: PROBE_UNEXPECTED (text_len outside [%#llx, %#llx])",
       (unsigned long long)before, (unsigned long long)after);
    return 1;
}

/* Direct-map probe: can [va, va+len) be copied out of the A53 window without
 * going through 0x01190201 at all?
 *
 * Why this matters: the SDBGP read path requires arming ds->offset/last, which
 * drags the A53 log cursor onto the landing point -- the spill is unavoidable
 * and can only be aimed at a sacrificial address. kernel_copyout() over the
 * direct map touches nothing: no command, no arming, no write. Measured cost is
 * zero cursor movement (see mode_paddr).
 *
 * Coverage is the catch. Only part of the A53 window is mapped here, so this is
 * a probe, not a replacement: 0x88700000 (448 KiB) and 0x88780000 answer, while
 * 0x88100000 / 0x88400000 / 0x885EB000 do not. Callers therefore try this first
 * and fall back to the command path. */
static int direct_read(uint64_t dmap, const struct a53_profile *p,
                       uint64_t va, uint64_t len, uint8_t *buf) {
    /* No range guard on purpose. The mapped extent is neither contiguous nor
     * aligned to the DS window -- 0x88600000 answers while 0x885EB000 and
     * 0x88100000 do not -- so the only reliable test is the copyout itself. A
     * rejected page yields 0 and the caller falls back to the command path. */
    if (va < A53_DIRECT_LO) return 0;   /* below the measured direct-map floor */
    uint64_t pa = va - p->ds + p->ds_pa;
    if (kernel_copyout((intptr_t)(dmap + pa), buf, (size_t)len) != 0) return 0;
    return 1;
}

/* Shared body of `one` and `dump`. Reads [va, va+len), restores, writes.
 *
 * Path selection: direct map when it answers (pollution-free), command read
 * otherwise. `wrap`/`one` keep their old behaviour for A/B work. */
static int do_read(uint64_t dmap, const struct a53_profile *p,
                   uint64_t va, uint64_t len, uint64_t *got_out) {
    static uint8_t direct[READ_MAX];
    if (len <= sizeof(direct) && direct_read(dmap, p, va, len, direct)) {
        FILE *df = fopen(OUT_PATH, "ab");
        if (!df) { lg("FATAL: cannot append %s", OUT_PATH); return 1; }
        fwrite(direct, 1, (size_t)len, df);
        fclose(df);
        lg("read va=%#llx asked=%#llx got=%#llu via=directmap (no spill)",
           (unsigned long long)va, (unsigned long long)len,
           (unsigned long long)len);
        if (got_out) *got_out = len;
        return 0;
    }

    if (gate_landing(p, va, len) != 0) return 1;
    if (arm(dmap, p, va, len) != 0) return 1;

    static uint8_t buf[READ_MAX + 0x1000];
    uint64_t n = 0;
    int rc = fetch_once(&n, buf, sizeof(buf));

    /* Always restore, even on failure: the next arming re-saves fields. */
    uint64_t o = 0, s = 0, l = 0;
    if (load_fields(&o, &s, &l) == 0) {
        uint64_t base = dmap + p->ds_pa;
        (void)kernel_copyin(&o, (intptr_t)(base + F_OFF),  8);
        (void)kernel_copyin(&s, (intptr_t)(base + F_SIZE), 8);
        (void)kernel_copyin(&l, (intptr_t)(base + F_LAST), 8);
        lg("restored off=%#llx size=%#llx last=%#llx",
           (unsigned long long)o, (unsigned long long)s, (unsigned long long)l);
    } else {
        restore_baseline(dmap, p);
    }

    if (rc != 0) { lg("VERDICT: READ_FAILED"); return 1; }

    FILE *f = fopen(OUT_PATH, "ab");
    if (!f) { lg("FATAL: cannot append %s", OUT_PATH); return 1; }
    fwrite(buf, 1, (size_t)n, f);
    fclose(f);

    lg("read va=%#llx asked=%#llx got=%#llu (delta=+%#llx)",
       (unsigned long long)va, (unsigned long long)len,
       (unsigned long long)n,
       (unsigned long long)(n - len));
    if (got_out) *got_out = n;
    return 0;
}

/* mode=forced -- read a segment whose tail butts against the next segment.
 *
 * controller_dev_data (0x88410000, 0x10000) ends exactly at
 * mm_controller_dram_text's first byte, so there is no gap to land in and gate 2
 * refuses it by policy. The spill is harmless *provided the next segment was
 * already copied out* -- which is the caller's responsibility here, hence the
 * explicit mode rather than a rule in do_read. Read mm_controller_dram_text
 * first, then this.
 *
 * The landing is the only thing damaged: the window itself is read before A53
 * writes its log line, so the bytes returned are clean.
 */
static int mode_forced(uint64_t dmap, const struct a53_profile *p) {
    if (transport_up() != 0) return 1;
    remove(OUT_PATH);
    uint64_t va  = read_hex_file(VA_PATH,  p->image);
    uint64_t len = read_hex_file(LEN_PATH, p->size);
    remove(VA_PATH);
    remove(LEN_PATH);
    if (len == 0 || len > READ_MAX) {
        lg("FATAL: bad len=%#llx", (unsigned long long)len);
        return 1;
    }
    lg("forced va=%#llx len=%#llx landing=%#llx (next segment assumed dumped)",
       (unsigned long long)va, (unsigned long long)len,
       (unsigned long long)(va + len));

    if (arm(dmap, p, va, len) != 0) return 1;
    static uint8_t buf[READ_MAX + 0x1000];
    uint64_t n = 0;
    int rc = fetch_once(&n, buf, sizeof(buf));

    uint64_t o = 0, sz = 0, l = 0;
    if (load_fields(&o, &sz, &l) == 0) {
        uint64_t base = dmap + p->ds_pa;
        (void)kernel_copyin(&o,  (intptr_t)(base + F_OFF),  8);
        (void)kernel_copyin(&sz, (intptr_t)(base + F_SIZE), 8);
        (void)kernel_copyin(&l,  (intptr_t)(base + F_LAST), 8);
    } else {
        restore_baseline(dmap, p);
    }
    if (rc != 0) { lg("VERDICT: READ_FAILED"); return 1; }

    FILE *f = fopen(OUT_PATH, "ab");
    if (!f) { lg("FATAL: cannot append %s", OUT_PATH); return 1; }
    fwrite(buf, 1, (size_t)(n < len ? n : len), f);
    fclose(f);
    lg("forced got=%#llu kept=%#llx", (unsigned long long)n,
       (unsigned long long)(n < len ? n : len));
    lg("VERDICT: %s", n >= len ? "FORCED_OK" : "FORCED_SHORT");
    return n >= len ? 0 : 1;
}

static int mode_one(uint64_t dmap, const struct a53_profile *p) {
    if (transport_up() != 0) return 1;
    remove(OUT_PATH);
    /* Default: the whole image in one request. */
    /* The va/len overrides let the same primitive reach regions outside the
     * image (.shstrtab, section headers). They are one-shot on purpose: a stale
     * file would silently make the next whole-image run read the wrong VA. */
    uint64_t va  = read_hex_file(VA_PATH,  p->image);
    uint64_t len = read_hex_file(LEN_PATH, p->size);
    if (va != p->image || len != p->size)
        lg("override va=%#llx len=%#llx (image is %#llx + %#llx)",
           (unsigned long long)va, (unsigned long long)len,
           (unsigned long long)p->image, (unsigned long long)p->size);
    remove(VA_PATH);
    remove(LEN_PATH);
    if (len == 0 || len > READ_MAX) { lg("FATAL: bad len=%#llx", (unsigned long long)len); return 1; }
    uint64_t got = 0;
    if (do_read(dmap, p, va, len, &got) != 0) return 1;

    /* The response carries armed_len + spill. The spill is what A53 logged at
     * landing = va + armed_len between arming and the handler reading the
     * cursor, so it is NOT a constant (measured 0x8c and 0x46 on two runs).
     * Only the first armed_len bytes are image data; drop the rest. */
    if (got > len) {
        if (truncate(OUT_PATH, (off_t)len) == 0)
            lg("truncated %s to %#llx (dropped %#llx spill bytes)", OUT_PATH,
               (unsigned long long)len, (unsigned long long)(got - len));
        else
            lg("WARN: truncate to %#llx failed", (unsigned long long)len);
    } else if (got < len) {
        lg("WARN: short image, got %#llx of %#llx",
           (unsigned long long)got, (unsigned long long)len);
    }

    /* Whole-image reads are the only place a strict ELF check is meaningful. */
    uint8_t hdr[4];
    FILE *f = fopen(OUT_PATH, "rb");
    size_t n = f ? fread(hdr, 1, sizeof(hdr), f) : 0;
    if (f) fclose(f);
    if (n == sizeof(hdr) && gate_elf(hdr, sizeof(hdr), 0) != 0) {
        lg("VERDICT: NOT_ELF");
        return 1;
    }
    lg("VERDICT: READ_OK");
    return 0;
}

static int mode_dump(uint64_t dmap, const struct a53_profile *p) {
    if (transport_up() != 0) return 1;

    uint64_t start = read_hex_file("/data/a53dump.start", p->image);
    uint64_t end   = read_hex_file("/data/a53dump.end", p->image + p->size);
    uint64_t chunk = read_hex_file("/data/a53dump.chunk", 0x4000);
    if (chunk == 0 || chunk > READ_MAX) chunk = 0x4000;

    uint64_t next = read_hex_file(STATE_PATH, start);
    if (next < start || next >= end) {
        lg("DONE next=%#llx start=%#llx end=%#llx",
           (unsigned long long)next, (unsigned long long)start,
           (unsigned long long)end);
        lg("VERDICT: DUMP_COMPLETE");
        return 0;
    }
    uint64_t len = end - next;
    if (len > chunk) len = chunk;

    uint64_t got = 0;
    if (do_read(dmap, p, next, len, &got) != 0) return 1;
    if (got == 0) got = len;

    /* Advance by the true length, which includes the spill. */
    write_hex_file(STATE_PATH, next + got);
    lg("chunk next=%#llx len=%#llx got=%#llx -> next=%#llx",
       (unsigned long long)next, (unsigned long long)len,
       (unsigned long long)got, (unsigned long long)(next + got));
    lg("VERDICT: CHUNK_OK");
    return 0;
}

/* mode=wrap -- exercise the count != 0 branch of 0x01190201.
 *
 * Background: with count == 0 the handler takes len from +0x218 ("last") and
 * reads base[0 .. last). With count != 0 it takes len from +0x210 ("size") and
 * reads base[last .. size) followed by base[0 .. last) -- a ring read.
 *
 * Purpose here is narrow: confirm which branch this build actually takes and
 * what the landing point becomes, without touching anything live. The window is
 * armed with size == last == len, so the first copy is empty and the second is
 * the plain [0, len). The landing then sits at base+last == base+len, which for
 * va=DS lands inside the core0 log ring -- a region A53 overwrites itself.
 */
static int mode_wrap(uint64_t dmap, const struct a53_profile *p) {
    uint64_t va  = read_hex_file(VA_PATH,  p->ds);
    uint64_t len = read_hex_file(LEN_PATH, 0x1000);
    remove(VA_PATH);
    remove(LEN_PATH);
    if (len == 0 || len > READ_MAX) {
        lg("FATAL: bad len=%#llx", (unsigned long long)len);
        return 1;
    }
    if (gate_landing(p, va, len) != 0) return 1;

    uint64_t base = dmap + p->ds_pa;
    uint64_t cur_off = 0, cur_size = 0, cur_last = 0, cur_cnt = 0;
    mdsr_fields(dmap, p, &cur_off, &cur_size, &cur_last, &cur_cnt);
    if (save_fields(cur_off, cur_size, cur_last) != 0) return 1;
    lg("saved off=%#llx size=%#llx last=%#llx count=%llu",
       (unsigned long long)cur_off, (unsigned long long)cur_size,
       (unsigned long long)cur_last, (unsigned long long)cur_cnt);

    /* Ring read shape: offset points at the window, size == last == len so the
     * two halves join into exactly [0, len) and the landing is base + len. */
    uint64_t off  = va - p->ds;
    uint64_t size = len;
    uint64_t last = len;
    uint64_t cnt  = 1;                  /* forces the wrapped branch */

    int r1 = kernel_copyin(&off,  (intptr_t)(base + F_OFF),  8);
    int r2 = kernel_copyin(&size, (intptr_t)(base + F_SIZE), 8);
    int r3 = kernel_copyin(&last, (intptr_t)(base + F_LAST), 8);
    int r4 = kernel_copyin(&cnt,  (intptr_t)(base + F_CNT),  8);
    uint64_t rb1 = 0, rb2 = 0, rb3 = 0, rb4 = 0;
    mdsr_fields(dmap, p, &rb1, &rb2, &rb3, &rb4);
    lg("armed off=%#llx size=%#llx last=%#llx count=%#llu",
       (unsigned long long)rb1, (unsigned long long)rb2,
       (unsigned long long)rb3, (unsigned long long)rb4);
    if (r1 || r2 || r3 || r4 || rb1 != off || rb2 != size || rb3 != last ||
        rb4 != cnt) {
        lg("FATAL: arm mismatch (%d/%d/%d/%d)", r1, r2, r3, r4);
        restore_baseline(dmap, p);
        return 1;
    }

    static uint8_t buf[READ_MAX + 0x1000];
    uint64_t n = 0;
    int rc = fetch_once(&n, buf, sizeof(buf));

    uint64_t o = 0, sz = 0, l = 0;
    if (load_fields(&o, &sz, &l) == 0) {
        (void)kernel_copyin(&o,  (intptr_t)(base + F_OFF),  8);
        (void)kernel_copyin(&sz, (intptr_t)(base + F_SIZE), 8);
        (void)kernel_copyin(&l,  (intptr_t)(base + F_LAST), 8);
        uint64_t zero = 0;
        (void)kernel_copyin(&zero, (intptr_t)(base + F_CNT), 8);  /* clear wrap */
        lg("restored off=%#llx size=%#llx last=%#llx count=0",
           (unsigned long long)o, (unsigned long long)sz, (unsigned long long)l);
    } else {
        restore_baseline(dmap, p);
    }
    if (rc != 0) { lg("VERDICT: WRAP_READ_FAILED"); return 1; }

    /* Keep the bytes: the point of this mode is comparing them against the
     * count == 0 path over the same window. */
    if (n) {
        FILE *wf = fopen(OUT_PATH, "wb");
        if (wf) { fwrite(buf, 1, (size_t)n, wf); fclose(wf); }
        lg("wrote %s (%llu B)", OUT_PATH, (unsigned long long)n);
    }
    lg("wrap got=%#llu asked=%#llx", (unsigned long long)n,
       (unsigned long long)len);
    /* Did the handler honour +0x210 or fall back to +0x218? With both equal
     * here the byte count cannot tell them apart, but a mismatch against `len`
     * says the ring read produced a different span than requested. */
    lg("VERDICT: %s", n == len ? "WRAP_OK" : "WRAP_LEN_MISMATCH");
    return n == len ? 0 : 1;
}

static int read_exact(uint64_t dmap, const struct a53_profile *p,
                      uint64_t va, uint64_t len, uint8_t *dst, int strict);

static int mode_restore(uint64_t dmap, const struct a53_profile *p) {
    uint64_t o = 0, s = 0, l = 0;
    if (load_fields(&o, &s, &l) != 0) return 1;
    uint64_t base = dmap + p->ds_pa;
    int r1 = kernel_copyin(&o, (intptr_t)(base + F_OFF),  8);
    int r2 = kernel_copyin(&s, (intptr_t)(base + F_SIZE), 8);
    int r3 = kernel_copyin(&l, (intptr_t)(base + F_LAST), 8);
    uint64_t rb1 = 0, rb2 = 0, rb3 = 0;
    mdsr_fields(dmap, p, &rb1, &rb2, &rb3, NULL);
    int ok = !r1 && !r2 && !r3 && rb1 == o && rb2 == s && rb3 == l;
    lg("RESTORE want off=%#llx size=%#llx last=%#llx",
       (unsigned long long)o, (unsigned long long)s, (unsigned long long)l);
    lg("RESTORE readback off=%#llx size=%#llx last=%#llx",
       (unsigned long long)rb1, (unsigned long long)rb2, (unsigned long long)rb3);
    lg("VERDICT: %s", ok ? "RESTORED" : "RESTORE_FAILED");
    return ok ? 0 : 1;
}

/* mode=scan -- locate DS on an unknown build, without touching A53.
 *
 * The MDSR structures live in the host-readable window right after TMR12.
 * 12.00 measured [0x605F0000, 0x60800000); the read-only scanner
 * `a53mdsrdump` proves the page range is readable on this unit. Never write. */
#define SCAN_LO 0x60600000ULL
#define SCAN_HI 0x60800000ULL

static int mode_scan(uint64_t dmap, const char *release) {
    lg("scan window [%#llx, %#llx) for magic1=%#llx",
       (unsigned long long)SCAN_LO, (unsigned long long)SCAN_HI,
       (unsigned long long)MDSR_MAGIC);

    int found = 0;
    for (uint64_t pa = SCAN_LO; pa < SCAN_HI; pa += 0x1000) {
        unsigned char page[8] = {0};
        if (kernel_copyout((intptr_t)(dmap + pa), page, 8) != 0) continue;
        uint64_t magic = 0;
        memcpy(&magic, page, 8);
        if (magic != MDSR_MAGIC) continue;

        uint64_t off  = kread64(dmap + pa + F_OFF);
        uint64_t size = kread64(dmap + pa + F_SIZE);
        uint64_t last = kread64(dmap + pa + F_LAST);
        uint64_t cnt  = kread64(dmap + pa + F_CNT);
        lg("HIT ds_pa=%#llx off=%#llx size=%#llx last=%#llx count=%llu",
           (unsigned long long)pa, (unsigned long long)off,
           (unsigned long long)size, (unsigned long long)last,
           (unsigned long long)cnt);
        /* Field sanity: an MDSR we can use has a small ring offset, a power-of-
         * two-ish size, and an unwrapped count. Anything else is a false hit. */
        if (off > 0x10000 || size == 0 || size > 0x1000000 || cnt != 0) {
            lg("  -> implausible field values, skipping");
            continue;
        }
        found++;
        lg("  -> usable core%d candidate", found - 1);
        lg("PROFILE ds_pa=%#llx ds=??? image=??? size=???",
           (unsigned long long)pa);
    }
    if (!found) {
        lg("VERDICT: SCAN_EMPTY");
        return 1;
    }
    lg("VERDICT: SCAN_OK found=%d", found);
    lg("Next: fill DS_PA from a hit, then locate IMAGE (see RUNBOOK 5.2).");
    return 0;
}

/* ------------------------------------------------------------------ elfmeta
 *
 * The loaded image stops at the last PT_LOAD, but an ELF's section header table
 * and its string table sit past that point. Both are still plain EL3 VAs, so
 * the same read primitive reaches them -- provided the landing point stays in
 * a harmless range.
 *
 * Offsets come from the image we already have on disk, never from constants:
 *   e_shoff    (u64 @ 0x28)   section header table file offset
 *   e_shnum    (u16 @ 0x3c)   number of section headers
 *   e_shentsize(u16 @ 0x3a)   size of one section header
 *   e_shstrndx (u16 @ 0x3e)   which header describes .shstrtab
 *
 * Everything is expressed relative to the image base, so only the profile's
 * IMAGE value is version dependent.
 */

static int read_u16(const uint8_t *b, size_t off, uint16_t *out) {
    if (!b || !out) return -1;
    *out = (uint16_t)b[off] | ((uint16_t)b[off + 1] << 8);
    return 0;
}

static int read_u32(const uint8_t *b, size_t off, uint32_t *out) {
    if (!b || !out) return -1;
    *out = (uint32_t)b[off] | ((uint32_t)b[off + 1] << 8) |
           ((uint32_t)b[off + 2] << 16) | ((uint32_t)b[off + 3] << 24);
    return 0;
}

static int read_u64(const uint8_t *b, size_t off, uint64_t *out) {
    if (!b || !out) return -1;
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | b[off + (size_t)i];
    *out = v;
    return 0;
}

/* Read [va, va+len) into *dst, then drop the spill the handler appended. */
static int read_exact(uint64_t dmap, const struct a53_profile *p,
                      uint64_t va, uint64_t len, uint8_t *dst, int strict) {
    if (strict && gate_landing(p, va, len) != 0) return -1;
    if (arm(dmap, p, va, len) != 0) return -1;

    uint64_t got = 0;
    int rc = fetch_once(&got, dst, READ_MAX + 0x1000);

    uint64_t o = 0, sz = 0, l = 0;
    if (load_fields(&o, &sz, &l) == 0) {
        uint64_t base = dmap + p->ds_pa;
        (void)kernel_copyin(&o, (intptr_t)(base + F_OFF),  8);
        (void)kernel_copyin(&sz, (intptr_t)(base + F_SIZE), 8);
        (void)kernel_copyin(&l, (intptr_t)(base + F_LAST), 8);
    } else {
        restore_baseline(dmap, p);
    }
    if (rc != 0) return -1;

    if (got < len) {
        lg("read va=%#llx: short, got %#llx of %#llx",
           (unsigned long long)va, (unsigned long long)got,
           (unsigned long long)len);
        return -1;
    }
    lg("read va=%#llx len=%#llx got=%#llu (spill %#llx)",
       (unsigned long long)va, (unsigned long long)len,
       (unsigned long long)got, (unsigned long long)(got - len));
    return 0;
}

static int dump_bytes(const char *path, const uint8_t *src, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f) { lg("FATAL: cannot write %s", path); return -1; }
    size_t w = fwrite(src, 1, n, f);
    fclose(f);
    if (w != n) { lg("FATAL: short write to %s", path); return -1; }
    lg("wrote %s (%zu B)", path, n);
    return 0;
}

static uint8_t g_meta[READ_MAX + 0x1000];

static int mode_elfmeta(uint64_t dmap, const struct a53_profile *p) {
    if (transport_up() != 0) return 1;

    uint8_t eh[0x40];
    FILE *f = fopen(OUT_PATH, "rb");
    if (!f) {
        lg("FATAL: %s missing; run mode=one first", OUT_PATH);
        return 1;
    }
    size_t n = fread(eh, 1, sizeof(eh), f);
    fclose(f);
    /* gate_elf(strict) compares e_phoff against the length it is given, so
     * pass the real file size rather than the 64-byte header we just read. */
    uint64_t img_size = 0;
    if (n == sizeof(eh)) {
        FILE *sz = fopen(OUT_PATH, "rb");
        if (sz && fseek(sz, 0, SEEK_END) == 0) {
            long end = ftell(sz);
            if (end > 0) img_size = (uint64_t)end;
        }
        if (sz) fclose(sz);
    }
    if (n != sizeof(eh) || img_size == 0 ||
        gate_elf(eh, (size_t)img_size, 1) != 0) {
        lg("VERDICT: BAD_IMAGE");
        return 1;
    }

    uint16_t shentsize = 0, shnum = 0, shstrndx = 0;
    uint64_t shoff = 0;
    (void)read_u16(eh, 0x3a, &shentsize);
    (void)read_u16(eh, 0x3c, &shnum);
    (void)read_u16(eh, 0x3e, &shstrndx);
    (void)read_u64(eh, 0x28, &shoff);
    lg("image: shoff=%#llx shnum=%u shentsize=%u shstrndx=%u",
       (unsigned long long)shoff, shnum, shentsize, shstrndx);
    if (shentsize < 0x40 || shnum == 0 || shstrndx >= shnum) {
        lg("VERDICT: BAD_ELF_METADATA");
        return 1;
    }

    uint64_t shdrs_len = (uint64_t)shnum * shentsize;
    if (shdrs_len > READ_MAX) {
        lg("FATAL: section headers %#llx exceed the read window",
           (unsigned long long)shdrs_len);
        return 1;
    }
    if (read_exact(dmap, p, p->image + shoff, shdrs_len, g_meta, 1) != 0) {
        lg("VERDICT: READ_FAILED");
        return 1;
    }
    if (dump_bytes(META_SHDRS, g_meta, (size_t)shdrs_len) != 0) return 1;

    /* Locate .shstrtab's own header and read the string table it describes. */
    size_t o = (size_t)shstrndx * shentsize;
    uint32_t sh_type = 0;
    uint64_t sh_off = 0, sh_size = 0;
    (void)read_u32(g_meta, o + 0x04, &sh_type);
    (void)read_u64(g_meta, o + 0x18, &sh_off);
    (void)read_u64(g_meta, o + 0x20, &sh_size);
    lg("shstrtab: type=%u off=%#llx size=%#llx",
       sh_type, (unsigned long long)sh_off, (unsigned long long)sh_size);
    if (sh_type != 3 || sh_size == 0 || sh_size > READ_MAX) {
        lg("VERDICT: BAD_SHSTRTAB_HEADER");
        return 1;
    }
    /* The first LANDING_SPILL bytes of .shstrtab are permanent collateral: on
     * every build examined they already hold A53 log text from earlier reads,
     * and reading them again cannot restore them. Start past that zone and
     * write a placeholder for the head so the file still lines up with
     * sh_offset. The affected sh_name entries are reported by the self-check
     * below and can be recovered from the program headers. */
    uint64_t skip = LANDING_SPILL;
    if (skip >= sh_size) {
        lg("VERDICT: SHSTRTAB_TOO_SMALL");
        return 1;
    }
    if (read_exact(dmap, p, p->image + sh_off + skip, sh_size - skip,
                   g_meta + skip, 1) != 0) {
        lg("VERDICT: READ_FAILED");
        return 1;
    }
    lg("shstrtab head [0, %#llx) left zero (pre-existing log spill)",
       (unsigned long long)skip);
    if (dump_bytes(META_SHSTR, g_meta, (size_t)sh_size) != 0) return 1;

    /* Self-check: every sh_name must resolve to a printable character. Read
     * both artefacts back from disk so the check covers what we actually
     * shipped, not the in-memory copies. */
    FILE *hf = fopen(META_SHDRS, "rb");
    FILE *sf = fopen(META_SHSTR, "rb");
    if (!hf || !sf) {
        if (hf) fclose(hf);
        if (sf) fclose(sf);
        lg("VERDICT: SELFCHECK_UNAVAILABLE");
        return 1;
    }
    uint32_t good = 0, bad = 0;
    for (uint32_t i = 0; i < shnum; i++) {
        uint8_t one[0x40];
        if (fseek(hf, (long)((size_t)i * shentsize), SEEK_SET) != 0) break;
        if (fread(one, 1, sizeof(one), hf) != sizeof(one)) break;
        uint32_t name = 0;
        (void)read_u32(one, 0x00, &name);
        if (name >= sh_size) { bad++; continue; }
        if (fseek(sf, (long)name, SEEK_SET) != 0) break;
        int c = fgetc(sf);
        if (c > 0 && c < 0x80) good++; else bad++;
    }
    fclose(hf);
    fclose(sf);
    lg("sh_name self-check: resolvable=%u unusable=%u of %u", good, bad, shnum);
    if (good + bad != shnum) {
        lg("VERDICT: SELFCHECK_INCOMPLETE");
        return 1;
    }
    lg("VERDICT: ELFMETA_OK");
    return 0;
}

static int mode_version(void) {
    if (transport_up() != 0) return 1;
    char banner[256] = {0};
    if (a53_transport_get_version(banner, sizeof(banner)) != 0) {
        lg("VERDICT: VERSION_UNKNOWN");
        return 1;
    }
    char *off = strstr(banner, "releases/");
    if (off) {
        char rel[16] = {0};
        for (int i = 0; i < 15 && off[9 + i] && off[9 + i] != ' '; i++)
            rel[i] = off[9 + i];
        lg("release=%s", rel);
    } else {
        lg("banner has no releases/ tag: %s", banner);
    }
    lg("VERDICT: VERSION_OK");
    return 0;
}

int main(void) {
    char mode[32] = "base";
    FILE *mf = fopen(MODE_PATH, "r");
    if (mf) {
        if (fgets(mode, sizeof(mode), mf)) {
            char *nl = strpbrk(mode, "\r\n");
            if (nl) *nl = 0;
        }
        fclose(mf);
    }

    g_log = fopen(LOG_PATH, "a");
    if (g_log) setvbuf(g_log, NULL, _IOLBF, 0);
    lg("=== a53dump mode=%s ===", mode);

    if (strcmp(mode, "version") == 0) return mode_version();
    /* scan needs no profile: it discovers one. */
    if (strcmp(mode, "scan") == 0) {
        uint64_t dm = dmap_from_kdata();
        if (!dm) { lg("FATAL: cannot locate direct map"); return 1; }
        return mode_scan(dm, NULL);
    }

    uint64_t dmap = dmap_from_kdata();
    lg("dmap=%#llx", (unsigned long long)dmap);
    if (!dmap) { lg("FATAL: cannot locate direct map"); return 1; }

    /* Resolve the release from the console itself, not from a host guess.
     * `GET_CONF` is a plain read command; failures here are not fatal for
     * modes that carry an explicit profile file. */
    struct a53_profile p;
    char release[16] = {0};
    if (transport_up() == 0) {
        char banner[256] = {0};
        if (a53_transport_get_version(banner, sizeof(banner)) == 0) {
            char *off = strstr(banner, "releases/");
            if (off)
                for (int i = 0; i < 15 && off[9 + i] && off[9 + i] != ' '; i++)
                    release[i] = off[9 + i];
        }
    }
    int pr = a53_profile_resolve(release, &p);
    if (pr == -2) {
        lg("FATAL: %s has no RANGE line", A53DUMP_PROFILE_PATH);
        return 1;
    }
    if (pr != 0) {
        lg("FATAL: release '%s' is not in the built-in profile table and no "
           "usable %s exists.", release[0] ? release : "?", A53DUMP_PROFILE_PATH);
        lg("Refusing to arm: a wrong DS/IMAGE would read the wrong memory.");
        lg("Safe next step: write %s with DS/IMAGE/SIZE/RANGE0, or run "
           "mode=base/probe on a known-good build first.", A53DUMP_PROFILE_PATH);
        lg("VERDICT: UNSUPPORTED_RELEASE");
        return 2;
    }
    a53_profile_print(&p, lg);

    /* Gate 1 runs for every mode, including base: it is the cheapest way to
     * prove the profile matches the hardware. */
    if (gate_mdsr(dmap, &p) != 0) {
        lg("VERDICT: PROFILE_MISMATCH");
        return 2;
    }

    if (strcmp(mode, "base") == 0)    return mode_base(dmap, &p);
    if (strcmp(mode, "paddr") == 0)   return mode_paddr(dmap, &p);
    if (strcmp(mode, "probe") == 0)   return mode_probe(dmap, &p);
    if (strcmp(mode, "one") == 0)     return mode_one(dmap, &p);
    if (strcmp(mode, "forced") == 0)  return mode_forced(dmap, &p);
    if (strcmp(mode, "dump") == 0)    return mode_dump(dmap, &p);
    if (strcmp(mode, "elfmeta") == 0) return mode_elfmeta(dmap, &p);
    if (strcmp(mode, "wrap") == 0)    return mode_wrap(dmap, &p);
    if (strcmp(mode, "restore") == 0) return mode_restore(dmap, &p);

    lg("FATAL: unknown mode '%s'", mode);
    lg("modes: version | scan | base | probe | one | forced | elfmeta | dump | wrap | paddr | restore");
    return 1;
}
