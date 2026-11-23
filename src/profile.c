/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 a53dump contributors
 *
 * This program links against a53_transport.c, which is derived from
 * drakmor/ppr-patch (GPL-3.0). The whole work is therefore distributed
 * under the GNU General Public License v3 or later. See LICENSE.
 */
#include "profile.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Built-in table.
 *
 * Only 12.00 is measured end to end on hardware (full 1,511,744 B image,
 * sha256 4f3411746d0fd3826c80eefeb4eed1ecea2e632eca377ac015c0d6a6d062f241).
 * 7.61 shares the same ds and image base by static analysis of the shipped
 * a53.elf (segment table identical, handler 0x111ae4 folds the same fields),
 * but no live dump was taken on that build -- it is marked "unverified" and
 * gated by the same runtime checks.
 *
 * Adding a build: run `mode=probe` first. It performs no A53 write and only
 * reads DS (magic must be 0xcbb3d18a1aa5daef) plus a passive text_len
 * comparison. If the magic matches, DS is right; then `mode=find` scans the
 * landing-safe hole above the image for the ELF magic to locate IMAGE.
 */
struct builtin {
    const char *release;
    uint64_t    ds;
    uint64_t    ds_pa;
    uint64_t    image;
    uint64_t    size;
    uint64_t    pmax;
    uint64_t    limit;
    int         nranges;
    struct a53_landing_range ranges[A53_MAX_LANDING_RANGES];
};

/* 12.00 landing-safe ranges.
 *
 * Source of truth: the console's own layout dump,
 *   mp4_layout_seg_set_name   (el3_boot log, 31 G6 entries)
 * which prints VA + size + name for every region. Deduplicated (EL2 and the
 * ELF load of EL2 overlap, as do EL1/stack/page tables) that is 22 segments.
 *
 * A landing L is safe iff the spill [L, L+0x8c) intersects no segment. Reading
 * a segment end-to-end puts the landing on its tail, so every gap below is the
 * space between one segment's end and the next segment's start.
 *
 * Two entries are easy to get wrong and were, during testing:
 *   - 0x88025000-0x88062000 is ONE segment holding EL1, both core stacks and
 *     both core page tables. It is not a series of small regions with gaps.
 *   - 0x88000000 holds the EL3 entry and the L1/L2/L3 translation tables, so
 *     its first bytes are live page tables even though they look like padding.
 * Writing into either kills the coprocessor; that is what A53 dying during the
 * whole-window sweep came from. */
#define R12_00 { 0x87FF0000ULL, 0x88000000ULL }  /* below the EL3 load segment */
#define R12_01 { 0x8801EBA0ULL, 0x8801F000ULL }  /* EL3 load end -> loader data */
#define R12_02 { 0x88021218ULL, 0x88022000ULL }  /* loader_el3_data -> dev_text */
#define R12_03 { 0x8802359DULL, 0x88024000ULL }  /* dev_text -> EL2 */
#define R12_04 { 0x88024D00ULL, 0x88025000ULL }  /* EL2 -> EL1/stacks/ptables */
#define R12_05 { 0x88062000ULL, 0x88100000ULL }  /* stacks/ptables -> a53.elf */
#define R12_06 { 0x88271140ULL, 0x88400000ULL }  /* a53.elf -> dev_text */
#define R12_07 { 0x88401140ULL, 0x88410000ULL }  /* dev_text -> dev_data */
#define R12_08 { 0x88438F10ULL, 0x88440000ULL }  /* mm_ctrl_text -> io_ctrl_text */
#define R12_09 { 0x88486980ULL, 0x88490000ULL }  /* io_ctrl_text -> ctrl_text */
#define R12_10 { 0x884B27ECULL, 0x884C0000ULL }  /* ctrl_text -> mm_data */
#define R12_11 { 0x884C02A0ULL, 0x884D0000ULL }  /* mm_data -> io_data */
#define R12_12 { 0x884D04A8ULL, 0x884E0000ULL }  /* io_data -> ctrl_data */
#define R12_13 { 0x884E00D0ULL, 0x88580000ULL }  /* ctrl_data -> mm_fixed_code */
#define R12_14 { 0x88594C40ULL, 0x88595000ULL }  /* mm_fixed_code -> wac */
#define R12_15 { 0x885A7F58ULL, 0x885A8000ULL }  /* wac -> shared_fixed_code */
#define R12_16 { 0x885B41E4ULL, 0x885B5000ULL }  /* shared -> io_fixed_code */
#define R12_17 { 0x885EA0E8ULL, 0x88700000ULL }  /* io_fixed_code -> MM_MDSR */
#define R12_18 { 0x88770000ULL, 0x88780000ULL }  /* MM_MDSR -> IO_MDSR */
#define R12_19 { 0x887F1450ULL, 0x887FFC00ULL }  /* Layout -> driver param */
#define R12_20 { 0x887FFE98ULL, 0x88800000ULL }  /* driver param -> window end */
/* Inside the two MDSR segments. A53 rewrites these rings continuously, so a
 * spill here is overwritten within seconds. */
#define R12_21 { 0x88701000ULL, 0x88770000ULL }  /* core0 ring in MM_MDSR */
#define R12_22 { 0x88781000ULL, 0x887F0000ULL }  /* core1 ring in IO_MDSR */
/* 13.60 landing-safe ranges.
 *
 * Derived the same way as 12.00 -- read each segment end to end, land in the gap
 * after it -- but the layout is not merely "12.00 with a longer io_fixed_code".
 * Seven of the 31 G6 entries move (source: kernelkatio 13.60 capture,
 * artifacts/external/2026-11-15_kernelkatio_1360/mm_mdsr.txt L223-260):
 *
 *   mli11 mm_ctrl_text      size  0x18F10 -> 0x188FC   (-0x614)
 *   mli12 io_ctrl_text      size  0x46980 -> 0x46FA8   (+0x628)
 *   mli13 ctrl_text         size  0x227EC -> 0x2286C   (+0x080)
 *   mli01 mm_fixed_code     size  0x14C40 -> 0x16B14   (+0x1ED4)
 *   mli02 mm_fixed_code_wac VA    0x88595000 -> 0x88597000  (+0x2000)
 *   mli03 shared_fixed_code VA    0x885A8000 -> 0x885AA000  (+0x2000), size +0x74
 *   mli04 io_fixed_code     VA    0x885B5000 -> 0x885B7000  (+0x2000), size +0xC24
 *
 * pmax 0x885EA0E8 -> 0x885ECD0C, LIMIT unchanged at 0x88700000.
 *
 * Using 12.00's gaps here does not corrupt anything -- gate 2 rejects the read --
 * but mm_fixed_code, mm_fixed_code_wac and shared_fixed_code become unreachable,
 * because their landings no longer fall in a gap. */
#define R13_00 { 0x87FF0000ULL, 0x88000000ULL }  /* below the EL3 load segment */
#define R13_01 { 0x8801EBA0ULL, 0x8801F000ULL }  /* EL3 load end -> loader data */
#define R13_02 { 0x88021218ULL, 0x88022000ULL }  /* loader_el3_data -> dev_text */
#define R13_03 { 0x8802359DULL, 0x88024000ULL }  /* dev_text -> EL2 */
#define R13_04 { 0x88024D00ULL, 0x88025000ULL }  /* EL2 -> EL1/stacks/ptables */
#define R13_05 { 0x88062000ULL, 0x88100000ULL }  /* stacks/ptables -> a53.elf */
#define R13_06 { 0x88271140ULL, 0x88400000ULL }  /* a53.elf -> dev_text */
#define R13_07 { 0x88401140ULL, 0x88410000ULL }  /* dev_text -> dev_data */
/* No gap after dev_data this time: mli30's tail meets mli11's head exactly, so
 * controller_dev_data needs mode=forced, as on 12.00. */
#define R13_08 { 0x884388FCULL, 0x88440000ULL }  /* mm_ctrl_text -> io_ctrl_text */
#define R13_09 { 0x88486FA8ULL, 0x88490000ULL }  /* io_ctrl_text -> ctrl_text */
#define R13_10 { 0x884B286CULL, 0x884C0000ULL }  /* ctrl_text -> mm_data */
#define R13_11 { 0x884C02A0ULL, 0x884D0000ULL }  /* mm_data -> io_data */
#define R13_12 { 0x884D04A8ULL, 0x884E0000ULL }  /* io_data -> ctrl_data */
#define R13_13 { 0x884E00D0ULL, 0x88580000ULL }  /* ctrl_data -> mm_fixed_code */
#define R13_14 { 0x88596B14ULL, 0x88597000ULL }  /* mm_fixed_code -> wac */
#define R13_15 { 0x885A9F58ULL, 0x885AA000ULL }  /* wac -> shared_fixed_code */
#define R13_16 { 0x885B6258ULL, 0x885B7000ULL }  /* shared -> io_fixed_code */
#define R13_17 { 0x885ECD0CULL, 0x88700000ULL }  /* io_fixed_code -> MM_MDSR */
#define R13_18 { 0x88770000ULL, 0x88780000ULL }  /* MM_MDSR -> IO_MDSR */
#define R13_19 { 0x887F1450ULL, 0x887FFC00ULL }  /* Layout -> driver param */
#define R13_20 { 0x887FFE98ULL, 0x88800000ULL }  /* driver param -> window end */
#define R13_21 { 0x88701000ULL, 0x88770000ULL }  /* core0 ring in MM_MDSR */
#define R13_22 { 0x88781000ULL, 0x887F0000ULL }  /* core1 ring in IO_MDSR */
#define R61_0 { 0x885EA0E8ULL, 0x88700000ULL }
#define R61_1 { 0x88701000ULL, 0x88770000ULL }
#define R61_2 { 0x88781000ULL, 0x887E0000ULL }

/* 13.60: layout identical to 12.00 except io_fixed_code grew by 0x2C24 bytes,
 * shifting pmax from 0x885EA0E8 to 0x885ECD0C. All other segments unchanged.
 * Values confirmed from live 13.60 MDSR boot log (pmax + LIMIT printk). */
#define R13_17 { 0x885ECD0CULL, 0x88700000ULL }  /* io_fixed_code -> MM_MDSR (13.60) */

static const struct builtin g_builtin[] = {
    { "12.00", 0x88700000ULL, 0x60700000ULL, 0x88100000ULL, 0x171140ULL,
      0x885EA0E8ULL, 0x88700000ULL, 23,
      { R12_00, R12_01, R12_02, R12_03, R12_04, R12_05, R12_06,
        R12_07, R12_08, R12_09, R12_10, R12_11, R12_12,
        R12_13, R12_14, R12_15, R12_16, R12_17,
        R12_18, R12_19, R12_20, R12_21, R12_22 } },
    /* 13.60: pmax and every gap below come from the console's own layout dump.
     *
     * Verified on hardware by the PR that added this row: `one` and `elfmeta`
     * both succeed, so the 13.60 address-window validator (0x2951C) does not
     * reject these reads.
     *
     * SIZE is the layout table's 0x171140 and is NOT independently confirmed.
     * On 12.00 that value stops one byte short of .shstrtab, so a self-contained
     * ELF needs 0x17E098. Do not assume it transfers: dump the image, then read
     * e_shoff + e_shnum*e_shentsize out of the result and check the file covers
     * the section header table. */
    { "13.60", 0x88700000ULL, 0x60700000ULL, 0x88100000ULL, 0x171140ULL,
      0x885ECD0CULL, 0x88700000ULL, 23,
      { R13_00, R13_01, R13_02, R13_03, R13_04, R13_05, R13_06,
        R13_07, R13_08, R13_09, R13_10, R13_11, R13_12,
        R13_13, R13_14, R13_15, R13_16, R13_17,
        R13_18, R13_19, R13_20, R13_21, R13_22 } },
    { "7.61",  0x88700000ULL, 0x60700000ULL, 0x88100000ULL, 0x171140ULL,
      0x885EA0E8ULL, 0x88700000ULL, 3, { R61_0, R61_1, R61_2 } },
};

static void copy_str(char *dst, size_t cap, const char *src) {
    if (!dst || cap == 0) return;
    size_t n = strlen(src);
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static int read_hex(FILE *f, const char *key, uint64_t *out) {
    char line[128];
    rewind(f);
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;
        if (strncmp(p, key, strlen(key)) != 0) continue;
        p += strlen(key);
        while (*p == ' ' || *p == '\t' || *p == '=' || *p == ':') p++;
        unsigned long long v = 0;
        if (sscanf(p, "%llx", &v) != 1) return -1;
        *out = (uint64_t)v;
        return 0;
    }
    return -1;
}

static int read_range(FILE *f, const char *key, struct a53_landing_range *out) {
    char line[128];
    rewind(f);
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, key, strlen(key)) != 0) continue;
        p += strlen(key);
        while (*p == ' ' || *p == '\t' || *p == '=' || *p == ':') p++;
        unsigned long long lo = 0, hi = 0;
        if (sscanf(p, "%llx %llx", &lo, &hi) != 2) return -1;
        out->lo = (uint64_t)lo;
        out->hi = (uint64_t)hi;
        return 0;
    }
    return -1;
}

/* User override: DS/IMAGE/SIZE/PMAGIC-less simple key=hex lines. */
static int load_file(struct a53_profile *out) {
    FILE *f = fopen(A53DUMP_PROFILE_PATH, "r");
    if (!f) return -1;

    uint64_t ds = 0, ds_pa = 0x60700000ULL, image = 0, size = 0, pmax = 0, limit = 0;
    if (read_hex(f, "DS", &ds) != 0 || read_hex(f, "IMAGE", &image) != 0 ||
        read_hex(f, "SIZE", &size) != 0) {
        fclose(f);
        return -1;
    }
    (void)read_hex(f, "DS_PA", &ds_pa);
    (void)read_hex(f, "PMAX", &pmax);
    (void)read_hex(f, "LIMIT", &limit);

    out->ds = ds;
    out->ds_pa = ds_pa;
    out->image = image;
    out->size = size;
    out->pmax = pmax;
    out->limit = limit;
    out->nranges = 0;
    for (int i = 0; i < A53_MAX_LANDING_RANGES; i++) {
        char key[16];
        snprintf(key, sizeof(key), "RANGE%d", i);
        if (read_range(f, key, &out->ranges[out->nranges]) != 0) break;
        out->nranges++;
    }
    fclose(f);
    copy_str(out->source, sizeof(out->source), "file");
    return 0;
}

int a53_profile_resolve(const char *release, struct a53_profile *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    copy_str(out->release, sizeof(out->release), release ? release : "?");

    if (load_file(out) == 0) {
        /* A file profile must still carry a landing range or the runtime gates
         * below will refuse everything -- report it now rather than later. */
        if (out->nranges == 0)
            return -2;
        return 0;
    }

    if (release) {
        for (size_t i = 0; i < sizeof(g_builtin) / sizeof(g_builtin[0]); i++) {
            if (strcmp(g_builtin[i].release, release) != 0) continue;
            out->ds = g_builtin[i].ds;
            out->ds_pa = g_builtin[i].ds_pa;
            out->image = g_builtin[i].image;
            out->size = g_builtin[i].size;
            out->pmax = g_builtin[i].pmax;
            out->limit = g_builtin[i].limit;
            out->nranges = g_builtin[i].nranges;
            for (int k = 0; k < out->nranges; k++)
                out->ranges[k] = g_builtin[i].ranges[k];
            copy_str(out->source, sizeof(out->source), "builtin");
            return 0;
        }
    }
    return -1;
}

int a53_profile_landing_ok(const struct a53_profile *p, uint64_t landing) {
    if (!p) return 0;
    for (int i = 0; i < p->nranges; i++)
        if (landing >= p->ranges[i].lo && landing < p->ranges[i].hi)
            return 1;
    return 0;
}

void a53_profile_print(const struct a53_profile *p, void (*log)(const char *, ...)) {
    if (!p || !log) return;
    log("profile release=%s source=%s", p->release, p->source);
    log("profile ds=%#llx (pa %#llx) image=%#llx size=%#llx pmax=%#llx limit=%#llx",
        (unsigned long long)p->ds, (unsigned long long)p->ds_pa,
        (unsigned long long)p->image,
        (unsigned long long)p->size, (unsigned long long)p->pmax,
        (unsigned long long)p->limit);
    for (int i = 0; i < p->nranges; i++)
        log("profile range[%d] = [%#llx, %#llx)", i,
            (unsigned long long)p->ranges[i].lo,
            (unsigned long long)p->ranges[i].hi);
}
