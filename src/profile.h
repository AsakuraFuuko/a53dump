/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 a53dump contributors
 *
 * This program links against a53_transport.c, which is derived from
 * drakmor/ppr-patch (GPL-3.0). The whole work is therefore distributed
 * under the GNU General Public License v3 or later. See LICENSE.
 */
/*
 * a53dump profile layer -- version identification and per-version constants.
 *
 * Why a profile layer
 * -------------------
 * The A53 dump channel (SDBGP 0x01190201 driven by MDSR fields) needs three
 * version-dependent constants:
 *
 *     DS      EL3 VA of mp4_debug_status_t (core0)
 *     IMAGE   EL3 VA where a53.elf is loaded
 *     SIZE    loaded image size in bytes
 *
 * Everything else is version-independent and verified across 4.02 .. 7.61:
 *   - command id 0x01190201 is the msgbuf handler in every build examined
 *   - MDSR field offsets +0x208 / +0x210 / +0x218 / +0x220
 *   - the deci5s_memory_arg wire format and the SDBGP response layout
 *   - transport discovery (mp4sc+0x18 -> bushandle+0x10 -> zcn_bar2)
 *
 * Resolution order
 *   1. /data/a53dump.profile   (explicit user override, highest priority)
 *   2. built-in table, keyed by the release string read from GET_CONF
 *   3. refuse. Never guess.
 *
 * Refusing is deliberate: a wrong DS or IMAGE makes the dump read the wrong
 * memory and, because the handler writes a log byte at the landing point, can
 * corrupt live A53 state. A11 gates in main.c are re-checked at runtime.
 */
#ifndef A53DUMP_PROFILE_H
#define A53DUMP_PROFILE_H

#include <stdint.h>

#define A53DUMP_PROFILE_PATH "/data/a53dump.profile"

/* Bytes the handler writes at the landing before the read is served. A landing
 * range must therefore absorb the whole [landing, landing+LANDING_SPILL) span. */
#define LANDING_SPILL 0x8cULL

/* A harmless landing range: the handler writes 0x8c log bytes at [lo, hi). */
struct a53_landing_range {
    uint64_t lo;
    uint64_t hi;
};

#define A53_MAX_LANDING_RANGES 28

/* Lowest VA the direct map reaches. Measured: 0x885EB000 is rejected by
 * kernel_copyout while 0x885F0000 answers, so the boundary sits in between and
 * this is the safe floor. Everything at or above it can be read without the
 * SDBGP command -- no arming, no spill. The value is stored rounded up to the
 * last known-good page. */
#define A53_DIRECT_LO 0x885F0000ULL

struct a53_profile {
    char     release[24];   /* "12.00", as parsed from the GET_CONF banner */
    uint64_t ds;            /* A53-side EL3 VA of mp4_debug_status_t (base for `offset`) */
    uint64_t ds_pa;         /* host PA of the same struct, for kernel_copyout/kernel_copyin */
    uint64_t image;         /* EL3 VA of the loaded a53.elf image */
    uint64_t size;          /* loaded image size, bytes */
    uint64_t pmax;          /* segment-table pmax, 0 if unknown */
    uint64_t limit;         /* segment-table LIMIT, 0 if unknown */
    int      nranges;
    struct a53_landing_range ranges[A53_MAX_LANDING_RANGES];
    char     source[32];    /* "builtin" | "file" */
};

/* Fill *out from the override file, else the built-in table.
 * `release` is the release string reported by the console ("12.00").
 * Returns 0 on success, -1 when the release is not known. */
int a53_profile_resolve(const char *release, struct a53_profile *out);

/* 1 if `landing` falls inside a declared harmless range. */
int a53_profile_landing_ok(const struct a53_profile *p, uint64_t landing);

void a53_profile_print(const struct a53_profile *p, void (*log)(const char *, ...));

#endif
