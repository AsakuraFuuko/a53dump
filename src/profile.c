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

/* 12.00 landing-safe ranges, all measured (see A53_FIRMWARE_DUMP_HOWTO.md section 5). */
#define R12_0 { 0x88271140ULL, 0x88400000ULL }  /* image end -> EL0 SYSHUB */
#define R12_1 { 0x885EA0E8ULL, 0x88700000ULL }  /* seg pmax -> LIMIT        */
#define R12_2 { 0x88701000ULL, 0x88770000ULL }  /* core0 log ring           */
#define R12_3 { 0x88781000ULL, 0x887E0000ULL }  /* core1 log ring           */
#define R61_0 { 0x885EA0E8ULL, 0x88700000ULL }
#define R61_1 { 0x88701000ULL, 0x88770000ULL }
#define R61_2 { 0x88781000ULL, 0x887E0000ULL }

static const struct builtin g_builtin[] = {
    { "12.00", 0x88700000ULL, 0x60700000ULL, 0x88100000ULL, 0x171140ULL,
      0x885EA0E8ULL, 0x88700000ULL, 4, { R12_0, R12_1, R12_2, R12_3 } },
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
