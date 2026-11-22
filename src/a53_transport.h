#ifndef PPR_A53_TRANSPORT_H
#define PPR_A53_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#include "ppr_patch.h"

struct a53_transport_options {
    int persistent;
    int batch;
    int mixed_io;
};

int a53_transport_initialize(const struct a53_transport_options *options);
int a53_transport_enable_time_acceleration(void);
int a53_transport_get_version(char *out, uint32_t out_size);
uint32_t a53_transport_parse_release(const char *version);
int a53_transport_verify_and_enable_fast(
    const struct a53_transport_options *requested);
void a53_transport_make_ppr(struct ppr_patch_transport *out, int fast_mode);
void a53_transport_shutdown(void);

int a53_transport_query_argv(uint32_t type, uint32_t flags,
                             uint32_t command_no, const void *arg,
                             uint32_t arg_size, uint8_t *out, size_t out_cap,
                             size_t *avail_out);
int a53_transport_query_raw(uint32_t type, uint32_t flags,
                            uint32_t command_no, int with_mem_arg,
                            uint32_t access_size_bits, uint32_t mem_type,
                            uint64_t address, uint64_t size,
                            uint8_t *out, size_t out_cap,
                            size_t *avail_out);
void a53_transport_set_cmd(uint32_t cmd);
int a53_transport_probe_read_raw(uint32_t mem_type, uint32_t access_size_bits,
                                 uint64_t address, uint64_t size,
                                 uint8_t *out, size_t out_cap,
                                 size_t *avail_out);
int a53_transport_probe_read_multi(uint32_t mem_type,
                                   const uint32_t *access_size_bits,
                                   const uint64_t *addresses,
                                   const uint64_t *sizes, uint32_t count,
                                   uint8_t *out, size_t out_cap,
                                   size_t *avail_out);
int a53_transport_read_mailbox(uint32_t *state, uint32_t *flags);

#endif

uint64_t a53_transport_bar2(void);
uint64_t a53_transport_mp4sc(void);

uint64_t a53_transport_state_addr(void);
uint64_t a53_transport_flags_addr(void);
