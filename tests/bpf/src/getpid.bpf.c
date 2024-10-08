// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 /* one page */);
} ringbuf SEC(".maps");

static __noinline u64 subprogram(void)
{
    u64 fp, ip;
    /* Read frame pointer value. */
    asm volatile ("%[fp] = r10" : [fp] "+r"(fp) :);
    /* At frame pointer + 8 we expect the return address. */
    bpf_probe_read_kernel(&ip, sizeof(ip), (void *)(long)(fp + 8));
    return ip;
}

SEC("tracepoint/syscalls/sys_enter_getpid")
int handle__getpid(void *ctx)
{
    u64 *value;

    value = bpf_ringbuf_reserve(&ringbuf, 2 * sizeof(*value), 0);
    if (!value) {
        bpf_printk("handle__getpid: failed to reserve ring buffer space");
        return 1;
    }

    /* First address is the return address of `subprogram`. */
    *(value + 0) = subprogram();
    /* Second address is the `subprogram` "sub-program". */
    *(value + 1) = (u64)&subprogram;
    bpf_printk("handle__getpid = %lx\n", *(value + 0));
    bpf_printk("subprogram = %lx\n", *(value + 1));
    bpf_ringbuf_submit(value, 0);
    bpf_printk("handle__getpid: submitted ringbuf value");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
