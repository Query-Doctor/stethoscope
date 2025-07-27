#ifndef MAPS_H
#define MAPS_H
#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
// #include <linux/bpf.h>
// #include <bpf/bpf_helpers.h>

struct sock_key {
  u32 pid;
  int fd;
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 20);
} postgres_queries SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 18);
} query_timings SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 20);
} sqlite_queries SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct sock_key);
  __type(value, struct connection_event_t);
} connections SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct sock_key);
  __type(value, struct query_stack_t);
} timing SEC(".maps");

struct read_args {
  __u64 fd;
  __u64 size;
  __u64 read_start_ns;
  char *buf;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u64); // pid_tgid
  __uint(value_size, sizeof(struct read_args));
  __uint(max_entries, 10240);
} active_reads SEC(".maps");

#endif
