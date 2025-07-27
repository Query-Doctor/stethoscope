#ifndef L7_H
#define L7_H
// #include "vmlinux.h"
#include "vmlinux.h"
#include <bpf/libbpf.h>

struct trace_event_raw_sys_enter_sendto {
  struct trace_entry ent;
  __s32 __syscall_nr;
  __u64 fd;
  void *buff;
  __u64 len; // size_t ??
  __u64 flags;
  struct sockaddr *addr;
  __u64 addr_len;
};

struct trace_event_sys_enter_connect {
  struct trace_entry ent;
  int __syscall_nr;
  long unsigned int fd;
  struct sockaddrv *uservaddr;
  long unsigned int addrlen;
};

#endif
