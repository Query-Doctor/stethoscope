#ifndef DATABASE_H
#define DATABASE_H
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define MAX_QUERY_LEN 65355 // Max query length we support (64KB)

#define SQLITE_STEP_FINISHED 101

typedef enum {
  DATABASE_TYPE_POSTGRES = 0,
  DATABASE_TYPE_SQLITE = 1,
} database_type_t;

#define STACK_SIZE 32

struct query_stack_t {
  __u64 stack[STACK_SIZE];
  __u64 top;
};

struct connection_event_t {
  __u32 fd;
  __u32 ip;
  __u16 port;
};

struct query_event_t {
  __u32 pid;
  __u32 tid;
  __u32 query_len;               // Total length of the full query string
  database_type_t database_type; // postgres | sqlite
  struct connection_event_t connection;
  __u8 encrypted;
  __u8 comm[16];            // Process name
  __u8 data[MAX_QUERY_LEN]; // Data buffer for the query string
};

struct query_timing_t {
  __u32 delta;
  struct connection_event_t connection;
};
#endif
