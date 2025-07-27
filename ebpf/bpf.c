#include "database.h"
#include "maps.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
// #include <bpf/bpf_tracing.h>
#include "openssl.c"
#include <bpf/bpf_helpers.h>
// #include <linux/socket.h>
// #include <arpa/inet.h>

// #include <sys/socket.h>

struct thread_ctx {
  __u32 pid;
  __u32 tid;
};

static __always_inline struct thread_ctx get_thread_ctx(void) {
  struct thread_ctx ctx;
  __u64 id = bpf_get_current_pid_tgid();
  ctx.tid = (__u32)(id & 0xFFFFFFFF);
  ctx.pid = (__u32)(id >> 32);

  return ctx;
}

static __always_inline struct query_event_t *
create_query(database_type_t database_type, __u8 encrypted) {
  struct query_event_t *event;
  event =
      bpf_ringbuf_reserve(&postgres_queries, sizeof(struct query_event_t), 0);
  if (event == NULL) {
    return NULL;
  }
  // make sure to zero out the padding!
  // __builtin_memset(event, 0, sizeof(struct query_event_t));
  struct thread_ctx ctx = get_thread_ctx();
  event->pid = ctx.pid;
  event->tid = ctx.tid;
  event->encrypted = encrypted;
  // event->query_type = query_type;
  event->database_type = database_type;
  if (bpf_get_current_comm(&event->comm, sizeof(event->comm)) != 0) {
    bpf_ringbuf_discard(event, 0);
    return NULL;
  }
  return event;
}

static __always_inline void push(struct query_stack_t *stack, __u64 start) {
  __u64 index = __sync_fetch_and_add(&stack->top, 1);
  if (index < STACK_SIZE) {
    stack->stack[index] = start;
  } else {
    bpf_printk("stethoscope: stack overflow");
    __sync_fetch_and_sub(&stack->top, 1);
  }
}

static __always_inline __u64 pop(struct query_stack_t *stack) {
  // TODO: all this is very unsafe
  if (stack->top >= STACK_SIZE) {
    bpf_printk("stethoscope: stack overflow");
    return 0;
  } else if (stack->top <= 0) {
    bpf_printk("stethoscope: stack underflow");
    return 0;
  }
  __u64 result = stack->stack[stack->top - 1];
  long long index = __sync_fetch_and_sub(&stack->top, 1);
  if (index < 0) {
    bpf_printk("stethoscope: stack underflow");
    __sync_fetch_and_add(&stack->top, 1);
  }
  return result;
}

static __always_inline void send(struct query_event_t *event) {
  if (event == NULL) {
    return;
  }
  struct sock_key key;
  bpf_printk("stethoscope: send: pid: %d, fd: %d", event->pid,
             event->connection.fd);
  key.pid = event->pid;
  key.fd = event->connection.fd;
  bpf_ringbuf_submit(event, 0);
  __u64 start = bpf_ktime_get_ns();
  struct query_stack_t *stack = bpf_map_lookup_elem(&timing, &key);
  if (stack) {
    bpf_printk("stethoscope: send: stack: %d", stack->top);
    push(stack, start);
    bpf_map_update_elem(&timing, &key, stack, BPF_ANY);
  } else {
    bpf_printk("stethoscope: send: stack: none");
    struct query_stack_t stack = {.top = 1, .stack = {start}};
    bpf_map_update_elem(&timing, &key, &stack, BPF_ANY);
  }
}

static __always_inline bool
is_valid_postgres_extended_query_identifier(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
         (c >= '0' && c <= '9');
}

static __always_inline bool is_non_standard_postgres_identifier(__u32 next) {
  return next == 80877103;
}

typedef bool (*postgres_query_callback_t)(__u8 header, const void *buf_ptr,
                                          size_t buf_len);

enum sender_t { SENDER_BACKEND, SENDER_FRONTEND };

static __always_inline bool
is_postgres_query(const void *buf_ptr, size_t buf_len,
                  postgres_query_callback_t callback) {
  size_t offset = 0;
  size_t i = 0;
  // pipelines extended queries probably don't have more sections than this
  // bpf_printk("stethoscope: postgres_query: buf_len: %d", buf_len);
  for (; i < 15 && offset < buf_len; i += 1) {
    char header;
    if (bpf_probe_read_user(&header, sizeof(header), buf_ptr + offset) != 0) {
      return false;
    }
    __u32 len;
    if (bpf_probe_read_user(&len, sizeof(len), buf_ptr + offset + 1) != 0) {
      return false;
    }
    len = bpf_ntohl(len);
    size_t skip = 0;
    char data[128];
    if (bpf_probe_read_user(&data, sizeof(data), buf_ptr + offset + 5) != 0) {
      return false;
    }
    if (len == 80877103) {
      skip = 8;
    } else if (is_valid_postgres_extended_query_identifier(header)) {
      skip = len + 1;
      size_t parsable_length = len > sizeof(len) ? len - sizeof(len) : 0;
      if (callback != NULL) {
        bool result =
            callback(header, buf_ptr + offset + sizeof(header) + sizeof(len),
                     parsable_length);
        if (result) {
          return true;
        }
      }
    } else {
      break;
    }
    // one extra for the header itself
    offset += skip;
  }
  // bpf_printk("stethoscope: postgres_query: offset: %d, i: %d", offset, i);
  return i > 0;
}

static __always_inline bool
is_postgres_client_query(__u8 header, const void *buf_ptr, size_t buf_len) {
  return header == 'Q' || header == 'P';
}

static __always_inline int postgres_sendto(__u32 fd, void *buf, size_t buf_len,
                                           __u8 encrypted) {
  if (buf_len <= 10) {
    return 0;
  }

  struct sock_key key = {
      .pid = bpf_get_current_pid_tgid() >> 32,
      .fd = fd,
  };
  struct connection_event_t *conn = bpf_map_lookup_elem(&connections, &key);
  const void *buf_ptr = (const void *)buf;
  __u8 header;
  if (bpf_probe_read_user(&header, sizeof(header), buf_ptr) != 0) {
    return 1;
  }

  char *pointer = (char *)buf_ptr + 1;
  bool is_query_response =
      is_postgres_query(buf_ptr, buf_len, is_postgres_client_query);
  if (!is_query_response) {
    return 1;
  }
  if (header == 'Q') {
    __u32 len;
    bpf_probe_read_user(&len, sizeof(len), pointer);
    len = bpf_ntohl(len);
    pointer += sizeof(len);
    // drop packets not matching the protocol
    if (buf_len != len + 1) {
      return 1;
    }
    struct query_event_t *event =
        create_query(DATABASE_TYPE_POSTGRES, encrypted);
    if (event == NULL) {
      return 1;
    }
    if (conn != NULL) {
      __builtin_memcpy(&event->connection, conn,
                       sizeof(struct connection_event_t));
    } else {
      __builtin_memset(&event->connection, 0,
                       sizeof(struct connection_event_t));
    }
    long read_count =
        bpf_probe_read_user_str(&event->data, sizeof(event->data), pointer);
    if (read_count < 0) {
      bpf_ringbuf_discard(event, 0);
      return 1;
    }
    event->query_len = read_count;
    send(event);
    return 0;
  }
  // 'P'
  if (header == 'P') {
    struct query_event_t *event =
        create_query(DATABASE_TYPE_POSTGRES, encrypted);
    if (event == NULL) {
      return 1;
    }
    if (conn != NULL) {
      __builtin_memcpy(&event->connection, conn,
                       sizeof(struct connection_event_t));
    } else {
      __builtin_memset(&event->connection, 0,
                       sizeof(struct connection_event_t));
    }
    // can contain other kinds of commands, not just P
    __u32 len;
    bpf_probe_read_user(&len, sizeof(len), pointer);
    len = bpf_ntohl(len);
    if (len > buf_len) {
      bpf_ringbuf_discard(event, 0);
      return 1;
    }
    pointer += sizeof(len);
    char prepared_statement_name[32];
    size_t name_read_count = bpf_probe_read_user_str(
        &prepared_statement_name, sizeof(prepared_statement_name), pointer);
    if (name_read_count < 0) {
      bpf_ringbuf_discard(event, 0);
      return 1;
    }
    pointer += name_read_count + 1;
    long long query_read_count =
        bpf_probe_read_user_str(&event->data, sizeof(event->data), pointer);
    if (query_read_count < 0) {
      bpf_ringbuf_discard(event, 0);
      return 1;
    }
    bpf_printk("stethoscope: len: %u, query: %s, name: %s %d", len, event->data,
               prepared_statement_name, name_read_count);
    event->query_len = query_read_count;
    pointer += query_read_count + 1;
    __u16 param_length;
    if (bpf_probe_read_user(&param_length, sizeof(param_length), pointer) !=
        0) {
      bpf_ringbuf_discard(event, 0);
      return 1;
    };
    pointer += sizeof(param_length);
    send(event);
    return 0;
  }

  return 1;
}

SEC("tp/syscalls/sys_enter_sendto")
int handle_sendto(struct trace_event_raw_sys_enter *ctx) {
  return postgres_sendto((__u32)ctx->args[0], (void *)ctx->args[1],
                         (size_t)ctx->args[2], 0);
}

SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct syscall_trace_enter *ctx) {
  struct sockaddr_in sa; // Use sockaddr_in directly
  struct sockaddr *addr_ptr = (struct sockaddr *)ctx->args[1];
  struct sock_key key = {
      .pid = bpf_get_current_pid_tgid() >> 32,
      .fd = ctx->args[0],
  };

  if (!addr_ptr) {
    bpf_printk("stethoscope: addr_ptr is null");
    return 0;
  }

  // Read the sockaddr data from user space
  bpf_probe_read_user(&sa, sizeof(sa), addr_ptr);

  // If you're sure it's IPv4, you can now access the members.
  // A safety check is still a good idea.
  u32 dest_ip = sa.sin_addr.s_addr;
  u16 dest_port = bpf_ntohs(sa.sin_port);
  // char ip_str[20];
  // __u64 args[] = {
  //     dest_ip & 0xFF,
  //     (dest_ip >> 8) & 0xFF,
  //     (dest_ip >> 16) & 0xFF,
  //     (dest_ip >> 24) & 0xFF,
  // };
  // bpf_snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", args, sizeof(args));

  struct connection_event_t event = {
      .fd = ctx->args[0],
      .ip = dest_ip,
      .port = dest_port,
  };

  bpf_map_update_elem(&connections, &key, &event, BPF_ANY);
  return 0;
}

SEC("tp/syscalls/sys_enter_close")
int handle_close(struct syscall_trace_enter *ctx) {
  struct sock_key key = {
      .pid = bpf_get_current_pid_tgid() >> 32,
      .fd = ctx->args[0],
  };

  bpf_map_delete_elem(&connections, &key);
  return 0;
}

SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write, void *ssl, void *buffer, int num) {
  // ssl_uprobe_write_v_3(ctx, ssl, buffer, num, 0);
  bpf_printk("stethoscope: SSL_write_v3: num: %d", num);
  struct ssl_st_v3_0_0 ssl_v3;
  if (bpf_probe_read_user(&ssl_v3, sizeof(ssl_v3), ssl) < 0) {
    return 0;
  }
  struct bio_st_v3_0 wbio;
  if (bpf_probe_read(&wbio, sizeof(wbio), ssl_v3.wbio) < 0) {
    return 0;
  }
  postgres_sendto(wbio.num, buffer, num, 1);
  return 0;
}

static bool is_response(__u8 header, const void *buf_ptr, size_t buf_len) {
  if (header == 'S' && buf_len > 0) {
    char key[32];
    size_t read = bpf_probe_read_user_str(&key, sizeof(key), buf_ptr);
    if (read < 0) {
      return false;
    }
    // bpf_printk("stethoscope: postgres_query_callback: key: %s", key);
    char val[32];
    read = bpf_probe_read_user_str(&val, sizeof(val), buf_ptr + read);
    if (read < 0) {
      return false;
    }
    bpf_printk("stethoscope: S (%d) %s=%s", read, key, val);
  }
  return header == 'C' || header == 'I';
}

int __always_inline postgres_read(__u32 fd, void *buf, size_t buf_len,
                                  __u8 encrypted) {
  struct sock_key key = {
      .pid = bpf_get_current_pid_tgid() >> 32,
      .fd = fd,
  };
  struct connection_event_t *conn = bpf_map_lookup_elem(&connections, &key);
  struct query_stack_t *stack = bpf_map_lookup_elem(&timing, &key);
  bool is_query_response = is_postgres_query(buf, buf_len, is_response);

  if (stack && is_query_response) {
    __u32 prev = pop(stack);
    bpf_printk("stethoscope: read: prev: %u", prev);
    __u32 delta = bpf_ktime_get_ns() - prev;
    bpf_map_delete_elem(&timing, &key);
    bpf_printk("stethoscope: read: delta: %u %d", delta, is_query_response);
    struct query_timing_t *timing =
        bpf_ringbuf_reserve(&query_timings, sizeof(struct query_timing_t), 0);
    if (timing == NULL) {
      return 0;
    }
    timing->delta = delta;
    if (conn) {
      timing->connection = *conn;
    } else {
      bpf_printk("stethoscope: read: conn is null");
    }
    bpf_ringbuf_submit(timing, 0);
    // bpf_ringbuf_submit(stack, 0);
  }
  return 0;
}

SEC("tp/syscalls/sys_enter_recvfrom")
int handle_recvfrom(struct trace_event_raw_sys_enter *ctx) {
  __u64 key = bpf_get_current_pid_tgid() >> 32;
  struct read_args args = {
      .fd = ctx->args[0],
      .buf = (char *)ctx->args[1],
      .size = ctx->args[2],
  };
  bpf_map_update_elem(&active_reads, &key, &args, BPF_ANY);
  return 0;
}

SEC("tp/syscalls/sys_exit_recvfrom")
int handle_exit_recvfrom(struct trace_event_raw_sys_exit *ctx) {
  __u64 key = bpf_get_current_pid_tgid() >> 32;
  struct read_args *args = bpf_map_lookup_elem(&active_reads, &key);
  if (args && ctx->ret > 0) {
    postgres_read(args->fd, args->buf, args->size, 0);
    bpf_map_delete_elem(&active_reads, &key);
  }
  return 0;
}

SEC("uprobe/SSL_read")
int BPF_UPROBE(ssl_read, void *ssl, void *buffer, int num) {
  bpf_printk("stethoscope: SSL_read: num: %d", num);
  struct ssl_st_v3_0_0 ssl_v3;
  if (bpf_probe_read_user(&ssl_v3, sizeof(ssl_v3), ssl) < 0) {
    bpf_printk("stethoscope: ssl_v3 not read");
    return 0;
  }
  struct bio_st_v3_0 rbio;
  if (bpf_probe_read(&rbio, sizeof(rbio), ssl_v3.rbio) < 0) {
    bpf_printk("stethoscope: rbio not read");
    return 0;
  }
  // we have to use the FULL pid/tgid as we're correlating an enter with exit on
  // the same thread
  __u64 key = bpf_get_current_pid_tgid();
  struct read_args args = {
      .fd = rbio.num,
      .size = num,
      .buf = buffer,
  };
  bpf_map_update_elem(&active_reads, &key, &args, BPF_ANY);
  return 0;
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ssl_ret_read) {
  int returnValue = PT_REGS_RC(ctx);
  __u64 key = bpf_get_current_pid_tgid();
  struct read_args *args = bpf_map_lookup_elem(&active_reads, &key);
  if (args && returnValue > 0) {
    bpf_printk("stethoscope: SSL_read: num: %d", returnValue);
    postgres_read(args->fd, args->buf, returnValue, 1);
    bpf_map_delete_elem(&active_reads, &key);
  }
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
