#include "vmlinux.h"

struct padding {};
typedef long (*padding_fn)();

// OpenSSL_1_0_2
struct ssl_st_v1_0_2 {
  __s32 version;
  __s32 type;
  struct padding *method; //  const SSL_METHOD *method;
  // ifndef OPENSSL_NO_BIO
  struct bio_st_v1 *rbio; // used by SSL_read
  struct bio_st_v1 *wbio; // used by SSL_write
};

struct bio_st_v1_0_2 {
  struct padding *method; // BIO_METHOD *method;
  padding_fn callback; // long (*callback) (struct bio_st *, int, const char *,
                       // int, long, long);
  char *cb_arg;        /* first argument for the callback */
  int init;
  int shutdown;
  int flags; /* extra storage */
  int retry_reason;
  int num; // fd
};

// OpenSSL_1_1_1
struct ssl_st_v1_1_1 {
  __s32 version;
  struct padding *method;     //  const SSL_METHOD *method;
  struct bio_st_v1_1_1 *rbio; // used by SSL_read
  struct bio_st_v1_1_1 *wbio; // used by SSL_write
};

struct bio_st_v1_1_1 {
  struct padding *method; // const BIO_METHOD *method;
  padding_fn callback; // long (*callback) (struct bio_st *, int, const char *,
                       // int, long, long);
  padding_fn callback_ex;
  char *cb_arg;
  int init;
  int shutdown;
  int flags;
  int retry_reason;
  int num; // fd
};

// openssl-3.0.0
struct ssl_st_v3_0_0 {
  __s32 version;
  struct padding *method; // const SSL_METHOD *method;
  /* used by SSL_read */
  struct bio_st_v3_0_0 *rbio;
  /* used by SSL_write */
  struct bio_st_v3_0_0 *wbio;
};

struct bio_st_v3_0 {
  struct padding *libctx; // OSSL_LIB_CTX *libctx;
  struct padding *method; // const BIO_METHOD *method;
  padding_fn callback;    // BIO_callback_fn callback;
  padding_fn callback_ex; // BIO_callback_fn_ex callback_ex;
  char *cb_arg;
  int init;
  int shutdown;
  int flags;
  int retry_reason;
  int num; // fd
  // void *ptr;
  // struct bio_st *next_bio;    /* used by filter BIOs */
  // struct bio_st *prev_bio;    /* used by filter BIOs */
  // CRYPTO_REF_COUNT references;
  // uint64_t num_read;
  // uint64_t num_write;
  // CRYPTO_EX_DATA ex_data;
  // CRYPTO_RWLOCK *lock;
};
