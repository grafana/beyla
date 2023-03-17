#define MAX_MSG_SIZE 1024

struct syscall_write_event_t
{
  // We split attributes into a separate struct, because BPF gets upset if you do lots of
  // size arithmetic. This makes it so that it's attributes followed by message.
  struct attr_t
  {
    int event_type;
    unsigned long fd;
    int bytes;
    unsigned long ts;
    unsigned long ssl_corr_id;
    int msg_size_or_type;
  } attr;
  char msg[MAX_MSG_SIZE];
};

// event types
const int kEventTypeSyscallAddrEvent = 1;
const int kEventTypeSyscallWriteEvent = 2;
const int kEventTypeSyscallCloseEvent = 3;
const int kEventTypeSyscallReadEvent = 4;
const int kEventTypeSyscallReadAndInitEvent = 5;
const int kEventTypeSyscallPeerNameEvent = 6;


// OPENSSL struct to offset , via kern/README.md
typedef long (*unused_fn)();

struct unused {};

struct ssl_st_inner {
    int type;
};

struct BIO {
    const struct unused* libctx;
    const struct unused* method;
    unused_fn callback;
    unused_fn callback_ex;
    char* cb_arg; /* first argument for the callback */
    int init;
    int shutdown;
    int flags; /* extra storage */
    int retry_reason;
    int num;
};

struct ssl_st {
    struct ssl_st_inner* ssl;
    int version;
    struct BIO* rbio;  // used by SSL_read
    struct BIO* wbio;  // used by SSL_write
};

