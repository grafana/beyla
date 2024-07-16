#ifndef __ERRORS_H_
#define __ERRORS_H_

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef ERR_MSG_LEN
#define ERR_MSG_LEN 128
#endif

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH 32
#endif

typedef __u64 stack_trace_t[MAX_STACK_DEPTH];

typedef struct error_event {
    __u32 pid;
    __u32 cpu_id;
    char comm[TASK_COMM_LEN];
    __s32 ustack_sz;
    stack_trace_t ustack;
    u8 err_msg[ERR_MSG_LEN];
} error_event;

#endif /* __ERRORS_H_ */
