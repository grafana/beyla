#pragma once

// TODO: make this user-configurable and modify the value from the userspace when
// loading the maps with the Cilium library
#define MAX_CONCURRENT_REQUESTS 10000 // 10000 requests per second max for a single traced process
// 10 * MAX_CONCURRENT_REQUESTS total ongoing requests, for maps shared among multiple tracers, e.g. pinned maps
#define MAX_CONCURRENT_SHARED_REQUESTS 30000
