#ifndef MAP_SIZING_H
#define MAP_SIZING_H

// TODO: make this user-configurable and modify the value from the userspace when
// loading the maps with the Cilium library
#define MAX_CONCURRENT_REQUESTS 1000 // 1000 requests per second max for a single traced process
#define MAX_CONCURRENT_SHARED_REQUESTS 10000 // 10 * MAX_CONCURRENT_REQUESTS total ongoing requests, for maps shared among multiple tracers, e.g. pinned maps

#endif