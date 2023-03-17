// Copyright 2020 Joshua J Baker. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

#ifndef G_HASHMAP_H
#define G_HASHMAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct hashmap;

struct hashmap *g_hashmap_new(size_t elsize, size_t cap, 
                            uint64_t seed0, uint64_t seed1,
                            uint64_t (*hash)(const void *item, 
                                             uint64_t seed0, uint64_t seed1),
                            int (*compare)(const void *a, const void *b, 
                                           void *udata),
                            void (*elfree)(void *item),
                            void *udata);
struct hashmap *g_hashmap_new_with_allocator(
                            void *(*malloc)(size_t), 
                            void *(*realloc)(void *, size_t), 
                            void (*free)(void*),
                            size_t elsize, size_t cap, 
                            uint64_t seed0, uint64_t seed1,
                            uint64_t (*hash)(const void *item, 
                                             uint64_t seed0, uint64_t seed1),
                            int (*compare)(const void *a, const void *b, 
                                           void *udata),
                            void (*elfree)(void *item),
                            void *udata);
void g_hashmap_free(struct hashmap *map);
void g_hashmap_clear(struct hashmap *map, bool update_cap);
size_t g_hashmap_count(struct hashmap *map);
bool g_hashmap_oom(struct hashmap *map);
void *g_hashmap_get(struct hashmap *map, const void *item);
void *g_hashmap_set(struct hashmap *map, const void *item);
void *g_hashmap_delete(struct hashmap *map, void *item);
void *g_hashmap_probe(struct hashmap *map, uint64_t position);
bool g_hashmap_scan(struct hashmap *map,
                  bool (*iter)(const void *item, void *udata), void *udata);
bool g_hashmap_iter(struct hashmap *map, size_t *i, void **item);

uint64_t g_hashmap_sip(const void *data, size_t len, 
                     uint64_t seed0, uint64_t seed1);
uint64_t g_hashmap_murmur(const void *data, size_t len, 
                        uint64_t seed0, uint64_t seed1);


// DEPRECATED: use `hashmap_new_with_allocator`
void g_hashmap_set_allocator(void *(*malloc)(size_t), void (*free)(void*));

#endif
