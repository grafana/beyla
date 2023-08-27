// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef _GO_TYPES_H
#define _GO_TYPES_H

#include "bpf_helpers.h"

#define MAX_REALLOCATION 400
#define MAX_DATA_SIZE 400

struct go_string
{
    char *str;
    s64 len;
};

struct go_slice
{
    void *array;
    s64 len;
    s64 cap;
};

struct go_slice_user_ptr
{
    void *array;
    void *len;
    void *cap;
};

struct go_iface
{
    void *tab;
    void *data;
};

struct map_bucket {
    char tophash[8];
    struct go_string keys[8];
    struct go_slice values[8];
    void *overflow;
};

#endif
