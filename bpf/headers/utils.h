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

#ifndef __UTILS_H__
#define __UTILS_H__

#include "common.h"
#include "bpf_helpers.h"

void *get_argument_by_reg(struct pt_regs *ctx, int index)
{
    switch (index)
    {
    case 1:
        return (void *)(ctx->rax);
    case 2:
        return (void *)(ctx->rbx);
    case 3:
        return (void *)(ctx->rcx);
    case 4:
        return (void *)(ctx->rdi);
    case 5:
        return (void *)(ctx->rsi);
    case 6:
        return (void *)(ctx->r8);
    case 7:
        return (void *)(ctx->r9);
    case 8:
        return (void *)(ctx->r10);
    case 9:
        return (void *)(ctx->r11);
    default:
        return NULL;
    }
}

// In x86, current goroutine is pointed by r14, according to
// https://go.googlesource.com/go/+/refs/heads/dev.regabi/src/cmd/compile/internal-abi.md#amd64-architecture
inline void *get_goroutine_address(struct pt_regs *ctx) {
    return (void *)(ctx->r14);
}

#endif /* __UTILS_H__ */
