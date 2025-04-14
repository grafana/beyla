#ifndef __VMLINUX_H_PARENT_
#define __VMLINUX_H_PARENT_

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
#pragma clang diagnostic ignored "-Wpacked"
#pragma clang diagnostic ignored "-Wunaligned-access"

#if defined(__TARGET_ARCH_x86)

#include "vmlinux_amd64.h"

#elif defined(__TARGET_ARCH_arm64)

#include "vmlinux_arm64.h"

#endif /*__TARGET_ARCH_arm64*/

#pragma clang diagnostic pop

#endif /*__VMLINUX_H_PARENT_*/
