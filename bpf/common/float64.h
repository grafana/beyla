#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

// The following code is a software implementation of floating point subtraction
// since eBPF doesn't support floating point instructions in the BPF instruction
// set. The code was adapted from the SoftFP Library by Fabrice Bellard
// https://bellard.org/softfp/ (Licensed under MIT), with a lot of things removed
// related to rounding, floating point denormals etc. The main need for this
// library code is to be able to read the NodeJS asyncID, which just like any
// other JavaScript numbers are stored as float64 in memory.

typedef long int int_fast16_t;

static const uint8_t count_leading_zeros_high[] = {
    8, 7, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static __always_inline uint64_t extract_float64_frac(uint64_t a) {
    return a & 0x000FFFFFFFFFFFFF;
}

static __always_inline int_fast16_t extract_float64_exp(uint64_t a) {
    return (a >> 52) & 0x7FF;
}

static __always_inline char extract_float64_sign(uint64_t a) {
    return a >> 63;
}

static __always_inline uint64_t pack_float64(uint8_t z_sign, int_fast16_t z_exp, uint64_t z_sig) {
    return (((uint64_t)z_sign) << 63) + (((uint64_t)z_exp) << 52) + z_sig;
}

static __always_inline void shift64_right_jamming(uint64_t a, int_fast16_t count, uint64_t *zPtr) {
    uint64_t z;

    if (count == 0) {
        z = a;
    } else if (count < 64) {
        z = (a >> count) | ((a << ((-count) & 63)) != 0);
    } else {
        z = (a != 0);
    }
    *zPtr = z;
}

static __always_inline uint8_t count_leading_zeros32(uint32_t a) {
    uint8_t shift_count = 0;

    if (a < 0x10000) {
        shift_count += 16;
        a <<= 16;
    }
    if (a < 0x1000000) {
        shift_count += 8;
        a <<= 8;
    }
    shift_count += count_leading_zeros_high[a >> 24];
    return shift_count;
}

static __always_inline uint8_t count_leading_zeros64(uint64_t a) {
    uint8_t shift_count = 0;

    if (a < (((uint64_t)1) << 32)) {
        shift_count += 32;
    } else {
        a >>= 32;
    }
    shift_count += count_leading_zeros32(a);
    return shift_count;
}

static __always_inline uint64_t normalize_and_pack_float64(uint8_t z_sign,
                                                           int_fast16_t z_exp,
                                                           uint64_t z_sig) {
    uint8_t shift_count = count_leading_zeros64(z_sig) - 1;

    z_sig = z_sig << shift_count;
    z_sig = z_sig >> 10;
    if (z_sig == 0) {
        z_exp = 0;
    }

    return pack_float64(z_sign, z_exp - shift_count, z_sig);
}

static __always_inline uint64_t sub_float64(uint64_t a, uint64_t b, char z_sign) {
    int_fast16_t a_exp;
    int_fast16_t b_exp;
    int_fast16_t z_exp;
    uint64_t a_sig;
    uint64_t b_sig;
    uint64_t z_sig;
    int_fast16_t exp_diff;

    a_sig = extract_float64_frac(a);
    a_exp = extract_float64_exp(a);
    b_sig = extract_float64_frac(b);
    b_exp = extract_float64_exp(b);
    exp_diff = a_exp - b_exp;
    a_sig <<= 10;
    b_sig <<= 10;

    if (0 < exp_diff) {
        goto a_exp_bigger;
    }

    if (exp_diff < 0) {
        goto b_exp_bigger;
    }

    if (a_exp == 0x7FF) {
        return -1;
    }

    if (a_exp == 0) {
        a_exp = 1;
        b_exp = 1;
    }

    if (b_sig < a_sig) {
        goto a_bigger;
    }

    if (a_sig < b_sig) {
        goto b_bigger;
    }

    return pack_float64(0, 0, 0);
b_exp_bigger:
    if (b_exp == 0x7FF) {
        if (b_sig) {
            return -1;
        }
        return pack_float64(z_sign ^ 1, 0x7FF, 0);
    }

    if (a_exp == 0) {
        ++exp_diff;
    } else {
        a_sig |= 0x4000000000000000;
    }

    shift64_right_jamming(a_sig, -exp_diff, &a_sig);
    b_sig |= 0x4000000000000000;
b_bigger:
    z_sig = b_sig - a_sig;
    z_exp = b_exp;
    z_sign ^= 1;

    goto normalize_and_pack;
a_exp_bigger:
    if (a_exp == 0x7FF) {
        if (a_sig) {
            return -1;
        }
        return a;
    }

    if (b_exp == 0) {
        --exp_diff;
    } else {
        b_sig |= 0x4000000000000000;
    }

    shift64_right_jamming(b_sig, exp_diff, &b_sig);
    a_sig |= 0x4000000000000000;
a_bigger:
    z_sig = a_sig - b_sig;
    z_exp = a_exp;
normalize_and_pack:
    --z_exp;

    return normalize_and_pack_float64(z_sign, z_exp, z_sig);
}
