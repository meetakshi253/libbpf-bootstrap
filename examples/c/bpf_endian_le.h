
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BPF_ENDIAN_LE__
#define __BPF_ENDIAN_LE__

#include <bpf/bpf_endian.h>

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define __bpf_le16_to_cpu(x)  (x)
# define __bpf_le32_to_cpu(x)  (x)
# define __bpf_le64_to_cpu(x)  (x)
# define __bpf_cpu_to_le16(x)  (x)
# define __bpf_cpu_to_le32(x)  (x)
# define __bpf_cpu_to_le64(x)  (x)
# define __bpf_constant_le16_to_cpu(x)  (x)
# define __bpf_constant_cpu_to_le16(x)  (x)
# define __bpf_constant_le32_to_cpu(x)  (x)
# define __bpf_constant_cpu_to_le32(x)  (x)
# define __bpf_constant_le64_to_cpu(x)  (x)
# define __bpf_constant_cpu_to_le64(x)  (x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __bpf_le16_to_cpu(x)  __builtin_bswap16(x)
#define __bpf_le32_to_cpu(x)  __builtin_bswap32(x)
#define __bpf_le64_to_cpu(x)  __builtin_bswap64(x)
#define __bpf_cpu_to_le16(x)  __builtin_bswap16(x)
#define __bpf_cpu_to_le32(x)  __builtin_bswap32(x)
#define __bpf_cpu_to_le64(x)  __builtin_bswap64(x)
#define __bpf_constant_le16_to_cpu(x)  ___bpf_swab16(x)
#define __bpf_constant_cpu_to_le16(x)  ___bpf_swab16(x)
#define __bpf_constant_le32_to_cpu(x)  ___bpf_swab32(x)
#define __bpf_constant_cpu_to_le32(x)  ___bpf_swab32(x)
#define __bpf_constant_le64_to_cpu(x)  ___bpf_swab64(x)
#define __bpf_constant_cpu_to_le64(x)  ___bpf_swab64(x)
#else
#error "Fix your compiler's __BYTE_ORDER__?!"
#endif /* __BYTE_ORDER__ */

#define bpf_le16_to_cpu(x)              \
    (__builtin_constant_p(x) ?		\
     __bpf_constant_le16_to_cpu(x) : __bpf_le16_to_cpu(x))
#define bpf_cpu_to_le16(x)              \
    (__builtin_constant_p(x) ?		\
     __bpf_constant_cpu_to_le16(x) : __bpf_cpu_to_le16(x))
#define bpf_le32_to_cpu(x)              \
    (__builtin_constant_p(x) ?		\
     __bpf_constant_le32_to_cpu(x) : __bpf_le32_to_cpu(x))
#define bpf_cpu_to_le32(x)              \
    (__builtin_constant_p(x) ?		\
     __bpf_constant_cpu_to_le32(x) : __bpf_cpu_to_le32(x))
#define bpf_le64_to_cpu(x)              \
    (__builtin_constant_p(x) ?		\
     __bpf_constant_le64_to_cpu(x) : __bpf_le64_to_cpu(x))
#define bpf_cpu_to_le64(x)              \
    (__builtin_constant_p(x) ?		\
     __bpf_constant_cpu_to_le64(x) : __bpf_cpu_to_le64(x))

#endif /* __BPF_ENDIAN_LE__ */