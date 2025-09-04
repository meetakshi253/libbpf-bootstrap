/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __NFSDIAG_H
#define __NFSDIAG_H

#include "aoddiag.h"

#define MAX_NFS_COMMANDS        70

#define NFSSLOWER               10

#define NFS4_READ               0
#define NFS4_GETATTR            1
#define NFS4_LOOKUP             2
#define NFS4_ACCESS             3
#define NFS4_OPEN               4
#define NFS4_CLOSE              5

#define NFS_ATTR_FATTR_FILEID   (1U << 11)

struct nfs_partial_event {
    int nfscommand;
	union metrics metric;
};

#endif /* __NFSDIAG_H */