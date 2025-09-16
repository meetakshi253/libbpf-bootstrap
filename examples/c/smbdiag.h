/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __SMBDIAG_H
#define __SMBDIAG_H

#include "aoddiag.h"

#define MAX_SMB_COMMANDS	20

#define SMBSLOWER	 		0

struct smb_partial_event {
	unsigned long long mid;
	unsigned short smbcommand;
	union metrics metric;
};

#endif