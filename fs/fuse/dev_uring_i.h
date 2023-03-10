/* SPDX-License-Identifier: GPL-2.0
 *
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>
 */

#ifndef _FS_FUSE_DEV_URING_I_H
#define _FS_FUSE_DEV_URING_I_H

#include "fuse_i.h"

void fuse_uring_end_requests(struct fuse_conn *fc);
void fuse_uring_ring_destruct(struct fuse_conn *fc);
int fuse_uring_ioctl(struct file *file, struct fuse_uring_cfg *cfg);
#endif





