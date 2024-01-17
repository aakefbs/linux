/* SPDX-License-Identifier: GPL-2.0
 *
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>
 */

#ifndef _FS_FUSE_DEV_URING_I_H
#define _FS_FUSE_DEV_URING_I_H

#include "fuse_i.h"

/* Minimal async size with uring communication. Async is handled on a different
 * core and that has overhead, so the async queue is only used beginning
 * with a certain size - XXX should this be a tunable parameter?
 */
#define FUSE_URING_MIN_ASYNC_SIZE (16384)


void fuse_uring_end_requests(struct fuse_conn *fc);
int fuse_uring_queue_fuse_req(struct fuse_conn *fc, struct fuse_req *req);
int fuse_uring_configure(struct fuse_conn *fc, unsigned int qid,
			 struct fuse_uring_cfg *cfg);
void fuse_uring_ring_destruct(struct fuse_conn *fc);
int fuse_uring_mmap(struct file *filp, struct vm_area_struct *vma);
int fuse_uring_cmd(struct io_uring_cmd *cmd, unsigned int issue_flags);
void fuse_uring_stop_queues(struct fuse_conn *fc);
#endif





