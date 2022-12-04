/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#ifndef _FS_FUSE_DEV_URING_I_H
#define _FS_FUSE_DEV_URING_I_H

#include "fuse_i.h"

int fuse_dev_uring_write_to_ring(struct fuse_ring_req *ring_req);
void fuse_dev_uring_read_from_ring(struct fuse_dev *fud,
			  struct fuse_ring_req *ring_req);

void fuse_uring_start_destruct(struct fuse_conn *fc);
int fuse_dev_uring_ioctl(struct file *file, struct fuse_uring_cfg *cfg);

struct fuse_req *fuse_request_alloc_ring(struct fuse_mount *fm, gfp_t flags,
					 bool for_background);

void fuse_dev_uring_req_release(struct fuse_req *req);

int fuse_dev_uring(struct io_uring_cmd *cmd, unsigned int issue_flags);
int fuse_dev_ring_mmap(struct file *filp, struct vm_area_struct *vma);


#endif





