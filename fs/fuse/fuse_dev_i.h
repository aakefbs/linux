/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#ifndef _FS_FUSE_DEV_I_H
#define _FS_FUSE_DEV_I_H

#include "fuse_i.h"

/* Ordinary requests have even IDs, while interrupts IDs are odd */
#define FUSE_INT_REQ_BIT (1ULL << 0)
#define FUSE_REQ_ID_STEP (1ULL << 1)


struct fuse_copy_state {
	int write;
	struct fuse_req *req;
	struct iov_iter *iter;
	struct pipe_buffer *pipebufs;
	struct pipe_buffer *currbuf;
	struct pipe_inode_info *pipe;
	unsigned long nr_segs;
	struct page *pg;
	unsigned len;
	unsigned offset;
	unsigned move_pages:1, is_uring:1;
	struct {
		/* pointer into the ring buffer */
		char *buf;
		unsigned len;
		unsigned offset;
	} ring;
};


static inline void fuse_request_init(struct fuse_mount *fm, struct fuse_req *req)
{
	INIT_LIST_HEAD(&req->list);
	INIT_LIST_HEAD(&req->intr_entry);
	init_waitqueue_head(&req->waitq);
	refcount_set(&req->count, 1);
	__set_bit(FR_PENDING, &req->flags);
	req->fm = fm;
}

struct fuse_dev *fuse_get_dev(struct file *file);
void fuse_dev_end_requests(struct list_head *head);

void fuse_copy_init(struct fuse_copy_state *cs, int write,
			   struct iov_iter *iter);
int fuse_copy_args(struct fuse_copy_state *cs, unsigned numargs,
		   unsigned argpages, struct fuse_arg *args,
		   int zeroing);
void fuse_copy_finish(struct fuse_copy_state *cs);
int copy_out_args(struct fuse_copy_state *cs, struct fuse_args *args,
		  unsigned nbytes);

#endif


