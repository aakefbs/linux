/* SPDX-License-Identifier: GPL-2.0
 *
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>
 */

#ifndef _FS_FUSE_DEV_I_H
#define _FS_FUSE_DEV_I_H

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
	unsigned int len;
	unsigned int offset;
	unsigned int move_pages:1, is_uring:1;
	struct {
		/* pointer into the ring buffer */
		char *buf;

		/* for copy to the ring request buffer, the buffer size - must
		 * not be exceeded, for copy from the ring request buffer,
		 * the size filled in by user space
		 */
		unsigned int buf_sz;

		/* offset within buf while it is copying from/to the buf */
		unsigned int offset;
	} ring;
};

static inline struct fuse_dev *fuse_get_dev(struct file *file)
{
	/*
	 * Lockless access is OK, because file->private data is set
	 * once during mount and is valid until the file is released.
	 */
	return READ_ONCE(file->private_data);
}

void fuse_dev_end_requests(struct list_head *head);

void fuse_copy_init(struct fuse_copy_state *cs, int write,
			   struct iov_iter *iter);
int fuse_copy_args(struct fuse_copy_state *cs, unsigned int numargs,
		   unsigned int argpages, struct fuse_arg *args,
		   int zeroing);
int fuse_copy_out_args(struct fuse_copy_state *cs, struct fuse_args *args,
		       unsigned int nbytes);

#endif


