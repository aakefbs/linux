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

struct fuse_uring_mbuf {
	struct rb_node rb_node;
	void *kbuf; /* kernel allocated ring request buffer */
	void *ubuf; /* mmaped address */
};

void fuse_uring_end_requests(struct fuse_conn *fc);
int fuse_uring_queue_fuse_req(struct fuse_conn *fc, struct fuse_req *req);
int fuse_uring_conn_cfg(struct fuse_conn *fc,
			struct fuse_ring_config *rcfg);
int fuse_uring_queue_cfg(struct fuse_conn *fc,
			 struct fuse_ring_queue_config *qcfg);
void fuse_uring_ring_destruct(struct fuse_conn *fc);
int fuse_uring_mmap(struct file *filp, struct vm_area_struct *vma);
int fuse_uring_cmd(struct io_uring_cmd *cmd, unsigned int issue_flags);
void fuse_uring_stop_queues(struct fuse_conn *fc);



static inline int fuse_uring_current_nodeid(void)
{
	int cpu;
	const struct cpumask *proc_mask = current->cpus_ptr;

	cpu = cpumask_first(proc_mask);

	return cpu_to_node(cpu);
}

static inline int fuse_uring_rb_tree_buf_cmp(const void *key,
					     const struct rb_node *node)
{
	const struct fuse_uring_mbuf *entry =
		rb_entry(node, struct fuse_uring_mbuf, rb_node);

	if (key == entry->ubuf)
		return 0;

	return (unsigned long)key < (unsigned long)entry->ubuf ? -1 : 1;
}

static inline bool fuse_uring_rb_tree_buf_less(struct rb_node *node1,
					       const struct rb_node *node2)
{
	const struct fuse_uring_mbuf *entry1 =
		rb_entry(node1, struct fuse_uring_mbuf, rb_node);

	return fuse_uring_rb_tree_buf_cmp(entry1->ubuf, node2) < 0;
}



#endif
