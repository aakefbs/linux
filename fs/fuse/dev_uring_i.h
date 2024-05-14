/* SPDX-License-Identifier: GPL-2.0
 *
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>
 */

#ifndef _FS_FUSE_DEV_URING_I_H
#define _FS_FUSE_DEV_URING_I_H

#include "fuse_i.h"
#include "linux/compiler_types.h"
#include "linux/spinlock.h"

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

void fuse_uring_abort_end_requests(struct fuse_conn *fc);
int fuse_uring_queue_fuse_req(struct fuse_conn *fc, struct fuse_req *req);
int fuse_uring_conn_cfg(struct fuse_conn *fc, struct fuse_ring_config *rcfg);
int fuse_uring_queue_cfg(struct fuse_conn *fc,
			 struct fuse_ring_queue_config *qcfg);
void fuse_uring_ring_destruct(struct fuse_conn *fc);
int fuse_uring_mmap(struct file *filp, struct vm_area_struct *vma);
int fuse_uring_cmd(struct io_uring_cmd *cmd, unsigned int issue_flags);
void fuse_uring_stop_queues(struct fuse_conn *fc);

#ifdef CONFIG_FUSE_IO_URING

static inline void fuse_uring_conn_init(struct fuse_conn *fc)
{
	init_waitqueue_head(&fc->ring.stop_waitq);
	mutex_init(&fc->ring.start_stop_lock);
	fc->ring.mem_buf_map = RB_ROOT;
}

static inline void fuse_uring_conn_destruct(struct fuse_conn *fc)
{
	fuse_uring_ring_destruct(fc);
	mutex_destroy(&fc->ring.start_stop_lock);
}

static inline struct fuse_ring_queue *fuse_uring_get_queue(struct fuse_conn *fc,
							   int qid)
{
	char *ptr = (char *)fc->ring.queues;

	if (unlikely(qid > fc->ring.nr_queues)) {
		WARN_ON(1);
		qid = 0;
	}

	return (struct fuse_ring_queue *)(ptr + qid * fc->ring.queue_size);
}

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

static inline bool fuse_per_core_queue(struct fuse_conn *fc)
{
	return fc->ring.per_core_queue;
}

static inline bool fuse_uring_ready(struct fuse_conn *fc)
{
	return fc->ring.ready;
}

static inline void fuse_uring_abort(struct fuse_conn *fc)
{
	if (fc->ring.configured && !fc->ring.all_queues_stopped) {
		fuse_uring_abort_end_requests(fc);
		fuse_uring_stop_queues(fc);
	}
}

static inline void fuse_uring_set_stopped_queues(struct fuse_conn *fc)
{
	int qid;

	for (qid = 0; qid < fc->ring.nr_queues; qid++) {
		struct fuse_ring_queue *queue = fuse_uring_get_queue(fc, qid);

		spin_lock(&queue->lock);
		queue->stopped = 1;
		spin_unlock(&queue->lock);
	}
}

/*
 *  Set per queue aborted flag
 */
static inline void fuse_uring_set_stopped(struct fuse_conn *fc)
__must_hold(fc->lock)
{
	fc->ring.ready = false;

	fuse_uring_set_stopped_queues(fc);
}

static inline void
fuse_uring_wait_stopped_queues(struct fuse_conn *fc)
{
	if (fc->ring.configured)
		wait_event(fc->ring.stop_waitq,
			   READ_ONCE(fc->ring.all_queues_stopped) == true);
}

#else /* CONFIG_FUSE_IO_URING */

static inline void fuse_uring_conn_init(struct fuse_conn *fc)
{
	return;
}

static inline bool fuse_per_core_queue(struct fuse_conn *fc)
{
	return false;
}
static inline bool fuse_uring_ready(struct fuse_conn *fc)
{
	return false;
}

static inline void fuse_uring_set_stopped(struct fuse_conn *fc)
{
	return;
}

static inline void fuse_uring_abort(struct fuse_conn *fc)
{
	return;
}

static inline void fuse_uring_wait_stopped_queues(struct fuse_conn *fc)
{
	return;
}

static inline void fuse_uring_conn_destruct(struct fuse_conn *fc)
{
	return;
}

#endif /* CONFIG_FUSE_IO_URING */

#endif /* _FS_FUSE_DEV_URING_I_H */
