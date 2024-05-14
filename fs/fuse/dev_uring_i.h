/* SPDX-License-Identifier: GPL-2.0
 *
 * FUSE: Filesystem in Userspace
 * Copyright (c) 2023-2024 DataDirect Networks.
 */

#ifndef _FS_FUSE_DEV_URING_I_H
#define _FS_FUSE_DEV_URING_I_H

#include "fuse_i.h"
#include "linux/compiler_types.h"
#include "linux/rbtree_types.h"

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

void fuse_uring_abort_end_requests(struct fuse_ring *ring);
int fuse_uring_conn_cfg(struct fuse_ring *ring, struct fuse_ring_config *rcfg);
int fuse_uring_queue_cfg(struct fuse_ring *ring,
			 struct fuse_ring_queue_config *qcfg);
void fuse_uring_ring_destruct(struct fuse_ring *ring);
int fuse_uring_mmap(struct file *filp, struct vm_area_struct *vma);
int fuse_uring_cmd(struct io_uring_cmd *cmd, unsigned int issue_flags);
void fuse_uring_stop_queues(struct fuse_ring *ring);

#ifdef CONFIG_FUSE_IO_URING

int fuse_uring_queue_fuse_req(struct fuse_conn *fc, struct fuse_req *req);

static inline void fuse_uring_conn_init(struct fuse_ring *ring,
					struct fuse_conn *fc)
{
	ring->fc = fc;
	fuse_conn_get(fc);
	init_waitqueue_head(&ring->stop_waitq);
	mutex_init(&ring->start_stop_lock);
	ring->mem_buf_map = RB_ROOT;
}

static inline void fuse_uring_conn_destruct(struct fuse_conn *fc)
{
	struct fuse_ring *ring = fc->ring;

	if (ring == NULL)
		return;

	fuse_uring_ring_destruct(ring);
	mutex_destroy(&ring->start_stop_lock);

	fuse_conn_put(ring->fc);
	ring->fc = NULL;

	kfree(ring);
}

static inline struct fuse_ring_queue *fuse_uring_get_queue(struct fuse_ring *ring,
							   int qid)
{
	char *ptr = (char *)ring->queues;

	if (unlikely(qid > ring->nr_queues)) {
		WARN_ON(1);
		qid = 0;
	}

	return (struct fuse_ring_queue *)(ptr + qid * ring->queue_size);
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
	return fc->ring && fc->ring->per_core_queue;
}

static inline bool fuse_uring_ready(struct fuse_conn *fc)
{

	return fc->ring && fc->ring->ready;
}

static inline void fuse_uring_abort(struct fuse_conn *fc)
{
	struct fuse_ring *ring = fc->ring;

	if (ring == NULL)
		return;

	if (ring->configured && !ring->all_queues_stopped) {
		fuse_uring_abort_end_requests(ring);
		fuse_uring_stop_queues(ring);
	}
}

static inline void fuse_uring_set_stopped_queues(struct fuse_ring *ring)
{
	int qid;

	for (qid = 0; qid < ring->nr_queues; qid++) {
		struct fuse_ring_queue *queue = fuse_uring_get_queue(ring, qid);

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
	if (fc->ring == NULL)
		return;

	fc->ring->ready = false;

	fuse_uring_set_stopped_queues(fc->ring);
}

static inline void
fuse_uring_wait_stopped_queues(struct fuse_conn *fc)
{
	struct fuse_ring *ring = fc->ring;

	if (ring && ring->configured)
		wait_event(ring->stop_waitq,
			   READ_ONCE(ring->all_queues_stopped) == true);
}

#else /* CONFIG_FUSE_IO_URING */

static inline void fuse_uring_conn_init(struct fuse_ring *ring,
					struct fuse_conn *fc)
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

static inline int fuse_uring_queue_fuse_req(struct fuse_conn *fc, struct fuse_req *req)
{
	return -ENODEV;
}

#endif /* CONFIG_FUSE_IO_URING */

#endif /* _FS_FUSE_DEV_URING_I_H */
