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

#if IS_ENABLED(CONFIG_FUSE_IO_URING)

/* IORING_MAX_ENTRIES */
#define FUSE_URING_MAX_QUEUE_DEPTH 32768

enum fuse_ring_req_state {

	/* request is basially initialized */
	FRRS_INIT,

	/* The ring request waits for a new fuse request */
	FRRS_WAIT,

	/* The ring req got assigned a fuse req */
	FRRS_FUSE_REQ,

	/* request is in or on the way to user space */
	FRRS_USERSPACE,

	/* request is released */
	FRRS_FREED,
};

struct fuse_uring_mbuf {
	struct rb_node rb_node;
	void *kbuf; /* kernel allocated ring request buffer */
	void *ubuf; /* mmaped address */
};

/** A fuse ring entry, part of the ring queue */
struct fuse_ring_ent {
	/*
	 * pointer to kernel request buffer, userspace side has direct access
	 * to it through the mmaped buffer
	 */
	struct fuse_ring_req *rreq;

	/* the ring queue that owns the request */
	struct fuse_ring_queue *queue;

	struct io_uring_cmd *cmd;

	struct list_head list;

	/*
	 * state the request is currently in
	 * (enum fuse_ring_req_state)
	 */
	unsigned long state;

	/* array index in the ring-queue */
	int tag;

	/* is this an async or sync entry */
	unsigned int async : 1;

	struct fuse_req *fuse_req; /* when a list request is handled */
};

struct fuse_ring_queue {
	/* task belonging to the current queue */
	struct task_struct *server_task;

	/*
	 * back pointer to the main fuse uring structure that holds this
	 * queue
	 */
	struct fuse_ring *ring;

	/* issue flags when running in io-uring task context */
	unsigned int uring_cmd_issue_flags;

	int qid;

	/*
	 * available number of sync requests,
	 * loosely bound to fuse foreground requests
	 */
	int nr_req_sync;

	/*
	 * available number of async requests
	 * loosely bound to fuse background requests
	 */
	int nr_req_async;

	/* queue lock, taken when any value in the queue changes _and_ also
	 * a ring entry state changes.
	 */
	spinlock_t lock;

	/* per queue memory buffer that is divided per request */
	char *queue_req_buf;

	/* fuse fg/bg request types */
	struct list_head async_fuse_req_queue;
	struct list_head sync_fuse_req_queue;

	/* available ring entries (struct fuse_ring_ent) */
	struct list_head async_ent_avail_queue;
	struct list_head sync_ent_avail_queue;

	struct list_head ent_in_userspace;

	unsigned int configured : 1;
	unsigned int stopped : 1;

	/* size depends on queue depth */
	struct fuse_ring_ent ring_ent[] ____cacheline_aligned_in_smp;
};

/**
 * Describes if uring is for communication and holds alls the data needed
 * for uring communication
 */
struct fuse_ring {
	/* back pointer to fuse_conn */
	struct fuse_conn *fc;

	/* number of ring queues */
	size_t nr_queues;

	/* number of entries per queue */
	size_t queue_depth;

	/* max arg size for a request */
	size_t req_arg_len;

	/* req_arg_len + sizeof(struct fuse_req) */
	size_t req_buf_sz;

	/* max number of background requests per queue */
	size_t max_nr_async;

	/* max number of foreground requests */
	size_t max_nr_sync;

	/* size of struct fuse_ring_queue + queue-depth * entry-size */
	size_t queue_size;

	/* buffer size per queue, that is used per queue entry */
	size_t queue_buf_size;

	/* Used to release the ring on stop */
	atomic_t queue_refs;

	/* Hold ring requests */
	struct fuse_ring_queue *queues;

	/* number of initialized queues with the ioctl */
	int nr_queues_ioctl_init;

	/* number of SQEs initialized */
	atomic_t nr_sqe_init;

	/* one queue per core or a single queue only ? */
	unsigned int per_core_queue : 1;

	/* Is the ring completely iocl configured */
	unsigned int configured : 1;

	/* numa aware memory allocation */
	unsigned int numa_aware : 1;

	/* Is the ring read to take requests */
	unsigned int ready : 1;

	/*
	 * Log ring entry states onces on stop when entries cannot be
	 * released
	 */
	unsigned int stop_debug_log : 1;

	struct mutex start_stop_lock;

	wait_queue_head_t stop_waitq;

	/* mmaped ring entry memory buffers, mmaped values is the key,
	 * kernel pointer is the value
	 */
	struct rb_root mem_buf_map;

	struct delayed_work stop_work;
	unsigned long stop_time;
};

void fuse_uring_abort_end_requests(struct fuse_ring *ring);
int fuse_uring_conn_cfg(struct fuse_ring *ring, struct fuse_ring_config *rcfg);
int fuse_uring_mmap(struct file *filp, struct vm_area_struct *vma);
int fuse_uring_queue_cfg(struct fuse_ring *ring,
			 struct fuse_ring_queue_config *qcfg);
void fuse_uring_ring_destruct(struct fuse_ring *ring);
int fuse_uring_cmd(struct io_uring_cmd *cmd, unsigned int issue_flags);

static inline void fuse_uring_conn_init(struct fuse_ring *ring,
					struct fuse_conn *fc)
{
	/* no reference on fc as ring and fc have to be destructed together */
	ring->fc = fc;
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

	WRITE_ONCE(fc->ring, NULL);
	kfree(ring);
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

static inline struct fuse_ring_queue *
fuse_uring_get_queue(struct fuse_ring *ring, int qid)
{
	char *ptr = (char *)ring->queues;

	if (unlikely(qid > ring->nr_queues)) {
		WARN_ON(1);
		qid = 0;
	}

	return (struct fuse_ring_queue *)(ptr + qid * ring->queue_size);
}

static inline bool fuse_uring_configured(struct fuse_conn *fc)
{
	if (READ_ONCE(fc->ring) != NULL && fc->ring->configured)
		return true;

	return false;
}

static inline bool fuse_per_core_queue(struct fuse_conn *fc)
{
	return fc->ring && fc->ring->per_core_queue;
}

#else /* CONFIG_FUSE_IO_URING */

struct fuse_ring;

static inline void fuse_uring_conn_init(struct fuse_ring *ring,
					struct fuse_conn *fc)
{
}

static inline void fuse_uring_conn_destruct(struct fuse_conn *fc)
{
}

static inline bool fuse_uring_configured(struct fuse_conn *fc)
{
	return false;
}

static inline bool fuse_per_core_queue(struct fuse_conn *fc)
{
	return false;
}


#endif /* CONFIG_FUSE_IO_URING */

#endif /* _FS_FUSE_DEV_URING_I_H */
