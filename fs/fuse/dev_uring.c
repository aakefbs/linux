// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>
 */

#include "fuse_i.h"
#include "fuse_dev_i.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/sched/signal.h>
#include <linux/uio.h>
#include <linux/miscdevice.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/pipe_fs_i.h>
#include <linux/swap.h>
#include <linux/splice.h>
#include <linux/sched.h>
#include <linux/io_uring.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/io_uring.h>
#include <linux/topology.h>

static bool __read_mostly enable_uring;
module_param(enable_uring, bool, 0644);
MODULE_PARM_DESC(enable_uring,
	"Enable uring userspace communication through uring.");

static struct fuse_ring_queue *
fuse_uring_get_queue(struct fuse_conn *fc, int qid)
{
	char *ptr = (char *)fc->ring.queues;

	if (unlikely(qid > fc->ring.nr_queues)) {
		WARN_ON(1);
		qid = 0;
	}

	return (struct fuse_ring_queue *)(ptr + qid * fc->ring.queue_size);
}

/* Abort all list queued request on the given ring queue */
static void fuse_uring_end_queue_requests(struct fuse_ring_queue *queue)
{
	spin_lock(&queue->lock);
	queue->aborted = 1;
	fuse_dev_end_requests(&queue->fg_queue);
	fuse_dev_end_requests(&queue->bg_queue);
	spin_unlock(&queue->lock);
}

void fuse_uring_end_requests(struct fuse_conn *fc)
{
	int qid;

	for (qid = 0; qid < fc->ring.nr_queues; qid++) {
		struct fuse_ring_queue *queue =
			fuse_uring_get_queue(fc, qid);

		if (!queue->configured)
			continue;

		fuse_uring_end_queue_requests(queue);
	}
}

/**
 * use __vmalloc_node_range() (needs to be
 * exported?) or add a new (exported) function vm_alloc_user_node()
 */
static char *fuse_uring_alloc_queue_buf(int size, int node)
{
	char *buf;

	if (size <= 0) {
		pr_info("Invalid queue buf size: %d.\n", size);
		return ERR_PTR(-EINVAL);
	}

	buf = vmalloc_node_user(size, node);
	return buf ? buf : ERR_PTR(-ENOMEM);
}

/**
 * Ring setup for this connection
 */
static int fuse_uring_conn_cfg(struct fuse_conn *fc,
			       struct fuse_uring_cfg *cfg)
__must_hold(fc->ring.stop_waitq.lock)
{
	size_t queue_sz;

	if (cfg->nr_queues == 0) {
		pr_info("zero number of queues is invalid.\n");
		return -EINVAL;
	}

	if (cfg->nr_queues > 1 &&
	    cfg->nr_queues != num_present_cpus()) {
		pr_info("nr-queues (%d) does not match nr-cores (%d).\n",
			cfg->nr_queues, num_present_cpus());
		return -EINVAL;
	}

	if (cfg->qid > cfg->nr_queues) {
		pr_info("qid (%d) exceeds number of queues (%d)\n",
			cfg->qid, cfg->nr_queues);
		return -EINVAL;
	}

	if (cfg->req_arg_len < FUSE_RING_MIN_IN_OUT_ARG_SIZE) {
		pr_info("Per req buffer size too small (%d), min: %d\n",
			cfg->req_arg_len, FUSE_RING_MIN_IN_OUT_ARG_SIZE);
		return -EINVAL;
	}

	if (unlikely(fc->ring.queues)) {
		WARN_ON(1);
		return -EINVAL;
	}

	fc->ring.daemon = current;
	get_task_struct(fc->ring.daemon);

	fc->ring.nr_queues = cfg->nr_queues;
	fc->ring.per_core_queue = cfg->nr_queues > 1;

	fc->ring.max_fg = cfg->fg_queue_depth;
	fc->ring.max_bg = cfg->bg_queue_depth;
	fc->ring.queue_depth = cfg->fg_queue_depth + cfg->bg_queue_depth;

	fc->ring.req_arg_len = cfg->req_arg_len;
	fc->ring.req_buf_sz =
		round_up(sizeof(struct fuse_ring_req) + fc->ring.req_arg_len,
			 PAGE_SIZE);

	/* verified during mmap that kernel and userspace have the same
	 * buffer size
	 */
	fc->ring.queue_buf_size = fc->ring.req_buf_sz * fc->ring.queue_depth;

	queue_sz = sizeof(*fc->ring.queues) +
			fc->ring.queue_depth * sizeof(struct fuse_ring_ent);
	fc->ring.queues = kcalloc(cfg->nr_queues, queue_sz, GFP_KERNEL);
	if (!fc->ring.queues)
		return -ENOMEM;
	fc->ring.queue_size = queue_sz;

	fc->ring.queue_refs = 0;

	return 0;
}

static int fuse_uring_queue_cfg(struct fuse_conn *fc, unsigned int qid,
				unsigned int node_id)
__must_hold(fc->ring.stop_waitq.lock)
{
	int tag;
	struct fuse_ring_queue *queue;
	char *buf;

	if (qid >= fc->ring.nr_queues) {
		pr_info("fuse ring queue config: qid=%u >= nr-queues=%zu\n",
			qid, fc->ring.nr_queues);
		return -EINVAL;
	}
	queue = fuse_uring_get_queue(fc, qid);

	if (queue->configured) {
		pr_info("fuse ring qid=%u already configured!\n", qid);
		return -EALREADY;
	}

	queue->qid = qid;
	queue->fc = fc;
	queue->req_fg = 0;
	bitmap_zero(queue->req_avail_map, fc->ring.queue_depth);
	spin_lock_init(&queue->lock);
	INIT_LIST_HEAD(&queue->fg_queue);
	INIT_LIST_HEAD(&queue->bg_queue);

	buf = fuse_uring_alloc_queue_buf(fc->ring.queue_buf_size, node_id);
	queue->queue_req_buf = buf;
	if (IS_ERR(queue->queue_req_buf)) {
		int err = PTR_ERR(queue->queue_req_buf);

		queue->queue_req_buf = NULL;
		return err;
	}

	for (tag = 0; tag < fc->ring.queue_depth; tag++) {
		struct fuse_ring_ent *ent = &queue->ring_ent[tag];

		ent->queue = queue;
		ent->tag = tag;
		ent->fuse_req = NULL;
		ent->rreq = (struct fuse_ring_req *)buf;

		pr_devel("initialize qid=%d tag=%d queue=%p req=%p",
			 qid, tag, queue, ent);

		ent->rreq->flags = 0;

		ent->state = FRRS_INIT;
		ent->need_cmd_done = 0;
		ent->need_req_end = 0;
		fc->ring.queue_refs++;
		buf += fc->ring.req_buf_sz;
	}

	queue->configured = 1;
	queue->aborted = 0;
	fc->ring.nr_queues_ioctl_init++;
	if (fc->ring.nr_queues_ioctl_init == fc->ring.nr_queues) {
		fc->ring.configured = 1;
		pr_devel("fc=%p nr-queues=%zu depth=%zu ioctl ready\n",
			fc, fc->ring.nr_queues, fc->ring.queue_depth);
	}

	return 0;
}

/**
 * Configure the queue for t he given qid. First call will also initialize
 * the ring for this connection.
 */
static int fuse_uring_cfg(struct fuse_conn *fc, unsigned int qid,
			  struct fuse_uring_cfg *cfg)
{
	int rc;

	/* The lock is taken, so that user space may configure all queues
	 * in parallel
	 */
	mutex_lock(&fc->ring.start_stop_lock);

	if (fc->ring.configured) {
		rc = -EALREADY;
		goto unlock;
	}

	if (fc->ring.daemon == NULL) {
		rc = fuse_uring_conn_cfg(fc, cfg);
		if (rc != 0)
			goto unlock;
	}

	rc = fuse_uring_queue_cfg(fc, qid, cfg->numa_node_id);

unlock:
	mutex_unlock(&fc->ring.start_stop_lock);

	return rc;
}

int fuse_uring_ioctl(struct file *file, struct fuse_uring_cfg *cfg)
{
	struct fuse_dev *fud = fuse_get_dev(file);
	struct fuse_conn *fc;

	if (fud == NULL)
		return -ENODEV;

	if (!enable_uring)
		return -ENOTTY;

	fc = fud->fc;

	pr_devel("%s fc=%p flags=%x cmd=%d qid=%d nq=%d fg=%d bg=%d\n",
		 __func__, fc, cfg->flags, cfg->cmd, cfg->qid, cfg->nr_queues,
		 cfg->fg_queue_depth, cfg->bg_queue_depth);


	switch (cfg->cmd) {
	case FUSE_URING_IOCTL_CMD_QUEUE_CFG:
		return fuse_uring_cfg(fc, cfg->qid, cfg);
	default:
		return -EINVAL;
	}

	/* no cmd flag set */
	return -EINVAL;
}

/**
 * Finalize the ring destruction when queue ref counters are zero.
 */
void fuse_uring_ring_destruct(struct fuse_conn *fc)
{
	unsigned int qid;

	if (READ_ONCE(fc->ring.queue_refs) != 0) {
		pr_info("fc=%p refs=%d configured=%d",
			fc, fc->ring.queue_refs, fc->ring.configured);
		WARN_ON(1);
		return;
	}

	put_task_struct(fc->ring.daemon);
	fc->ring.daemon = NULL;

	for (qid = 0; qid < fc->ring.nr_queues; qid++) {
		int tag;
		struct fuse_ring_queue *queue = fuse_uring_get_queue(fc, qid);

		if (!queue->configured)
			continue;

		for (tag = 0; tag < fc->ring.queue_depth; tag++) {
			struct fuse_ring_ent *ent = &queue->ring_ent[tag];

			if (ent->need_cmd_done) {
				pr_warn("fc=%p qid=%d tag=%d cmd not done\n",
					fc, qid, tag);
				io_uring_cmd_done(ent->cmd, -ENOTCONN, 0);
				ent->need_cmd_done = 0;
			}
		}

		vfree(queue->queue_req_buf);
	}

	kfree(fc->ring.queues);
	fc->ring.queues = NULL;
	fc->ring.nr_queues_ioctl_init = 0;
	fc->ring.queue_depth = 0;
	fc->ring.nr_queues = 0;
}
