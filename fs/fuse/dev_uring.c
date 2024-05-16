// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE: Filesystem in Userspace
 * Copyright (c) 2023-2024 DataDirect Networks.
 */

#include "fuse_i.h"
#include "fuse_dev_i.h"
#include "dev_uring_i.h"

#include "linux/compiler_types.h"
#include "linux/spinlock.h"
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
#include <linux/io_uring/cmd.h>
#include <linux/topology.h>
#include <linux/io_uring/cmd.h>

/*
 * Basic ring setup for this connection based on the provided configuration
 */
int fuse_uring_conn_cfg(struct fuse_ring *ring, struct fuse_ring_config *rcfg)
{
	size_t queue_sz;

	if (ring->configured) {
		pr_info("The ring is already configured.\n");
		return -EALREADY;
	}

	if (rcfg->nr_queues == 0) {
		pr_info("zero number of queues is invalid.\n");
		return -EINVAL;
	}

	if (rcfg->nr_queues > 1 && rcfg->nr_queues != num_present_cpus()) {
		pr_info("nr-queues (%d) does not match nr-cores (%d).\n",
			rcfg->nr_queues, num_present_cpus());
		return -EINVAL;
	}

	if (rcfg->req_arg_len < FUSE_RING_MIN_IN_OUT_ARG_SIZE) {
		pr_info("Per req buffer size too small (%d), min: %d\n",
			rcfg->req_arg_len, FUSE_RING_MIN_IN_OUT_ARG_SIZE);
		return -EINVAL;
	}

	if (WARN_ON(ring->queues))
		return -EINVAL;

	ring->numa_aware = rcfg->numa_aware;
	ring->nr_queues = rcfg->nr_queues;
	ring->per_core_queue = rcfg->nr_queues > 1;

	ring->max_nr_sync = rcfg->sync_queue_depth;
	ring->max_nr_async = rcfg->async_queue_depth;
	ring->queue_depth = ring->max_nr_sync + ring->max_nr_async;

	ring->req_arg_len = rcfg->req_arg_len;
	ring->req_buf_sz = rcfg->user_req_buf_sz;

	ring->queue_buf_size = ring->req_buf_sz * ring->queue_depth;

	queue_sz = sizeof(*ring->queues) +
		   ring->queue_depth * sizeof(struct fuse_ring_ent);
	ring->queues = kcalloc(rcfg->nr_queues, queue_sz, GFP_KERNEL);
	if (!ring->queues)
		return -ENOMEM;
	ring->queue_size = queue_sz;
	ring->configured = 1;

	atomic_set(&ring->queue_refs, 0);

	return 0;
}

void fuse_uring_ring_destruct(struct fuse_ring *ring)
{
	unsigned int qid;
	struct rb_node *rbn;

	for (qid = 0; qid < ring->nr_queues; qid++) {
		struct fuse_ring_queue *queue = fuse_uring_get_queue(ring, qid);

		vfree(queue->queue_req_buf);
	}

	kfree(ring->queues);
	ring->queues = NULL;
	ring->nr_queues_ioctl_init = 0;
	ring->queue_depth = 0;
	ring->nr_queues = 0;

	rbn = rb_first(&ring->mem_buf_map);
	while (rbn) {
		struct rb_node *next = rb_next(rbn);
		struct fuse_uring_mbuf *entry =
			rb_entry(rbn, struct fuse_uring_mbuf, rb_node);

		rb_erase(rbn, &ring->mem_buf_map);
		kfree(entry);

		rbn = next;
	}

	mutex_destroy(&ring->start_stop_lock);
}
