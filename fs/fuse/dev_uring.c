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

static inline int fuse_uring_current_nodeid(void)
{
	int cpu;
	const struct cpumask *proc_mask = current->cpus_ptr;

	cpu = cpumask_first(proc_mask);

	return cpu_to_node(cpu);
}

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
 * fuse uring mmap, per ring qeuue.
 * Userpsace maps a kernel allocated ring/queue buffer. For numa awareness,
 * userspace needs to run the do the mapping from a core bound thread.
 */
int
fuse_uring_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct fuse_dev *fud = fuse_get_dev(filp);
	struct fuse_conn *fc;
	struct fuse_ring *ring;
	size_t sz = vma->vm_end - vma->vm_start;
	int ret;
	struct fuse_uring_mbuf *new_node = NULL;
	void *buf = NULL;
	int nodeid;

	if (vma->vm_pgoff << PAGE_SHIFT != FUSE_URING_MMAP_OFF) {
		pr_debug("Invalid offset, expected %llu got %lu\n",
			 FUSE_URING_MMAP_OFF, vma->vm_pgoff << PAGE_SHIFT);
		return -EINVAL;
	}

	if (!fud)
		return -ENODEV;
	fc = fud->fc;
	ring = fc->ring;
	if (!ring)
		return -ENODEV;

	nodeid = ring->numa_aware ? fuse_uring_current_nodeid() : NUMA_NO_NODE;

	/* check if uring is configured and if the requested size matches */
	if (ring->nr_queues == 0 || ring->queue_depth == 0) {
		ret = -EINVAL;
		goto out;
	}

	if (sz != ring->queue_buf_size) {
		ret = -EINVAL;
		pr_devel("mmap size mismatch, expected %zu got %zu\n",
			 ring->queue_buf_size, sz);
		goto out;
	}

	if (current->nr_cpus_allowed != 1 && ring->numa_aware) {
		ret = -EINVAL;
		pr_debug(
			"Numa awareness, but thread has more than allowed cpu.\n");
		goto out;
	}

	buf = fuse_uring_alloc_queue_buf(ring->queue_buf_size, nodeid);
	if (IS_ERR(buf)) {
		ret = PTR_ERR(buf);
		goto out;
	}

	new_node = kmalloc(sizeof(*new_node), GFP_USER);
	if (unlikely(new_node == NULL)) {
		ret = -ENOMEM;
		goto out;
	}

	ret = remap_vmalloc_range(vma, buf, 0);
	if (ret)
		goto out;

	mutex_lock(&ring->start_stop_lock);
	/*
	 * In this function we do not know the queue the buffer belongs to.
	 * Later server side will pass the mmaped address, the kernel address
	 * will be found through the map.
	 */
	new_node->kbuf = buf;
	new_node->ubuf = (void *)vma->vm_start;
	rb_add(&new_node->rb_node, &ring->mem_buf_map,
	       fuse_uring_rb_tree_buf_less);
	mutex_unlock(&ring->start_stop_lock);
out:
	if (ret) {
		kfree(new_node);
		vfree(buf);
	}

	pr_devel("%s: pid %d addr: %p sz: %zu  ret: %d\n", __func__,
		 current->pid, (char *)vma->vm_start, sz, ret);

	return ret;
}
