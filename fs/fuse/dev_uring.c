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

static void fuse_uring_req_end_and_get_next(struct fuse_ring_ent *ring_ent,
					    bool set_err, int error,
					    unsigned int issue_flags);

static void fuse_ring_ring_ent_unset_userspace(struct fuse_ring_ent *ent)
{
	clear_bit(FRRS_USERSPACE, &ent->state);
	list_del_init(&ent->list);
}

static void
fuse_uring_async_send_to_ring(struct io_uring_cmd *cmd,
			      unsigned int issue_flags)
{
	io_uring_cmd_done(cmd, 0, 0, issue_flags);
}

/* Abort all list queued request on the given ring queue */
static void fuse_uring_abort_end_queue_requests(struct fuse_ring_queue *queue)
{
	struct fuse_req *req;
	LIST_HEAD(sync_list);
	LIST_HEAD(async_list);

	spin_lock(&queue->lock);

	list_for_each_entry(req, &queue->sync_fuse_req_queue, list)
		clear_bit(FR_PENDING, &req->flags);
	list_for_each_entry(req, &queue->async_fuse_req_queue, list)
		clear_bit(FR_PENDING, &req->flags);

	list_splice_init(&queue->async_fuse_req_queue, &sync_list);
	list_splice_init(&queue->sync_fuse_req_queue, &async_list);

	spin_unlock(&queue->lock);

	/* must not hold queue lock to avoid order issues with fi->lock */
	fuse_dev_end_requests(&sync_list);
	fuse_dev_end_requests(&async_list);
}

void fuse_uring_abort_end_requests(struct fuse_ring *ring)
{
	int qid;

	for (qid = 0; qid < ring->nr_queues; qid++) {
		struct fuse_ring_queue *queue = fuse_uring_get_queue(ring, qid);

		if (!queue->configured)
			continue;

		fuse_uring_abort_end_queue_requests(queue);
	}
}

/* Update conn limits according to ring values */
static void fuse_uring_conn_cfg_limits(struct fuse_ring *ring)
{
	struct fuse_conn *fc = ring->fc;

	WRITE_ONCE(fc->max_pages, min_t(unsigned int, fc->max_pages,
					ring->req_arg_len / PAGE_SIZE));

	/* This not ideal, as multiplication with nr_queue assumes the limit
	 * gets reached when all queues are used, but a single threaded
	 * application might already do that.
	 */
	WRITE_ONCE(fc->max_background, ring->nr_queues * ring->max_nr_async);
}

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

/*
 * mmaped allocated buffers, but does not know which queue that is for
 * This ioctl uses the userspace address as key to identify the kernel address
 * and assign it to the kernel side of the queue.
 */
static int fuse_uring_ioctl_mem_reg(struct fuse_ring *ring,
				    struct fuse_ring_queue *queue,
				    uint64_t uaddr)
{
	struct rb_node *node;
	struct fuse_uring_mbuf *entry;
	int tag;

	node = rb_find((const void *)uaddr, &ring->mem_buf_map,
		       fuse_uring_rb_tree_buf_cmp);
	if (!node)
		return -ENOENT;
	entry = rb_entry(node, struct fuse_uring_mbuf, rb_node);

	rb_erase(node, &ring->mem_buf_map);

	queue->queue_req_buf = entry->kbuf;

	for (tag = 0; tag < ring->queue_depth; tag++) {
		struct fuse_ring_ent *ent = &queue->ring_ent[tag];

		ent->rreq = entry->kbuf + tag * ring->req_buf_sz;
	}

	kfree(node);
	return 0;
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

int fuse_uring_queue_cfg(struct fuse_ring *ring,
			 struct fuse_ring_queue_config *qcfg)
{
	int tag;
	struct fuse_ring_queue *queue;

	if (qcfg->qid >= ring->nr_queues) {
		pr_info("fuse ring queue config: qid=%u >= nr-queues=%zu\n",
			qcfg->qid, ring->nr_queues);
		return -EINVAL;
	}
	queue = fuse_uring_get_queue(ring, qcfg->qid);

	if (queue->configured) {
		pr_info("fuse ring qid=%u already configured!\n", queue->qid);
		return -EALREADY;
	}

	mutex_lock(&ring->start_stop_lock);
	fuse_uring_ioctl_mem_reg(ring, queue, qcfg->uaddr);
	mutex_unlock(&ring->start_stop_lock);

	queue->qid = qcfg->qid;
	queue->ring = ring;
	spin_lock_init(&queue->lock);
	INIT_LIST_HEAD(&queue->sync_fuse_req_queue);
	INIT_LIST_HEAD(&queue->async_fuse_req_queue);

	INIT_LIST_HEAD(&queue->sync_ent_avail_queue);
	INIT_LIST_HEAD(&queue->async_ent_avail_queue);

	INIT_LIST_HEAD(&queue->ent_in_userspace);

	for (tag = 0; tag < ring->queue_depth; tag++) {
		struct fuse_ring_ent *ent = &queue->ring_ent[tag];

		ent->queue = queue;
		ent->tag = tag;
		ent->fuse_req = NULL;

		pr_devel("initialize qid=%d tag=%d queue=%p req=%p", qcfg->qid,
			 tag, queue, ent);

		ent->rreq->flags = 0;

		ent->state = 0;
		set_bit(FRRS_INIT, &ent->state);

		INIT_LIST_HEAD(&ent->list);
	}

	queue->configured = 1;
	ring->nr_queues_ioctl_init++;
	if (ring->nr_queues_ioctl_init == ring->nr_queues) {
		pr_devel("ring=%p nr-queues=%zu depth=%zu ioctl ready\n", ring,
			 ring->nr_queues, ring->queue_depth);
	}

	return 0;
}

static void fuse_uring_stop_fuse_req_end(struct fuse_ring_ent *ent)
{
	struct fuse_req *req = ent->fuse_req;

	ent->fuse_req = NULL;
	clear_bit(FRRS_FUSE_REQ, &ent->state);
	clear_bit(FR_SENT, &req->flags);
	req->out.h.error = -ECONNABORTED;
	fuse_request_end(req);
}

/*
 * Release a request/entry on connection shutdown
 */
static bool fuse_uring_try_entry_stop(struct fuse_ring_ent *ent,
				      bool need_cmd_done)
	__must_hold(ent->queue->lock)
{
	struct fuse_ring_queue *queue = ent->queue;
	bool released = false;

	if (test_bit(FRRS_FREED, &ent->state))
		goto out; /* no work left, freed before */

	if (ent->state == BIT(FRRS_INIT) || test_bit(FRRS_WAIT, &ent->state) ||
	    test_bit(FRRS_USERSPACE, &ent->state)) {
		set_bit(FRRS_FREED, &ent->state);

		if (need_cmd_done) {
			pr_devel("qid=%d tag=%d sending cmd_done\n", queue->qid,
				 ent->tag);

			spin_unlock(&queue->lock);
			io_uring_cmd_done(ent->cmd, -ENOTCONN, 0,
					  IO_URING_F_UNLOCKED);
			spin_lock(&queue->lock);
		}

		if (ent->fuse_req)
			fuse_uring_stop_fuse_req_end(ent);
		released = true;
	}
out:
	return released;
}

static void fuse_uring_stop_list_entries(struct list_head *head,
					 struct fuse_ring_queue *queue,
					 bool need_cmd_done)
{
	struct fuse_ring *ring = queue->ring;
	struct fuse_ring_ent *ent, *next;
	ssize_t queue_refs = SSIZE_MAX;

	list_for_each_entry_safe(ent, next, head, list) {
		if (fuse_uring_try_entry_stop(ent, need_cmd_done)) {
			queue_refs = atomic_dec_return(&ring->queue_refs);
			list_del_init(&ent->list);
		}

		if (WARN_ON_ONCE(queue_refs < 0))
			pr_warn("qid=%d queue_refs=%zd", queue->qid,
				queue_refs);
	}
}

static void fuse_uring_stop_queue(struct fuse_ring_queue *queue)
	__must_hold(&queue->lock)
{
	fuse_uring_stop_list_entries(&queue->ent_in_userspace, queue, false);
	fuse_uring_stop_list_entries(&queue->async_ent_avail_queue, queue, true);
	fuse_uring_stop_list_entries(&queue->sync_ent_avail_queue, queue, true);
}

/*
 * Log state debug info
 */
static void fuse_uring_stop_ent_state(struct fuse_ring *ring)
{
	int qid, tag;

	for (qid = 0; qid < ring->nr_queues; qid++) {
		struct fuse_ring_queue *queue = fuse_uring_get_queue(ring, qid);

		for (tag = 0; tag < ring->queue_depth; tag++) {
			struct fuse_ring_ent *ent = &queue->ring_ent[tag];

			if (!test_bit(FRRS_FREED, &ent->state))
				pr_info("ring=%p qid=%d tag=%d state=%lu\n",
					ring, qid, tag, ent->state);
		}
	}
	ring->stop_debug_log = 1;
}

static void fuse_uring_async_stop_queues(struct work_struct *work)
{
	int qid;
	struct fuse_ring *ring =
		container_of(work, struct fuse_ring, stop_work.work);

	for (qid = 0; qid < ring->nr_queues; qid++) {
		struct fuse_ring_queue *queue = fuse_uring_get_queue(ring, qid);

		if (!queue->configured)
			continue;

		spin_lock(&queue->lock);
		fuse_uring_stop_queue(queue);
		spin_unlock(&queue->lock);
	}

	if (atomic_read(&ring->queue_refs) > 0) {
		if (time_after(jiffies,
			       ring->stop_time + FUSE_URING_STOP_WARN_TIMEOUT))
			fuse_uring_stop_ent_state(ring);

		pr_info("ring=%p scheduling intervalled queue stop\n", ring);

		schedule_delayed_work(&ring->stop_work,
				      FUSE_URING_STOP_INTERVAL);
	} else {
		wake_up_all(&ring->stop_waitq);
	}
}

/*
 * Stop the ring queues
 */
void fuse_uring_stop_queues(struct fuse_ring *ring)
{
	int qid;

	for (qid = 0; qid < ring->nr_queues; qid++) {
		struct fuse_ring_queue *queue = fuse_uring_get_queue(ring, qid);

		if (!queue->configured)
			continue;

		spin_lock(&queue->lock);
		fuse_uring_stop_queue(queue);
		spin_unlock(&queue->lock);
	}

	if (atomic_read(&ring->queue_refs) > 0) {
		pr_info("ring=%p scheduling intervalled queue stop\n", ring);
		ring->stop_time = jiffies;
		INIT_DELAYED_WORK(&ring->stop_work,
				  fuse_uring_async_stop_queues);
		schedule_delayed_work(&ring->stop_work,
				      FUSE_URING_STOP_INTERVAL);
	} else {
		wake_up_all(&ring->stop_waitq);
	}
}

/*
 * Checks for errors and stores it into the request
 */
static int fuse_uring_ring_ent_has_err(struct fuse_ring *ring,
				       struct fuse_ring_ent *ring_ent)
{
	struct fuse_conn *fc = ring->fc;
	struct fuse_req *req = ring_ent->fuse_req;
	struct fuse_out_header *oh = &req->out.h;
	int err;

	if (oh->unique == 0) {
		/* Not supportd through request based uring, this needs another
		 * ring from user space to kernel
		 */
		pr_warn("Unsupported fuse-notify\n");
		err = -EINVAL;
		goto seterr;
	}

	if (oh->error <= -512 || oh->error > 0) {
		err = -EINVAL;
		goto seterr;
	}

	if (oh->error) {
		err = oh->error;
		pr_devel("%s:%d err=%d op=%d req-ret=%d", __func__, __LINE__,
			 err, req->args->opcode, req->out.h.error);
		goto err; /* error already set */
	}

	if ((oh->unique & ~FUSE_INT_REQ_BIT) != req->in.h.unique) {
		pr_warn("Unpexted seqno mismatch, expected: %llu got %llu\n",
			req->in.h.unique, oh->unique & ~FUSE_INT_REQ_BIT);
		err = -ENOENT;
		goto seterr;
	}

	/* Is it an interrupt reply ID?	 */
	if (oh->unique & FUSE_INT_REQ_BIT) {
		err = 0;
		if (oh->error == -ENOSYS)
			fc->no_interrupt = 1;
		else if (oh->error == -EAGAIN) {
			/* XXX Interrupts not handled yet */
			/* err = queue_interrupt(req); */
			pr_warn("Intrerupt EAGAIN not supported yet");
			err = -EINVAL;
		}

		goto seterr;
	}

	return 0;

seterr:
	pr_devel("%s:%d err=%d op=%d req-ret=%d", __func__, __LINE__, err,
		 req->args->opcode, req->out.h.error);
	oh->error = err;
err:
	pr_devel("%s:%d err=%d op=%d req-ret=%d", __func__, __LINE__, err,
		 req->args->opcode, req->out.h.error);
	return err;
}

/*
 * Copy data from the ring buffer to the fuse request
 */
static int fuse_uring_copy_from_ring(struct fuse_ring *ring,
				     struct fuse_req *req,
				     struct fuse_ring_req *rreq)
{
	struct fuse_copy_state cs;
	struct fuse_args *args = req->args;

	fuse_copy_init(&cs, 0, NULL);
	cs.is_uring = 1;
	cs.ring.buf = rreq->in_out_arg;

	if (rreq->in_out_arg_len > ring->req_arg_len) {
		pr_devel("Max ring buffer len exceeded (%u vs %zu\n",
			 rreq->in_out_arg_len, ring->req_arg_len);
		return -EINVAL;
	}
	cs.ring.buf_sz = rreq->in_out_arg_len;
	cs.req = req;

	pr_devel("%s:%d buf=%p len=%d args=%d\n", __func__, __LINE__,
		 cs.ring.buf, cs.ring.buf_sz, args->out_numargs);

	return fuse_copy_out_args(&cs, args, rreq->in_out_arg_len);
}

/*
 * Copy data from the req to the ring buffer
 */
static int fuse_uring_copy_to_ring(struct fuse_ring *ring, struct fuse_req *req,
				   struct fuse_ring_req *rreq)
{
	struct fuse_copy_state cs;
	struct fuse_args *args = req->args;
	int err;

	fuse_copy_init(&cs, 1, NULL);
	cs.is_uring = 1;
	cs.ring.buf = rreq->in_out_arg;
	cs.ring.buf_sz = ring->req_arg_len;
	cs.req = req;

	pr_devel("%s:%d buf=%p len=%d args=%d\n", __func__, __LINE__,
		 cs.ring.buf, cs.ring.buf_sz, args->out_numargs);

	err = fuse_copy_args(&cs, args->in_numargs, args->in_pages,
			     (struct fuse_arg *)args->in_args, 0);
	rreq->in_out_arg_len = cs.ring.offset;

	pr_devel("%s:%d buf=%p len=%d args=%d err=%d\n", __func__, __LINE__,
		 cs.ring.buf, cs.ring.buf_sz, args->out_numargs, err);

	return err;
}

/*
 * Write data to the ring buffer and send the request to userspace,
 * userspace will read it
 * This is comparable with classical read(/dev/fuse)
 */
static void fuse_uring_send_to_ring(struct fuse_ring_ent *ring_ent,
				    unsigned int issue_flags, bool send_in_task)
{
	struct fuse_ring *ring = ring_ent->queue->ring;
	struct fuse_ring_req *rreq = ring_ent->rreq;
	struct fuse_req *req = ring_ent->fuse_req;
	struct fuse_ring_queue *queue = ring_ent->queue;
	int err = 0;

	spin_lock(&queue->lock);

	if (WARN_ON(test_bit(FRRS_USERSPACE, &ring_ent->state) ||
		   (test_bit(FRRS_FREED, &ring_ent->state)))) {
		pr_err("qid=%d tag=%d ring-req=%p buf_req=%p invalid state %lu on send\n",
		       queue->qid, ring_ent->tag, ring_ent, rreq,
		       ring_ent->state);
		err = -EIO;
	} else {
		set_bit(FRRS_USERSPACE, &ring_ent->state);
		list_add(&ring_ent->list, &queue->ent_in_userspace);
	}

	spin_unlock(&queue->lock);
	if (err)
		goto err;

	err = fuse_uring_copy_to_ring(ring, req, rreq);
	if (unlikely(err)) {
		spin_lock(&queue->lock);
		fuse_ring_ring_ent_unset_userspace(ring_ent);
		spin_unlock(&queue->lock);
		goto err;
	}

	/* ring req go directly into the shared memory buffer */
	rreq->in = req->in.h;
	set_bit(FR_SENT, &req->flags);

	pr_devel("%s qid=%d tag=%d state=%lu cmd-done op=%d unique=%llu issue_flags=%u\n",
		 __func__, ring_ent->queue->qid, ring_ent->tag, ring_ent->state,
		 rreq->in.opcode, rreq->in.unique, issue_flags);

	if (send_in_task)
		io_uring_cmd_complete_in_task(ring_ent->cmd,
					      fuse_uring_async_send_to_ring);
	else
		io_uring_cmd_done(ring_ent->cmd, 0, 0, issue_flags);

	return;

err:
	fuse_uring_req_end_and_get_next(ring_ent, true, err, issue_flags);
}

/*
 * Put a ring request onto hold, it is no longer used for now.
 */
static void fuse_uring_ent_avail(struct fuse_ring_ent *ring_ent,
				 struct fuse_ring_queue *queue)
	__must_hold(&queue->lock)
{
	struct fuse_ring *ring = queue->ring;

	/* unsets all previous flags - basically resets */
	pr_devel("%s ring=%p qid=%d tag=%d state=%lu async=%d\n", __func__,
		 ring, ring_ent->queue->qid, ring_ent->tag, ring_ent->state,
		 ring_ent->async);

	if (WARN_ON(test_bit(FRRS_USERSPACE, &ring_ent->state))) {
		pr_warn("%s qid=%d tag=%d state=%lu async=%d\n", __func__,
			ring_ent->queue->qid, ring_ent->tag, ring_ent->state,
			ring_ent->async);
		return;
	}

	WARN_ON_ONCE(!list_empty(&ring_ent->list));

	if (ring_ent->async)
		list_add(&ring_ent->list, &queue->async_ent_avail_queue);
	else
		list_add(&ring_ent->list, &queue->sync_ent_avail_queue);

	set_bit(FRRS_WAIT, &ring_ent->state);
}

/*
 * Assign a fuse queue entry to the given entry
 */
static void fuse_uring_add_req_to_ring_ent(struct fuse_ring_ent *ring_ent,
					   struct fuse_req *req)
{
	clear_bit(FRRS_WAIT, &ring_ent->state);
	list_del_init(&req->list);
	clear_bit(FR_PENDING, &req->flags);
	ring_ent->fuse_req = req;
	set_bit(FRRS_FUSE_REQ, &ring_ent->state);
}

/*
 * Release a uring entry and fetch the next fuse request if available
 *
 * @return true if a new request has been fetched
 */
static bool fuse_uring_ent_release_and_fetch(struct fuse_ring_ent *ring_ent)
{
	struct fuse_req *req = NULL;
	struct fuse_ring_queue *queue = ring_ent->queue;
	struct list_head *req_queue = ring_ent->async ?
		&queue->async_fuse_req_queue : &queue->sync_fuse_req_queue;

	spin_lock(&ring_ent->queue->lock);
	fuse_uring_ent_avail(ring_ent, queue);
	if (!list_empty(req_queue)) {
		req = list_first_entry(req_queue, struct fuse_req, list);
		fuse_uring_add_req_to_ring_ent(ring_ent, req);
		list_del_init(&ring_ent->list);
	}
	spin_unlock(&ring_ent->queue->lock);

	return req ? true : false;
}

/*
 * Finalize a fuse request, then fetch and send the next entry, if available
 *
 * has lock/unlock/lock to avoid holding the lock on calling fuse_request_end
 */
static void fuse_uring_req_end_and_get_next(struct fuse_ring_ent *ring_ent,
					    bool set_err, int error,
					    unsigned int issue_flags)
{
	struct fuse_req *req = ring_ent->fuse_req;
	int has_next;

	if (set_err)
		req->out.h.error = error;

	clear_bit(FR_SENT, &req->flags);
	fuse_request_end(ring_ent->fuse_req);
	ring_ent->fuse_req = NULL;
	clear_bit(FRRS_FUSE_REQ, &ring_ent->state);

	has_next = fuse_uring_ent_release_and_fetch(ring_ent);
	if (has_next) {
		/* called within uring context - use provided flags */
		fuse_uring_send_to_ring(ring_ent, issue_flags, false);
	}
}

/*
 * Read data from the ring buffer, which user space has written to
 * This is comparible with handling of classical write(/dev/fuse).
 * Also make the ring request available again for new fuse requests.
 */
static void fuse_uring_commit_and_release(struct fuse_dev *fud,
					  struct fuse_ring_ent *ring_ent,
					  unsigned int issue_flags)
{
	struct fuse_ring_req *rreq = ring_ent->rreq;
	struct fuse_req *req = ring_ent->fuse_req;
	ssize_t err = 0;
	bool set_err = false;

	req->out.h = rreq->out;

	err = fuse_uring_ring_ent_has_err(fud->fc->ring, ring_ent);
	if (err) {
		/* req->out.h.error already set */
		pr_devel("%s:%d err=%zd oh->err=%d\n", __func__, __LINE__, err,
			 req->out.h.error);
		goto out;
	}

	err = fuse_uring_copy_from_ring(fud->fc->ring, req, rreq);
	if (err)
		set_err = true;

out:
	pr_devel("%s:%d ret=%zd op=%d req-ret=%d\n", __func__, __LINE__, err,
		 req->args->opcode, req->out.h.error);
	fuse_uring_req_end_and_get_next(ring_ent, set_err, err, issue_flags);
}

/*
 * fuse_uring_req_fetch command handling
 */
static int fuse_uring_fetch(struct fuse_ring_ent *ring_ent,
			    struct io_uring_cmd *cmd, unsigned int issue_flags)
__must_hold(ring_ent->queue->lock)
{
	struct fuse_ring_queue *queue = ring_ent->queue;
	struct fuse_ring *ring = queue->ring;
	int ret = 0;
	int nr_ring_sqe;

	/* register requests for foreground requests first, then backgrounds */
	if (queue->nr_req_sync >= ring->max_nr_sync) {
		queue->nr_req_async++;
		ring_ent->async = 1;
	} else
		queue->nr_req_sync++;

	fuse_uring_ent_avail(ring_ent, queue);

	if (queue->nr_req_sync + queue->nr_req_async > ring->queue_depth) {
		/* should be caught by ring state before and queue depth
		 * check before
		 */
		WARN_ON(1);
		pr_info("qid=%d tag=%d req cnt (fg=%d async=%d exceeds depth=%zu",
			queue->qid, ring_ent->tag, queue->nr_req_sync,
			queue->nr_req_async, ring->queue_depth);
		ret = -ERANGE;
	}

	if (ret)
		goto out; /* erange */

	WRITE_ONCE(ring_ent->cmd, cmd);

	nr_ring_sqe = ring->queue_depth * ring->nr_queues;
	if (atomic_inc_return(&ring->nr_sqe_init) == nr_ring_sqe) {
		fuse_uring_conn_cfg_limits(ring);
		ring->ready = 1;
	}

out:
	return ret;
}

static struct fuse_ring_queue *
fuse_uring_get_verify_queue(struct fuse_ring *ring,
			    const struct fuse_uring_cmd_req *cmd_req,
			    unsigned int issue_flags)
{
	struct fuse_conn *fc = ring->fc;
	struct fuse_ring_queue *queue;
	int ret;

	if (!(issue_flags & IO_URING_F_SQE128)) {
		pr_info("qid=%d tag=%d SQE128 not set\n", cmd_req->qid,
			cmd_req->tag);
		ret = -EINVAL;
		goto err;
	}

	if (unlikely(!fc->connected)) {
		ret = -ENOTCONN;
		goto err;
	}

	if (unlikely(!ring->configured)) {
		pr_info("command for a connection that is not ring configured\n");
		ret = -ENODEV;
		goto err;
	}

	if (unlikely(cmd_req->qid >= ring->nr_queues)) {
		pr_devel("qid=%u >= nr-queues=%zu\n", cmd_req->qid,
			 ring->nr_queues);
		ret = -EINVAL;
		goto err;
	}

	queue = fuse_uring_get_queue(ring, cmd_req->qid);
	if (unlikely(queue == NULL)) {
		pr_info("Got NULL queue for qid=%d\n", cmd_req->qid);
		ret = -EIO;
		goto err;
	}

	if (unlikely(!queue->configured || queue->stopped)) {
		pr_info("Ring or queue (qid=%u) not ready.\n", cmd_req->qid);
		ret = -ENOTCONN;
		goto err;
	}

	if (cmd_req->tag > ring->queue_depth) {
		pr_info("tag=%u > queue-depth=%zu\n", cmd_req->tag,
			ring->queue_depth);
		ret = -EINVAL;
		goto err;
	}

	return queue;

err:
	return ERR_PTR(ret);
}

/**
 * Entry function from io_uring to handle the given passthrough command
 * (op cocde IORING_OP_URING_CMD)
 */
int fuse_uring_cmd(struct io_uring_cmd *cmd, unsigned int issue_flags)
{
	const struct fuse_uring_cmd_req *cmd_req = io_uring_sqe_cmd(cmd->sqe);
	struct fuse_dev *fud = fuse_get_dev(cmd->file);
	struct fuse_conn *fc = fud->fc;
	struct fuse_ring *ring = fc->ring;
	struct fuse_ring_queue *queue;
	struct fuse_ring_ent *ring_ent = NULL;
	u32 cmd_op = cmd->cmd_op;
	int ret = 0;

	if (!ring) {
		ret = -ENODEV;
		goto out;
	}

	queue = fuse_uring_get_verify_queue(ring, cmd_req, issue_flags);
	if (IS_ERR(queue)) {
		ret = PTR_ERR(queue);
		goto out;
	}

	ring_ent = &queue->ring_ent[cmd_req->tag];

	pr_devel("%s:%d received: cmd op %d qid %d (%p) tag %d  (%p)\n",
		 __func__, __LINE__, cmd_op, cmd_req->qid, queue, cmd_req->tag,
		 ring_ent);

	spin_lock(&queue->lock);
	if (unlikely(queue->stopped)) {
		/* XXX how to ensure queue still exists? Add
		 * an rw ring->stop lock? And take that at the beginning
		 * of this function? Better would be to advise uring
		 * not to call this function at all? Or free the queue memory
		 * only, on daemon PF_EXITING?
		 */
		ret = -ENOTCONN;
		goto err_unlock;
	}

	if (current == queue->server_task)
		queue->uring_cmd_issue_flags = issue_flags;

	switch (cmd_op) {
	case FUSE_URING_REQ_FETCH:
		if (queue->server_task == NULL) {
			queue->server_task = current;
			queue->uring_cmd_issue_flags = issue_flags;
		}

		/* No other bit must be set here */
		if (ring_ent->state != BIT(FRRS_INIT)) {
			pr_info_ratelimited(
				"qid=%d tag=%d register req state %lu expected %lu",
				cmd_req->qid, cmd_req->tag, ring_ent->state,
				BIT(FRRS_INIT));
			ret = -EINVAL;
			goto err_unlock;
		}

		fuse_ring_ring_ent_unset_userspace(ring_ent);

		ret = fuse_uring_fetch(ring_ent, cmd, issue_flags);
		if (ret)
			goto err_unlock;

		/*
		 * The ring entry is registered now and needs to be handled
		 * for shutdown.
		 */
		atomic_inc(&ring->queue_refs);

		spin_unlock(&queue->lock);
		break;
	case FUSE_URING_REQ_COMMIT_AND_FETCH:
		if (unlikely(!ring->ready)) {
			pr_info("commit and fetch, but fuse-uringis not ready.");
			goto err_unlock;
		}

		if (!test_bit(FRRS_USERSPACE, &ring_ent->state)) {
			pr_info("qid=%d tag=%d state %lu SQE already handled\n",
				queue->qid, ring_ent->tag, ring_ent->state);
			goto err_unlock;
		}

		fuse_ring_ring_ent_unset_userspace(ring_ent);
		spin_unlock(&queue->lock);

		WRITE_ONCE(ring_ent->cmd, cmd);
		fuse_uring_commit_and_release(fud, ring_ent, issue_flags);

		ret = 0;
		break;
	default:
		ret = -EINVAL;
		pr_devel("Unknown uring command %d", cmd_op);
		goto err_unlock;
	}
out:
	pr_devel("uring cmd op=%d, qid=%d tag=%d ret=%d\n", cmd_op,
		 cmd_req->qid, cmd_req->tag, ret);

	if (ret < 0) {
		if (ring_ent != NULL) {
			pr_info_ratelimited("error: uring cmd op=%d, qid=%d tag=%d ret=%d\n",
					    cmd_op, cmd_req->qid, cmd_req->tag,
					    ret);

			/* must not change the entry state, as userspace
			 * might have sent random data, but valid requests
			 * might be registered already - don't confuse those.
			 */
		}
		io_uring_cmd_done(cmd, ret, 0, issue_flags);
	}

	return -EIOCBQUEUED;

err_unlock:
	spin_unlock(&queue->lock);
	goto out;
}

