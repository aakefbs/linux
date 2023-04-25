// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>
 */

#include "fuse_i.h"
#include "fuse_dev_i.h"
#include "dev_uring_i.h"

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

/* default monitor interval for a dying daemon */
#define FURING_DAEMON_MON_PERIOD (5 * HZ)

static bool __read_mostly enable_uring;
module_param(enable_uring, bool, 0644);
MODULE_PARM_DESC(enable_uring,
	"Enable uring userspace communication through uring.");

static bool fuse_uring_ent_release_and_fetch(struct fuse_ring_ent *ring_ent);
static void fuse_uring_send_to_ring(struct fuse_ring_ent *ring_ent,
				    unsigned int issue_flags);

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
	fuse_dev_end_requests(&queue->async_queue);
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

/*
 * Finalize a fuse request, then fetch and send the next entry, if available
 *
 * has lock/unlock/lock to avoid holding the lock on calling fuse_request_end
 */
static void
fuse_uring_req_end_and_get_next(struct fuse_ring_ent *ring_ent, bool set_err,
				int error)
{
	bool already = false;
	struct fuse_req *req = ring_ent->fuse_req;
	bool send;

	spin_lock(&ring_ent->queue->lock);
	if (ring_ent->state & FRRS_FUSE_REQ_END || !ring_ent->need_req_end)
		already = true;
	else {
		ring_ent->state |= FRRS_FUSE_REQ_END;
		ring_ent->need_req_end = 0;
	}
	spin_unlock(&ring_ent->queue->lock);

	if (already) {
		struct fuse_ring_queue *queue = ring_ent->queue;

		if (!queue->aborted) {
			pr_info("request end not needed state=%llu end-bit=%d\n",
				ring_ent->state, ring_ent->need_req_end);
			WARN_ON(1);
		}
		return;
	}

	if (set_err)
		req->out.h.error = error;

	fuse_request_end(ring_ent->fuse_req);
	ring_ent->fuse_req = NULL;

	send = fuse_uring_ent_release_and_fetch(ring_ent);
	if (send) {
		/* called within uring context - IO_URING_F_UNLOCKED not set */
		fuse_uring_send_to_ring(ring_ent, 0);
	}
}

/*
 * Copy data from the req to the ring buffer
 */
static int fuse_uring_copy_to_ring(struct fuse_conn *fc,
				   struct fuse_req *req,
				   struct fuse_ring_req *rreq)
{
	struct fuse_copy_state cs;
	struct fuse_args *args = req->args;
	int err;

	fuse_copy_init(&cs, 1, NULL);
	cs.is_uring = 1;
	cs.ring.buf = rreq->in_out_arg;
	cs.ring.buf_sz = fc->ring.req_arg_len;
	cs.req = req;

	pr_devel("%s:%d buf=%p len=%d args=%d\n", __func__, __LINE__,
		 cs.ring.buf, cs.ring.buf_sz, args->out_numargs);

	err = fuse_copy_args(&cs, args->in_numargs, args->in_pages,
			     (struct fuse_arg *) args->in_args, 0);
	rreq->in_out_arg_len = cs.ring.offset;

	pr_devel("%s:%d buf=%p len=%d args=%d err=%d\n", __func__, __LINE__,
		 cs.ring.buf, cs.ring.buf_sz, args->out_numargs, err);

	return err;
}

/*
 * Copy data from the ring buffer to the fuse request
 */
static int fuse_uring_copy_from_ring(struct fuse_conn *fc,
				     struct fuse_req *req,
				     struct fuse_ring_req *rreq)
{
	struct fuse_copy_state cs;
	struct fuse_args *args = req->args;

	fuse_copy_init(&cs, 0, NULL);
	cs.is_uring = 1;
	cs.ring.buf = rreq->in_out_arg;

	if (rreq->in_out_arg_len > fc->ring.req_arg_len) {
		pr_devel("Max ring buffer len exceeded (%u vs %zu\n",
			 rreq->in_out_arg_len,  fc->ring.req_arg_len);
		return -EINVAL;
	}
	cs.ring.buf_sz = rreq->in_out_arg_len;
	cs.req = req;

	pr_devel("%s:%d buf=%p len=%d args=%d\n", __func__, __LINE__,
		 cs.ring.buf, cs.ring.buf_sz, args->out_numargs);

	return fuse_copy_out_args(&cs, args, rreq->in_out_arg_len);
}

/**
 * Write data to the ring buffer and send the request to userspace,
 * userspace will read it
 * This is comparable with classical read(/dev/fuse)
 */
static void fuse_uring_send_to_ring(struct fuse_ring_ent *ring_ent,
				    unsigned int issue_flags)
{
	struct fuse_conn *fc = ring_ent->queue->fc;
	struct fuse_ring_req *rreq = ring_ent->rreq;
	struct fuse_req *req = ring_ent->fuse_req;
	int err = 0;

	pr_devel("%s:%d ring-req=%p fuse_req=%p state=%llu args=%p\n", __func__,
		 __LINE__, ring_ent, ring_ent->fuse_req, ring_ent->state, req->args);

	spin_lock(&ring_ent->queue->lock);
	if (unlikely((ring_ent->state & FRRS_USERSPACE) ||
		     (ring_ent->state & FRRS_FREED))) {
		pr_err("ring-req=%p buf_req=%p invalid state %llu on send\n",
		       ring_ent, rreq, ring_ent->state);
		WARN_ON(1);
		err = -EIO;
	} else
		ring_ent->state |= FRRS_USERSPACE;

	ring_ent->need_cmd_done = 0;
	spin_unlock(&ring_ent->queue->lock);
	if (err)
		goto err;

	err = fuse_uring_copy_to_ring(fc, req, rreq);
	if (unlikely(err)) {
		ring_ent->state &= ~FRRS_USERSPACE;
		ring_ent->need_cmd_done = 1;
		goto err;
	}

	/* ring req go directly into the shared memory buffer */
	rreq->in = req->in.h;

	pr_devel("%s qid=%d tag=%d state=%llu cmd-done op=%d unique=%llu\n",
		__func__, ring_ent->queue->qid, ring_ent->tag, ring_ent->state,
		rreq->in.opcode, rreq->in.unique);

	io_uring_cmd_done(ring_ent->cmd, 0, 0, issue_flags);
	return;

err:
	fuse_uring_req_end_and_get_next(ring_ent, true, err);
}

/**
 * Set the given ring entry as available in the queue bitmap
 */
static void fuse_uring_bit_set(struct fuse_ring_ent *ring_ent, bool async,
			       const char *str)
__must_hold(ring_ent->queue->lock)
{
	int old;
	struct fuse_ring_queue *queue = ring_ent->queue;
	const struct fuse_conn *fc = queue->fc;
	int tag = ring_ent->tag;

	old = test_and_set_bit(tag, queue->req_avail_map);
	if (unlikely(old != 0)) {
		pr_warn("%8s invalid bit value on clear for qid=%d tag=%d",
			str, queue->qid, tag);
		WARN_ON(1);
	}
	if (async)
		queue->req_async++;
	else
		queue->req_fg++;

	pr_devel("%35s bit set fc=%pa async=%d qid=%d tag=%d qfg=%d qasync=%d\n",
		 str, fc, async, queue->qid, ring_ent->tag, queue->req_fg,
		 queue->req_async);
}

/**
 * Mark the ring entry as not available for other requests
 */
static int fuse_uring_bit_clear(struct fuse_ring_ent *ring_ent, int async,
				const char *str)
__must_hold(ring_ent->queue->lock)
{
	int old;
	struct fuse_ring_queue *queue = ring_ent->queue;
	const struct fuse_conn *fc = queue->fc;
	int tag = ring_ent->tag;
	int *value = async ? &queue->req_async : &queue->req_fg;

	if (unlikely(*value <= 0)) {
		pr_warn("%s qid=%d tag=%d async=%d zero req avail fg=%d qasync=%d\n",
			str, queue->qid, ring_ent->tag, async,
			queue->req_fg, queue->req_async);
		WARN_ON(1);
		return -EINVAL;
	}

	old = test_and_clear_bit(tag, queue->req_avail_map);
	if (unlikely(old != 1)) {
		pr_warn("%8s invalid bit value on clear for qid=%d tag=%d",
			str, queue->qid, tag);
		WARN_ON(1);
		return -EIO;
	}

	ring_ent->rreq->flags = 0;

	if (async) {
		ring_ent->rreq->flags |= FUSE_RING_REQ_FLAG_ASYNC;
		queue->req_async--;
	} else
		queue->req_fg--;

	pr_devel("%35s ring bit clear fc=%p async=%d qid=%d tag=%d fg=%d qasync=%d\n",
		 str, fc, async, queue->qid, ring_ent->tag,
		 queue->req_fg, queue->req_async);

	ring_ent->state |= FRRS_FUSE_REQ;

	return 0;
}

/*
 * Assign a fuse queue entry to the given entry
 *
 */
static bool fuse_uring_assign_ring_entry(struct fuse_ring_ent *ring_ent,
					     struct list_head *head,
					     int async)
__must_hold(&queue.waitq.lock)
{
	struct fuse_req *req;
	int res;

	if (list_empty(head))
		return false;

	res = fuse_uring_bit_clear(ring_ent, async, __func__);
	if (unlikely(res))
		return false;

	req = list_first_entry(head, struct fuse_req, list);
	list_del_init(&req->list);
	clear_bit(FR_PENDING, &req->flags);
	ring_ent->fuse_req = req;
	ring_ent->need_req_end = 1;

	return true;
}

int fuse_uring_queue_fuse_req(struct fuse_conn *fc, struct fuse_req *req)
{
	struct fuse_ring_queue *queue;
	int qid = 0;
	struct fuse_ring_ent *ring_ent = NULL;
	const size_t queue_depth = fc->ring.queue_depth;
	int res;
	int async = test_bit(FR_BACKGROUND, &req->flags) &&
		    !req->args->async_blocking;
	struct list_head *head;
	int *queue_avail;
	int cpu_off;

	if (async && req->args->opcode == FUSE_READ &&
	    req->args->out_args[0].size < FUSE_URING_MIN_RA_ASYNC_SIZE)
		async = 0;

	pr_devel("opcode=%d out_size=%d async=%d\n",
		req->args->opcode, req->args->out_args[0].size, async);

	/* async requests are best handled on another core, the current
	 * core can do application/page handling, while the async request
	 * is handled on another core in userspace.
	 * For sync request the application has to wait - no processing, so
	 * the request should continue on the current core and avoid context
	 * switches.
	 * XXX This should be on the same numa node and not busy - is there
	 * a scheduler function available  that could make this decision?
	 */
	cpu_off = async ? 1 : 0;

	if (fc->ring.per_core_queue) {

		qid = (task_cpu(current) + cpu_off) % fc->ring.nr_queues;

		if (unlikely(qid >= fc->ring.nr_queues)) {
			WARN_ONCE(1, "Core number (%u) exceeds nr ueues (%zu)\n",
				  qid, fc->ring.nr_queues);
			qid = 0;
		}
	}

	pr_devel("%s req=%p async=%d qid=%d\n", __func__, req, async, qid);

	queue = fuse_uring_get_queue(fc, qid);
	head = async ?  &queue->async_queue : &queue->fg_queue;
	queue_avail = async ? &queue->req_async : &queue->req_fg;

	spin_lock(&queue->lock);

	if (unlikely(queue->aborted)) {
		res = -ENOTCONN;
		goto err_unlock;
	}

	list_add_tail(&req->list, head);
	if (*queue_avail) {
		bool got_req;
		int tag = find_first_bit(queue->req_avail_map, queue_depth);

		if (unlikely(tag == queue_depth)) {
			pr_err("queue: no free bit found for qid=%d "
				"qdepth=%zu av-fg=%d av-async=%d max-fg=%zu "
				"max-async=%zu is_async=%d\n", queue->qid,
				queue_depth, queue->req_fg, queue->req_async,
				fc->ring.max_fg, fc->ring.max_async, async);

			WARN_ON(1);
			res = -ENOENT;
			goto err_unlock;
		}
		ring_ent = &queue->ring_ent[tag];
		got_req = fuse_uring_assign_ring_entry(ring_ent, head, async);
		if (unlikely(!got_req)) {
			WARN_ON(1);
			ring_ent = NULL;
		}
	}
	spin_unlock(&queue->lock);

	if (ring_ent != NULL)
		fuse_uring_send_to_ring(ring_ent, IO_URING_F_UNLOCKED);

	return 0;

err_unlock:
	spin_unlock(&queue->lock);
	return res;
}

/*
 * Checks for errors and stores it into the request
 */
static int fuse_uring_ring_ent_has_err(struct fuse_conn *fc,
				       struct fuse_ring_ent *ring_ent)
{
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
		pr_devel("%s:%d err=%d op=%d req-ret=%d",
			 __func__, __LINE__, err, req->args->opcode,
			 req->out.h.error);
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
			/* XXX Needs to copy to the next cq and submit it */
			// err = queue_interrupt(req);
			pr_warn("Intrerupt EAGAIN not supported yet");
			err = -EINVAL;
		}

		goto seterr;
	}

	return 0;

seterr:
	pr_devel("%s:%d err=%d op=%d req-ret=%d",
		 __func__, __LINE__, err, req->args->opcode,
		 req->out.h.error);
	oh->error = err;
err:
	pr_devel("%s:%d err=%d op=%d req-ret=%d",
		 __func__, __LINE__, err, req->args->opcode,
		 req->out.h.error);
	return err;
}

/**
 * Read data from the ring buffer, which user space has written to
 * This is comparible with handling of classical write(/dev/fuse).
 * Also make the ring request available again for new fuse requests.
 */
static void fuse_uring_commit_and_release(struct fuse_dev *fud,
					  struct fuse_ring_ent *ring_ent)
{
	struct fuse_ring_req *rreq = ring_ent->rreq;
	struct fuse_req *req = ring_ent->fuse_req;
	ssize_t err = 0;
	bool set_err = false;

	req->out.h = rreq->out;

	err = fuse_uring_ring_ent_has_err(fud->fc, ring_ent);
	if (err) {
		/* req->out.h.error already set */
		pr_devel("%s:%d err=%zd oh->err=%d\n",
			 __func__, __LINE__, err, req->out.h.error);
		goto out;
	}

	err = fuse_uring_copy_from_ring(fud->fc, req, rreq);
	if (err)
		set_err = true;

out:
	pr_devel("%s:%d ret=%zd op=%d req-ret=%d\n",
		 __func__, __LINE__, err, req->args->opcode, req->out.h.error);
	fuse_uring_req_end_and_get_next(ring_ent, set_err, err);
}

/*
 * Release a ring request, it is no longer needed and can handle new data
 *
 */
static void fuse_uring_ent_release(struct fuse_ring_ent *ring_ent,
					   struct fuse_ring_queue *queue,
					   bool async)
__must_hold(&queue->lock)
{
	struct fuse_conn *fc = queue->fc;

	/* unsets all previous flags - basically resets */
	pr_devel("%s fc=%p qid=%d tag=%d state=%llu async=%d\n",
		__func__, fc, ring_ent->queue->qid, ring_ent->tag,
		ring_ent->state, async);

	if (ring_ent->state & FRRS_USERSPACE) {
		pr_warn("%s qid=%d tag=%d state=%llu async=%d\n",
			__func__, ring_ent->queue->qid, ring_ent->tag,
			ring_ent->state, async);
		WARN_ON(1);
		return;
	}

	fuse_uring_bit_set(ring_ent, async, __func__);

	/* Check if this is call through shutdown/release task and already and
	 * the request is about to be released - the state must not be reset
	 * then, as state FRRS_FUSE_WAIT would introduce a double
	 * io_uring_cmd_done
	 */
	if (ring_ent->state & FRRS_FREEING)
		return;

	/* Note: the bit in req->flag got already cleared in fuse_request_end */
	ring_ent->rreq->flags = 0;
	ring_ent->state = FRRS_FUSE_WAIT;
}

/*
 * Release a uring entry and fetch the next fuse request if available
 */
static bool fuse_uring_ent_release_and_fetch(struct fuse_ring_ent *ring_ent)
{
	struct fuse_ring_queue *queue = ring_ent->queue;
	bool async = !!(ring_ent->rreq->flags & FUSE_RING_REQ_FLAG_ASYNC);
	bool send = false;
	struct list_head *head = async ? &queue->async_queue : &queue->fg_queue;

	spin_lock(&ring_ent->queue->lock);
	fuse_uring_ent_release(ring_ent, queue, async);
	send = fuse_uring_assign_ring_entry(ring_ent, head, async);
	spin_unlock(&ring_ent->queue->lock);

	return send;
}

/**
 * Simplified ring-entry release function, for shutdown only
 */
static void _fuse_uring_shutdown_release_ent(struct fuse_ring_ent *ent)
__must_hold(&queue->lock)
{
	bool async = !!(ent->rreq->flags & FUSE_RING_REQ_FLAG_ASYNC);

	ent->state |= FRRS_FUSE_REQ_END;
	ent->need_req_end = 0;
	fuse_request_end(ent->fuse_req);
	ent->fuse_req = NULL;
	fuse_uring_bit_set(ent, async, __func__);
}

/*
 * Release a request/entry on connection shutdown
 */
static void fuse_uring_shutdown_release_ent(struct fuse_ring_ent *ent)
__must_hold(&fc->ring.start_stop_lock)
__must_hold(&queue->lock)
{
	struct fuse_ring_queue *queue = ent->queue;
	struct fuse_conn *fc = queue->fc;
	bool may_release = false;
	int state;

	pr_devel("%s fc=%p qid=%d tag=%d state=%llu\n",
		 __func__, fc, queue->qid, ent->tag, ent->state);

	if (ent->state & FRRS_FREED)
		goto out; /* no work left, freed before */

	state = ent->state;

	if (state == FRRS_INIT || state == FRRS_FUSE_WAIT ||
	    ((state & FRRS_USERSPACE) && queue->aborted)) {
		ent->state |= FRRS_FREED;

		if (ent->need_cmd_done) {
			pr_devel("qid=%d tag=%d sending cmd_done\n",
				queue->qid, ent->tag);
			io_uring_cmd_done(ent->cmd, -ENOTCONN, 0,
					  IO_URING_F_UNLOCKED);
			ent->need_cmd_done = 0;
		}

		if (ent->need_req_end)
			_fuse_uring_shutdown_release_ent(ent);
		may_release = true;
	} else {
		/* somewhere in between states, another thread should currently
		 * handle it
		 */
		pr_devel("%s qid=%d tag=%d state=%llu\n",
			 __func__, queue->qid, ent->tag, ent->state);
	}

out:
	/* might free the queue - needs to have the queue waitq lock released */
	if (may_release) {
		int refs = --fc->ring.queue_refs;

		pr_devel("free-req fc=%p qid=%d tag=%d refs=%d\n",
			 fc, queue->qid, ent->tag, refs);
		if (refs == 0) {
			fc->ring.queues_stopped = 1;
			wake_up_all(&fc->ring.stop_waitq);
		}
	}
}

static void fuse_uring_stop_queue(struct fuse_ring_queue *queue)
__must_hold(&fc->ring.start_stop_lock)
__must_hold(&queue->lock)
{
	struct fuse_conn *fc = queue->fc;
	int tag;
	bool empty =
		(list_empty(&queue->fg_queue) && list_empty(&queue->fg_queue));

	if (!empty && !queue->aborted)
		return;

	for (tag = 0; tag < fc->ring.queue_depth; tag++) {
		struct fuse_ring_ent *ent = &queue->ring_ent[tag];

		fuse_uring_shutdown_release_ent(ent);
	}
}

/*
 *  Stop the ring queues
 */
static void fuse_uring_stop_queues(struct fuse_conn *fc)
__must_hold(fc->ring.start_stop_lock)
{
	int qid;

	if (fc->ring.daemon == NULL)
		return;

	fc->ring.stop_requested = 1;
	fc->ring.ready = 0;

	for (qid = 0; qid < fc->ring.nr_queues; qid++) {
		struct fuse_ring_queue *queue =
			fuse_uring_get_queue(fc, qid);

		if (!queue->configured)
			continue;

		spin_lock(&queue->lock);
		fuse_uring_stop_queue(queue);
		spin_unlock(&queue->lock);
	}
}

/*
 * monitoring functon to check if fuse shall be destructed, run
 * as delayed task
 */
static void fuse_uring_stop_mon(struct work_struct *work)
{
	struct fuse_conn *fc = container_of(work, struct fuse_conn,
					    ring.stop_monitor.work);
	struct fuse_iqueue *fiq = &fc->iq;

	pr_devel("fc=%p running stop-mon, queues-stopped=%u queue-refs=%d\n",
		fc, fc->ring.queues_stopped, fc->ring.queue_refs);

	mutex_lock(&fc->ring.start_stop_lock);

	if (!fiq->connected || fc->ring.stop_requested ||
	    (fc->ring.daemon->flags & PF_EXITING)) {
		pr_devel("%s Stopping queues connected=%d stop-req=%d exit=%d\n",
			__func__, fiq->connected, fc->ring.stop_requested,
			(fc->ring.daemon->flags & PF_EXITING));
		fuse_uring_stop_queues(fc);
	}

	if (!fc->ring.queues_stopped)
		schedule_delayed_work(&fc->ring.stop_monitor,
				      FURING_DAEMON_MON_PERIOD);
	else
		pr_devel("Not scheduling work queues-stopped=%u queue-refs=%d.\n",
			fc->ring.queues_stopped,  fc->ring.queue_refs);

	mutex_unlock(&fc->ring.start_stop_lock);
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

/* Update conn limits according to ring values */
static void fuse_uring_conn_cfg_limits(struct fuse_conn *fc)
{
	WRITE_ONCE(fc->max_pages,
		   min_t(unsigned int, fc->max_pages,
			      fc->ring.req_arg_len / PAGE_SIZE));

	/* This not ideal, as multiplication with nr_queue assumes the limit
	 * gets reached when all queues are used, but a single threaded
	 * application might already do that.
	 */
	WRITE_ONCE(fc->max_background,
		   fc->ring.nr_queues * fc->ring.max_async);
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

	INIT_DELAYED_WORK(&fc->ring.stop_monitor,
			  fuse_uring_stop_mon);
	schedule_delayed_work(&fc->ring.stop_monitor,
			      FURING_DAEMON_MON_PERIOD);

	fc->ring.nr_queues = cfg->nr_queues;
	fc->ring.per_core_queue = cfg->nr_queues > 1;

	fc->ring.max_fg = cfg->fg_queue_depth;
	fc->ring.max_async = cfg->async_queue_depth;
	fc->ring.queue_depth = cfg->fg_queue_depth + cfg->async_queue_depth;

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
	queue->req_async = 0;
	bitmap_zero(queue->req_avail_map, fc->ring.queue_depth);
	spin_lock_init(&queue->lock);
	INIT_LIST_HEAD(&queue->fg_queue);
	INIT_LIST_HEAD(&queue->async_queue);

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

/**
 * Wait until uring shall be destructed and then release uring resources
 */
static int fuse_uring_wait_stop(struct fuse_conn *fc)
{
	struct fuse_iqueue *fiq = &fc->iq;

	pr_devel("%s stop_requested=%d", __func__, fc->ring.stop_requested);

	if (fc->ring.stop_requested)
		return -EINTR;

	/* This userspace thread can stop uring on process stop, no need
	 * for the interval worker
	 */
	pr_devel("%s cancel stop monitor\n", __func__);
	cancel_delayed_work_sync(&fc->ring.stop_monitor);

	wait_event_interruptible(fc->ring.stop_waitq,
				 !fiq->connected ||
				 fc->ring.stop_requested);

	/* The userspace task gets scheduled to back userspace, we need
	 * the interval worker again. It runs immediately for quick cleanup
	 * in shutdown/process kill.
	 */

	mutex_lock(&fc->ring.start_stop_lock);
	if (!fc->ring.queues_stopped)
		mod_delayed_work(system_wq, &fc->ring.stop_monitor, 0);
	mutex_unlock(&fc->ring.start_stop_lock);

	return 0;
}

static int fuse_uring_shutdown_wakeup(struct fuse_conn *fc)
{
	fc->ring.stop_requested = 1;
	wake_up_all(&fc->ring.stop_waitq);

	return 0;
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

	pr_devel("%s fc=%p flags=%x cmd=%d qid=%d nq=%d fg=%d async=%d\n",
		 __func__, fc, cfg->flags, cfg->cmd, cfg->qid, cfg->nr_queues,
		 cfg->fg_queue_depth, cfg->async_queue_depth);


	switch (cfg->cmd) {
	case FUSE_URING_IOCTL_CMD_QUEUE_CFG:
		return fuse_uring_cfg(fc, cfg->qid, cfg);
	case FUSE_URING_IOCTL_CMD_WAIT:
		return fuse_uring_wait_stop(fc);
	case FUSE_URING_IOCTL_CMD_STOP:
		return fuse_uring_shutdown_wakeup(fc);
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

	cancel_delayed_work_sync(&fc->ring.stop_monitor);
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
				io_uring_cmd_done(ent->cmd, -ENOTCONN, 0,
						  IO_URING_F_UNLOCKED);
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

/**
 * fuse uring mmap, per ring qeuue. The queue is identified by the offset
 * parameter
 */
int fuse_uring_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct fuse_dev *fud = fuse_get_dev(filp);
	struct fuse_conn *fc = fud->fc;
	size_t sz = vma->vm_end - vma->vm_start;
	unsigned int qid;
	int ret;
	loff_t off;
	struct fuse_ring_queue *queue;

	/* check if uring is configured and if the requested size matches */
	if (fc->ring.nr_queues == 0 || fc->ring.queue_depth == 0) {
		ret = -EINVAL;
		goto out;
	}

	if (sz != fc->ring.queue_buf_size) {
		ret = -EINVAL;
		pr_devel("mmap size mismatch, expected %zu got %zu\n",
			 fc->ring.queue_buf_size, sz);
		goto out;
	}

	/* XXX: Enforce a cloned session per ring and assign fud per queue
	 * and use fud as key to find the right queue?
	 */
	off = (vma->vm_pgoff << PAGE_SHIFT) / PAGE_SIZE;
	qid = off / (fc->ring.queue_depth);

	queue = fuse_uring_get_queue(fc, qid);

	if (queue == NULL) {
		pr_devel("fuse uring mmap: invalid qid=%u\n", qid);
		return -ERANGE;
	}

	ret = remap_vmalloc_range(vma, queue->queue_req_buf, 0);
out:
	pr_devel("%s: pid %d qid: %u addr: %p sz: %zu  ret: %d\n",
		 __func__, current->pid, qid, (char *)vma->vm_start,
		 sz, ret);

	return ret;
}

/*
 * fuse_uring_req_fetch command handling
 */
static int fuse_uring_fetch(struct fuse_ring_ent *ring_ent,
			    struct io_uring_cmd *cmd)
{
	struct fuse_ring_queue *queue = ring_ent->queue;
	struct fuse_conn *fc = queue->fc;
	int ret = 0;
	bool async = false;
	int nr_queue_init = 0;

	spin_lock(&queue->lock);

	/* register requests for foreground requests first, then backgrounds */
	if (queue->req_fg >= fc->ring.max_fg)
		async = true;
	fuse_uring_ent_release(ring_ent, queue, async);

	/* daemon side registered all requests, this queue is complete */
	if (queue->req_fg + queue->req_async == fc->ring.queue_depth)
		nr_queue_init =
			atomic_inc_return(&fc->ring.nr_queues_cmd_init);

	if (queue->req_fg + queue->req_async > fc->ring.queue_depth) {
		/* should be caught by ring state before and queue depth
		 * check before
		 */
		WARN_ON(1);
		pr_info("qid=%d tag=%d req cnt (fg=%d async=%d exceeds depth=%zu",
			queue->qid, ring_ent->tag, queue->req_fg,
			queue->req_async, fc->ring.queue_depth);
		ret = -ERANGE;

		/* avoid completion through fuse_req_end, as there is no
		 * fuse req assigned yet
		 */
		ring_ent->state = FRRS_INIT;
	}

	pr_devel("%s:%d qid=%d tag=%d nr-fg=%d nr-async=%d nr_queue_init=%d\n",
		__func__, __LINE__,
		queue->qid, ring_ent->tag, queue->req_fg, queue->req_async,
		nr_queue_init);

	spin_unlock(&queue->lock);
	if (ret)
		goto out; /* erange */

	WRITE_ONCE(ring_ent->cmd, cmd);

	if (nr_queue_init == fc->ring.nr_queues) {
		fuse_uring_conn_cfg_limits(fc);
		fc->ring.ready = 1;
	}

out:
	return ret;
}

struct fuse_ring_queue *
fuse_uring_get_verify_queue(struct fuse_conn *fc,
			 const struct fuse_uring_cmd_req *cmd_req,
			 unsigned int issue_flags)
{
	struct fuse_ring_queue *queue;
	int ret;

	if (!(issue_flags & IO_URING_F_SQE128)) {
		pr_info("qid=%d tag=%d SQE128 not set\n",
			cmd_req->qid, cmd_req->tag);
		ret =  -EINVAL;
		goto err;
	}

	if (unlikely(fc->ring.stop_requested)) {
		ret = -ENOTCONN;
		goto err;
	}

	if (unlikely(!fc->ring.configured)) {
		pr_info("command for a conection that is not ring configure\n");
		ret = -ENODEV;
		goto err;
	}

	if (unlikely(cmd_req->qid >= fc->ring.nr_queues)) {
		pr_devel("qid=%u >= nr-queues=%zu\n",
			cmd_req->qid, fc->ring.nr_queues);
		ret = -EINVAL;
		goto err;
	}

	queue = fuse_uring_get_queue(fc, cmd_req->qid);
	if (unlikely(queue == NULL)) {
		pr_info("Got NULL queue for qid=%d\n", cmd_req->qid);
		ret = -EIO;
		goto err;
	}

	if (unlikely(!fc->ring.configured || !queue->configured ||
		     queue->aborted)) {
		pr_info("Ring or queue (qid=%u) not ready.\n", cmd_req->qid);
		ret = -ENOTCONN;
		goto err;
	}

	if (cmd_req->tag > fc->ring.queue_depth) {
		pr_info("tag=%u > queue-depth=%zu\n",
			cmd_req->tag, fc->ring.queue_depth);
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
	const struct fuse_uring_cmd_req *cmd_req =
		(struct fuse_uring_cmd_req *)cmd->cmd;
	struct fuse_dev *fud = fuse_get_dev(cmd->file);
	struct fuse_conn *fc = fud->fc;
	struct fuse_ring_queue *queue;
	struct fuse_ring_ent *ring_ent = NULL;
	u32 cmd_op = cmd->cmd_op;
	u64 prev_state;
	int ret = 0;

	queue = fuse_uring_get_verify_queue(fc, cmd_req, issue_flags);
	if (IS_ERR(queue)) {
		ret = PTR_ERR(queue);
		goto out;
	}

	ring_ent = &queue->ring_ent[cmd_req->tag];

	pr_devel("%s:%d received: cmd op %d qid %d (%p) tag %d  (%p)\n",
		 __func__, __LINE__,
		 cmd_op, cmd_req->qid, queue, cmd_req->tag, ring_ent);

	spin_lock(&queue->lock);
	if (unlikely(queue->aborted)) {
		/* XXX how to ensure queue still exists? Add
		 * an rw fc->ring.stop lock? And take that at the beginning
		 * of this function? Better would be to advise uring
		 * not to call this function at all? Or free the queue memory
		 * only, on daemon PF_EXITING?
		 */
		ret = -ENOTCONN;
		spin_unlock(&queue->lock);
		goto out;
	}

	prev_state = ring_ent->state;
	ring_ent->state |= FRRS_FUSE_FETCH_COMMIT;
	ring_ent->state &= ~FRRS_USERSPACE;
	ring_ent->need_cmd_done = 1;
	spin_unlock(&queue->lock);

	switch (cmd_op) {
	case FUSE_URING_REQ_FETCH:
		if (prev_state != FRRS_INIT) {
			pr_info_ratelimited("register req state %llu expected %d",
					    prev_state, FRRS_INIT);
			ret = -EINVAL;
			goto out;

			/* XXX error injection or test with malicious daemon */
		}

		ret = fuse_uring_fetch(ring_ent, cmd);
		break;
	case FUSE_URING_REQ_COMMIT_AND_FETCH:
		if (unlikely(!fc->ring.ready)) {
			pr_info("commit and fetch, but the ring is not ready yet");
			goto out;
		}

		if (!(prev_state & FRRS_USERSPACE)) {
			pr_info("qid=%d tag=%d state %llu misses %d\n",
				queue->qid, ring_ent->tag, ring_ent->state,
				FRRS_USERSPACE);
			goto out;
		}

		/* XXX Test inject error */

		WRITE_ONCE(ring_ent->cmd, cmd);
		fuse_uring_commit_and_release(fud, ring_ent);

		ret = 0;
		break;
	default:
		ret = -EINVAL;
		pr_devel("Unknown uring command %d", cmd_op);
		goto out;
	}

out:
	pr_devel("uring cmd op=%d, qid=%d tag=%d ret=%d\n",
		 cmd_op, cmd_req->qid, cmd_req->tag, ret);

	if (ret < 0) {
		if (ring_ent != NULL) {
			spin_lock(&queue->lock);
			ring_ent->state |= (FRRS_CMD_ERR | FRRS_USERSPACE);
			ring_ent->need_cmd_done = 0;
			spin_unlock(&queue->lock);
		}
		io_uring_cmd_done(cmd, ret, 0, issue_flags);
	}

	return -EIOCBQUEUED;
}
