/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
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
#include <asm/io.h>
#include <linux/io_uring.h>
#include <linux/topology.h>

/* default monitor interval for a dying daemon */
#define FURING_DAEMON_MON_PERIOD (5 * HZ)

static void fuse_dev_uring_req_release(struct fuse_ring_req *ring_req);


static struct fuse_ring_queue *
fuse_uring_get_queue(struct fuse_conn *fc, int qid)
{
	char *ptr = (char *)fc->ring.queues;

	if (unlikely(qid > fc->ring.nr_queues))
		return NULL;

	return (struct fuse_ring_queue *)(ptr + qid * fc->ring.queue_size);
}

static void
fuse_uring_request_end(struct fuse_ring_req *ring_req, bool set_err, int error)
{
	bool already = false;
	struct fuse_req *req = &ring_req->req;


	spin_lock(&ring_req->queue->waitq.lock);
	if (ring_req->state & FRRS_FUSE_REQ_END)
		already = true;
	else
		ring_req->state |= FRRS_FUSE_REQ_END;
	spin_unlock(&ring_req->queue->waitq.lock);

	if (already) {
		WARN_ON(1);
		return;
	}

	if (set_err)
		req->out.h.error = error;

	if (ring_req->req_ptr) {
		*ring_req->req_ptr = *req;
		fuse_request_end(ring_req->req_ptr);
		ring_req->req_ptr = NULL;

		/* release the ring req, typically it is done through
		 * fuse_request_end, but here the fuse req is just an
		 * attached pointer - we need to release the ring-request
		 * on our on own */
		fuse_dev_uring_req_release(ring_req);
	} else
		fuse_request_end(req);
}

static int fuse_uring_copy_to_ring(struct fuse_conn *fc,
				   struct fuse_req *req,
				   struct fuse_uring_buf_req *buf_req)
{
	struct fuse_copy_state cs;
	struct fuse_args *args = req->args;
	int err;
	size_t max_buf = sizeof(buf_req->in_out_arg) + fc->ring.req_buf_sz;

	fuse_copy_init(&cs, 1, NULL);
	cs.is_uring = 1;
	cs.ring.buf = buf_req->in_out_arg;
	cs.ring.len = max_buf;
	cs.req = req;

	pr_devel("%s:%d buf=%p len=%d args=%d\n", __func__, __LINE__,
		 cs.ring.buf, cs.ring.len, args->out_numargs);

	err = fuse_copy_args(&cs, args->in_numargs, args->in_pages,
			     (struct fuse_arg *) args->in_args, 0);
	buf_req->in_out_arg_len = cs.ring.offset;

	pr_devel("%s:%d buf=%p len=%d args=%d err=%d\n", __func__, __LINE__,
		 cs.ring.buf, cs.ring.len, args->out_numargs, err);

	return err;
}

static int fuse_uring_copy_from_ring(struct fuse_conn *fc,
				     struct fuse_req *req,
				     struct fuse_uring_buf_req *buf_req)
{
	struct fuse_copy_state cs;
	struct fuse_args *args = req->args;
	size_t max_buf = sizeof(buf_req->in_out_arg) + fc->ring.req_buf_sz;

	fuse_copy_init(&cs, 0, NULL);
	cs.is_uring = 1;
	cs.ring.buf = buf_req->in_out_arg;

	if (buf_req->in_out_arg_len > max_buf) {
		pr_devel("Max ring buffer len exceeded (%u vs %zu\n",
			 buf_req->in_out_arg_len, max_buf);
		return -EINVAL;
	}
	cs.ring.len = buf_req->in_out_arg_len;
	cs.req = req;

	pr_devel("%s:%d buf=%p len=%d args=%d\n", __func__, __LINE__,
		 cs.ring.buf, cs.ring.len, args->out_numargs);

	return copy_out_args(&cs, args, buf_req->in_out_arg_len);
}

/**
 * Write data to the ring buffer and send the request to userspace,
 * userspace will read it
 * This is comparable with classical read(/dev/fuse)
 */
int fuse_dev_uring_send_to_ring(struct fuse_ring_req *ring_req)
{
	struct fuse_conn *fc = ring_req->queue->fc;
	struct fuse_uring_buf_req *buf_req = ring_req->kbuf;
	struct fuse_req *req = &ring_req->req;
	int err = 0;

	pr_devel("%s:%d ring-req=%p buf_req=%p state=%llu args=%p \n", __func__,
		 __LINE__, ring_req, buf_req, ring_req->state, req->args);

	spin_lock(&ring_req->queue->waitq.lock);
	if (unlikely((ring_req->state & FRRS_USERSPACE) ||
		     (ring_req->state & FRRS_FREED))) {
		pr_err("ring-req=%p buf_req=%p invalid state %llu on send\n",
		       ring_req, buf_req, ring_req->state);
		WARN_ON(1);
		err = -EIO;
	} else
		ring_req->state |= FRRS_USERSPACE;

	spin_unlock(&ring_req->queue->waitq.lock);
	if (err)
		goto err;

	err = fuse_uring_copy_to_ring(fc, req, buf_req);
	if (err)
		goto err;

	/* ring req go directly into the shared memory buffer */
	buf_req->in = req->in.h;

	pr_devel("%s qid=%d tag=%d state=%llu cmd-done op=%d unique=%llu\n",
		__func__, ring_req->queue->qid, ring_req->tag, ring_req->state,
		buf_req->in.opcode, buf_req->in.unique);

	io_uring_cmd_done(ring_req->cmd, 0, 0);

	return 0;

err:
	fuse_uring_request_end(ring_req, true, err);
	return err;
}

static void fuse_dev_uring_bit_set(struct fuse_ring_req *ring_req, bool bg,
				   const char *str)
__must_hold(ring_req->queue->waitq.lock)
{
	int old;
	struct fuse_ring_queue *queue = ring_req->queue;
	const struct fuse_conn *fc = queue->fc;
	int tag = ring_req->tag;

	old = test_and_set_bit(tag, queue->req_avail_map);
	if (unlikely(old != 0)) {
		pr_warn("%8s invalid bit value on clear for qid=%d tag=%d",
			str, queue->qid, tag);
		WARN_ON(1);
	}
	if (bg)
		queue->req_bg++;
	else {
		queue->req_fg++;
		wake_up_locked(&queue->waitq);
	}

	pr_devel("%35s ring bit set   fc=%p is_bg=%d qid=%d tag=%d fg=%d bg=%d "
		 "bgq: %d\n",
		 str, fc, bg, queue->qid, ring_req->tag, queue->req_fg,
		 queue->req_bg, !list_empty(&queue->bg_queue));
}

static int fuse_dev_uring_bit_clear(struct fuse_ring_req *ring_req, bool bg,
				     const char *str)
__must_hold(ring_req->queue->waitq.lock)
{
	int old;
	struct fuse_ring_queue *queue = ring_req->queue;
	const struct fuse_conn *fc = queue->fc;
	int tag = ring_req->tag;
	int *value = bg ? &queue->req_bg : &queue->req_fg;

	if (unlikely(*value <= 0)) {
		pr_warn("%s bug: qid=%d tag=%d is_bg=%d "
			"zero requests available fg=%d bg=%d\n",
			str, queue->qid, ring_req->tag, bg,
			queue->req_bg, queue->req_fg);
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

	ring_req->kbuf->flags = 0;

	if (bg) {
		ring_req->kbuf->flags |= FUSE_RING_REQ_FLAG_BACKGROUND;
		queue->req_bg--;
	} else
		queue->req_fg--;

	pr_devel("%35s ring bit clear fc=%p is_bg=%d qid=%d tag=%d fg=%d bg=%d \n",
		 str, fc, bg, queue->qid, ring_req->tag,
		 queue->req_fg, queue->req_bg);

	ring_req->state |= FRRS_FUSE_REQ;

	return 0;
}

/*
 * Take the next (first) entry from the queue list and assign it to the given
 * request
 */
static bool fuse_dev_uring_get_bg_entry(struct fuse_ring_queue *queue,
					 struct fuse_ring_req *ring_req)
__must_hold(&queue.waitq.lock)
{
	struct fuse_req *req;
	int res;

	if (list_empty(&queue->bg_queue))
		return false;

	res = fuse_dev_uring_bit_clear(ring_req, 1, __func__);
	if (unlikely(res))
		return false;

	req = list_first_entry(&queue->bg_queue, struct fuse_req, list);
	list_del_init(&req->list);
	clear_bit(FR_PENDING, &req->flags);
	ring_req->req_ptr = req;
	ring_req->req = *req;

	return true;
}

int fuse_dev_uring_queue_bg(struct fuse_conn *fc, struct fuse_req *req)
{
	struct fuse_ring_queue *queue;
	int qid = 0;
	struct fuse_ring_req *ring_req = NULL;
	const size_t queue_depth = fc->ring.queue_depth;
	int res;

	pr_devel("%s req=%p bg=%d\n",
		__func__, req, test_bit(FR_BACKGROUND, &req->flags));

	if (fc->ring.per_core_queue) {
		qid = task_cpu(current);
		if (unlikely(qid) >= fc->ring.nr_queues) {
			WARN_ONCE(1, "Core number (%u) exceeds nr of ring "
				  "queues (%zu)\n", qid, fc->ring.nr_queues);
			qid = 0;
		}
	}

	queue = fuse_uring_get_queue(fc, qid);
	spin_lock(&queue->waitq.lock);
	list_add_tail(&req->list, &queue->bg_queue);
	if (queue->req_bg) {
		bool got_req;

		/* the request was allocated from memory, but in the mean time
		 * the queue has an empty slot  */
		int tag = find_first_bit(queue->req_avail_map, queue_depth);

		if (unlikely(tag == queue_depth)) {
			pr_err("queue bg: no free bit found for qid=%d "
				"qdepth=%zu av-fg=%d av-bg=%d max-fg=%zu "
				"max-bg=%zu\n", queue->qid,
				queue_depth, queue->req_fg, queue->req_bg,
				fc->ring.max_fg, fc->ring.max_bg);

			WARN_ON(1);
			res = -ENOENT;
			goto err_unlock;
		}
		ring_req = &queue->ring_req[tag];
		got_req = fuse_dev_uring_get_bg_entry(queue, ring_req);
		if (unlikely(!got_req)) {
			WARN_ON(1);
			ring_req = NULL;
		}
	}
	spin_unlock(&queue->waitq.lock);

	if (ring_req != NULL)
		fuse_dev_uring_send_to_ring(ring_req);

	return 0;

err_unlock:
	spin_unlock(&queue->waitq.lock);
	return res;
}

/*
 * Checks for errors and stores it into the request
 */
static int fuse_dev_uring_ring_req_has_err(struct fuse_conn *fc,
				       struct fuse_ring_req *ring_req)
{
	struct fuse_req *req = &ring_req->req;
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

	/* Is it an interrupt reply ID?
	 * XXX: Verifiy if right
	 */
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
 * This is comparible with classical write(/dev/fuse) and also make the ring
 * request available again
 */
static void fuse_dev_uring_commit_and_release(struct fuse_dev *fud,
					      struct fuse_ring_req *ring_req)
{
	struct fuse_uring_buf_req *buf_req = ring_req->kbuf;
	struct fuse_req *req = &ring_req->req;
	ssize_t err = 0;
	bool set_err = false;

	pr_devel("%s:%d req=%p\n", __func__, __LINE__, req);

	req->out.h = buf_req->out;

	err = fuse_dev_uring_ring_req_has_err(fud->fc, ring_req);
	if (err) {
		/* req->out.h.error already set */
		pr_devel("%s:%d err=%zd oh->err=%d \n", __func__, __LINE__,
			 err, req->out.h.error);
		goto out;
	}

	err = fuse_uring_copy_from_ring(fud->fc, req, buf_req);
	if (err)
		set_err = true;

out:
	pr_devel("%s:%d ret=%zd op=%d req-ret=%d",
		 __func__, __LINE__, err, req->args->opcode, req->out.h.error);
	fuse_uring_request_end(ring_req, set_err, err);
	return;
}

/**
 * Check if an application command was queued into the list-queue
 *
 * @return 1 if a reqesust was taken from the queue, 0 if the queue was empty
 * 	   negative values on error
 *
 * negative values for error
 */
static int fuse_dev_uring_fetch_fc(struct fuse_conn *fc,
				   struct fuse_ring_queue *queue,
				   struct fuse_ring_req *ring_req)
{
	struct fuse_iqueue *fiq = &fc->iq;
	struct fuse_req *q_req = NULL;
	int ret;
	bool bg;

	spin_lock(&fiq->lock);
	if (!list_empty(&fiq->pending)) {
		q_req = list_entry(fiq->pending.next, struct fuse_req, list);
		clear_bit(FR_PENDING, &q_req->flags);
		list_del_init(&q_req->list);
	}
	spin_unlock(&fiq->lock);

	if (!q_req)
		return 0; /* no request to handle */

	if (test_bit(FR_BACKGROUND, &q_req->flags))
		bg = true;

	pr_devel("%s: args=%p ring-args=%p req=%p list-req=%p\n",
		 __func__, q_req->args, ring_req->req.args, &ring_req->req, q_req);

	spin_lock(&queue->waitq.lock);
	ret = fuse_dev_uring_bit_clear(ring_req, bg, __func__);
	spin_unlock(&queue->waitq.lock);

	if (unlikely(ret))
		return ret;

	/* copy over and store the initial req, on completion copy back has to
	 * be done */
	ring_req->req = *q_req;
	ring_req->req_ptr = q_req;

	ret = fuse_dev_uring_send_to_ring(ring_req);
	if (ret) {
		if (unlikely(ret > 0)) {
			WARN(1, "Unexpected return code: %d", ret);
			ret = -EIO;
		}
	}
	else
		ret = 1; /* request handled */

	return ret;
}


/* This needs rework, a shared lock between numa nodes might be a problem.
 * I.e. cycling should be within a single numa node only */
#if 0

/*
 * @return locked queue for background requests, may return NULL if no queue
 * is available
 */
static struct fuse_ring_queue *
fuse_dev_uring_queue_for_background_req(struct fuse_conn *fc)
{
	unsigned int qid, cnt;
	struct fuse_ring_queue *queue = NULL;
	int retries = 0;

	/* backgnd_queue_cnt logic is to queue multiple requests to the
	 * same queue, so that userspace has the possibility to coalescence CQEs
	 * (IOs) - background requests are page cache read/writes and userspace
	 * might prefer to do large IOs, beyond fuse req max IO size.
	 */
	spin_lock(&fc->ring.backgnd_qid_lock);
	qid = fc->ring.background_qid;
	cnt = fc->ring.backgnd_queue_cnt;
	while (queue == NULL && retries != fc->ring.nr_queues) {
		if (cnt > fc->ring.max_backgnd_aggr) {
			cnt = 0;
			qid = (qid + 1) % fc->ring.nr_queues;
		}

		if (unlikely(qid >= fc->ring.nr_queues)) {
			WARN_ON(1);
			qid = 0;
			cnt = 0;
		}
		queue = fuse_uring_get_queue(fc, qid);
		cnt++;

		spin_lock(&queue->waitq.lock);

		if (queue->req_bg >= fc->ring.max_bg) {
			/* no need to wait for background requests, the caller
			 * can handle request allocation failures
			 */
			pr_devel("%s Active bg=%d max-bnd=%zu\n", __func__,
				 queue->req_bg,
				 fc->ring.max_bg);
			spin_unlock(&queue->waitq.lock);
			qid = (qid + 1) % fc->ring.nr_queues;
			cnt = 0;
			queue = NULL;
		}
		retries++;
	}

	pr_devel("background get-queue: qid %d->%d cnt %d->%d\n",
		 fc->ring.background_qid, qid, fc->ring.backgnd_queue_cnt, cnt);


	fc->ring.background_qid = qid;
	fc->ring.backgnd_queue_cnt = cnt;

	/* queue has to be kept locked, to avoid that other threads
	 * take requests and invalidate the ring.backgnd logic
	 */
	spin_unlock(&fc->ring.backgnd_qid_lock);

	return queue;
}
#endif

/*
 * @return queue to that will take the request, might be NULL if for_background
 * The returned queue is waitq locked
 */
static struct fuse_ring_queue *
fuse_dev_uring_queue_from_current_task(struct fuse_conn *fc, bool for_background)
__acquires(queue->waitq.lock)
{
	unsigned int qid = 0;
	struct fuse_ring_queue *queue;

	if (fc->ring.per_core_queue) {
		qid = task_cpu(current);
		if (unlikely(qid) >= fc->ring.nr_queues) {
			WARN_ONCE(1, "Core number (%u) exceeds nr of ring "
				  "queues (%zu)\n", qid, fc->ring.nr_queues);
			qid = 0;
		}
	}

	queue = fuse_uring_get_queue(fc, qid);
	spin_lock(&queue->waitq.lock);

	if (!for_background && !queue->req_fg) {
		/* background is in atomic context and cannot wait */
		wait_event_interruptible_exclusive_locked(queue->waitq,
			READ_ONCE(queue->req_fg) > 0);
	}

	return queue;
}

struct fuse_req *fuse_request_alloc_ring(struct fuse_mount *fm,
					 bool for_background, gfp_t flags)
{
	struct fuse_conn *fc = fm->fc;
	struct fuse_ring_queue *queue;
	struct fuse_ring_req *ring_req;
	struct fuse_req *req = NULL;
	unsigned int tag = -1, res;
	const size_t queue_depth = fc->ring.queue_depth;
	struct fuse_iqueue *fiq = &fc->iq;

	/* returned queue is locked */
	queue = fuse_dev_uring_queue_from_current_task(fc, for_background);

	if (!queue)
		return NULL;

	/* the waitq got woken up for some reason, although no request is
	 * availble - typically happens on daemon termination signal
	 */
	if (!for_background && queue->req_fg == 0)
		goto out;

	/* XXX is this needed ? */
	if (unlikely((fc->ring.daemon->flags & PF_EXITING) ||
		     !fiq->connected || fc->ring.stop_requested ||
		     (current->flags & PF_EXITING)) || queue->stop_requested) {
		goto out;
	}

	if (for_background && queue->req_bg == 0) {
		/* The ring is busy and background might run in atomic
		 * context - it cannot wait here. The request needs to be
		 * queued on a list.
		 */
		goto alloc;
	}

	pr_devel("%s qid=%d is_bg=%d fg=%d bg=%d\n",
		__func__, queue->qid, for_background,
		queue->req_fg, queue->req_bg);

	smp_mb__before_atomic();
	tag = find_first_bit(queue->req_avail_map, queue_depth);
	if (unlikely(tag == queue_depth)) {
		pr_err("ring: no free bit found for qid=%d backgnd=%d "
			"qdepth=%zu av-foregnd=%d av-backgnd=%d max-foregnd=%zu "
			"max-backgnd=%zu\n", queue->qid, for_background,
			queue_depth, queue->req_fg, queue->req_bg,
			fc->ring.max_fg, fc->ring.max_bg);
		goto out;
	}


	ring_req = &queue->ring_req[tag];
	req = &ring_req->req;

	res = fuse_dev_uring_bit_clear(ring_req, for_background, __func__);
	if (unlikely(res))
		req = NULL;

out:
	spin_unlock(&queue->waitq.lock);

	if (req) {
		memset(req, 0, sizeof(*req));
		fuse_request_init(fm, req);
		set_bit(FR_URING, &req->flags);
		clear_bit(FR_PENDING, &req->flags);

		pr_devel("%s qid=%d tag=%d is_bg=%d fg=%d bg=%d\n",
			 __func__, queue->qid, ring_req->tag, for_background,
			 queue->req_fg, queue->req_bg);
	}

	return req;

alloc:
	spin_unlock(&queue->waitq.lock);
	return fuse_request_alloc_mem(fm, flags);
}

/*
 * This is called on shutdown
 */
static void fuse_uring_shutdown_release_req(struct fuse_conn *fc,
					    struct fuse_ring_queue *queue,
					    struct fuse_ring_req *rreq)
__must_hold(&fc->ring.stop_waitq.lock)
{
	bool may_release = false;

	spin_lock(&queue->waitq.lock);

	pr_devel("%s fc=%p qid=%d tag=%d state=%llu\n",
		 __func__, fc, queue->qid, rreq->tag, rreq->state);

	if (rreq->state & FRRS_FREED)
		goto out; /* no work left, freed before */

	if ((rreq->state == FRRS_INIT) ||
	    ((rreq->state & FRRS_INIT) && (rreq->state & FRRS_USERSPACE) &&
	     (rreq->state & FRRS_CMD_ERR))) {
		may_release = true;
		rreq->state = FRRS_FREED;
		goto out; /* all done */
	}

	if (rreq->state == FRRS_FUSE_WAIT) {
		io_uring_cmd_done(rreq->cmd, -EINTR, 0);
		may_release = true;
		rreq->state = FRRS_FREED;
	} else if ((rreq->state & FRRS_USERSPACE) &&
		    !(rreq->state & FRRS_FUSE_FETCH_COMMIT) &&
		    !(rreq->state & FRRS_FREEING)) {

		/* XXX How do we know here, when the user space daemon is not
		 *     using the request anymore. On testing
		 *     fc->ring.daemon->flags & PF_EXITING we do not stop
		 *     on ctrl-c - that signal does not set FRRS_FREEING
		 */

		pr_devel("fc=%p qid=%d tag=%d state=%llu request end\n",
			 fc, queue->qid, rreq->tag, rreq->state);

		rreq->state &= ~FRRS_USERSPACE;
		rreq->state |= FRRS_FREEING;

		spin_unlock(&queue->waitq.lock);
		/* ensure there is an error code set */
		fuse_uring_request_end(rreq, true, -EINTR);
		spin_lock(&queue->waitq.lock);
		rreq->state |= FRRS_FREED;
		may_release = true;
	} else {
		/* somewhere in between states, another thread should currently
		 * handle it */
		pr_devel("%s qid=%d tag=%d state=%llu\n",
			 __func__, queue->qid, rreq->tag, rreq->state);
	}

out:
	spin_unlock(&queue->waitq.lock);

	/* might free the queue - needs to have the queue waitq lock released */
	if (may_release) {
		int refs = --fc->ring.queue_refs;
		pr_devel("free-req fc=%p qid=%d tag=%d refs=%d\n",
			 fc, queue->qid, rreq->tag, refs);
		if (refs == 0)
			wake_up_locked(&fc->ring.stop_waitq);
	}
}

/*
 * Release a ring request, it is no longer needed and can handle new data
 *
 */
static void fuse_dev_uring_req_release_locked(struct fuse_ring_req *ring_req,
					      struct fuse_ring_queue *queue,
					      bool bg)
__must_hold(&queue.waitq.lock)
{
	struct fuse_conn *fc = queue->fc;

	/* unsets all previous flags - basically resets */
	pr_devel("%s qid=%d tag=%d state=%llu bg=%d\n",
		__func__, ring_req->queue->qid, ring_req->tag, ring_req->state,
		bg);

	if (ring_req->state & FRRS_USERSPACE) {
		pr_warn("%s qid=%d tag=%d state=%llu is_bg=%d\n",
			__func__, ring_req->queue->qid, ring_req->tag,
			ring_req->state, bg);
		WARN_ON(1);
		return;
	}

	fuse_dev_uring_bit_set(ring_req, bg, __func__);

	/* Check if this is call through shutdown/release task and already and
	 * the request is about to be released - the state must not be reset
	 * then, as state FRRS_FUSE_WAIT would introduce a double
	 * io_uring_cmd_done
	 */
	if (ring_req->state & FRRS_FREEING)
		return;

	/* Note: the bit in req->flag got already cleared in fuse_request_end */
	ring_req->kbuf->flags = 0;
	ring_req->state = FRRS_FUSE_WAIT;

	/* speeds up shutdown */
	if (unlikely(queue->stop_requested))
		schedule_delayed_work(&fc->ring.stop_monitor, 0);
}

/*
 * Release a uring request, called internally of dev_uring
 */
static void fuse_dev_uring_req_release(struct fuse_ring_req *ring_req)
{
	struct fuse_ring_queue *queue = ring_req->queue;
	bool backgnd = !!(ring_req->kbuf->flags & FUSE_RING_REQ_FLAG_BACKGROUND);
	bool send = false;

	spin_lock(&queue->waitq.lock);
	fuse_dev_uring_req_release_locked(ring_req, queue, backgnd);

	if (backgnd)
		send = fuse_dev_uring_get_bg_entry(queue, ring_req);

	spin_unlock(&queue->waitq.lock);

	if (send)
		fuse_dev_uring_send_to_ring(ring_req);
}

/**
 * Release a ring request through fuse_request_end() -> ... -> fuse_put_req()
 */
void fuse_dev_uring_req_release_ext(struct fuse_req *req)
{
	struct fuse_ring_req *ring_req =
		container_of(req, struct fuse_ring_req, req);
	struct fuse_ring_queue *queue = ring_req->queue;
	bool backgnd = !!(ring_req->kbuf->flags & FUSE_RING_REQ_FLAG_BACKGROUND);
	bool send = false;

	spin_lock(&queue->waitq.lock);

	fuse_dev_uring_req_release_locked(ring_req, queue, backgnd);

	if (backgnd)
		send = fuse_dev_uring_get_bg_entry(queue, ring_req);

	spin_unlock(&queue->waitq.lock);

	if (send)
		fuse_dev_uring_send_to_ring(ring_req);
}

/*
 * FUSE_URING_REQ_FETCH command handling
 */
static int fuse_dev_uring_fetch(struct fuse_ring_req *ring_req,
				struct io_uring_cmd *cmd)
{
	struct fuse_ring_queue *queue = ring_req->queue;
	struct fuse_conn *fc = queue->fc;
	int ret;
	bool is_bg = false;
	int nr_queue_init = 0;

	spin_lock(&queue->waitq.lock);

	/* register requests for foreground requests first, then backgrounds */
	if (queue->req_fg >= fc->ring.max_fg)
		is_bg = true;
	fuse_dev_uring_req_release_locked(ring_req, queue, is_bg);

	/* daemon side registered all requests, this queue is complete */
	if (queue->req_fg + queue->req_bg == fc->ring.queue_depth)
		nr_queue_init =
			atomic_inc_return(&fc->ring.nr_queues_cmd_init);

	ret = 0;
	if (queue->req_fg + queue->req_bg > fc->ring.queue_depth) {
		/* should be caught by ring state before and queue depth
		 * check before */
		WARN_ON(1);
		pr_info("qid=%d tag=%d request counter (fg=%d bg=%d exceeds "
			"queue-depth=%zu", queue->qid, ring_req->tag,
			queue->req_fg, queue->req_bg, fc->ring.queue_depth);
		ret = -ERANGE;
	}

	pr_devel("%s:%d qid=%d tag=%d nr-fg=%d nr-bg=%d nr_queue_init=%d\n",
		__func__, __LINE__,
		queue->qid, ring_req->tag, queue->req_fg, queue->req_bg,
		nr_queue_init);

	spin_unlock(&queue->waitq.lock);
	if (ret)
		goto out; /* ERANGE */

	WRITE_ONCE(ring_req->cmd, cmd);

	/* the last reqistered request gets what is in the
	 * ring queue.
	 * XXX re-enter until the queue is empty
	 */
	if (nr_queue_init == fc->ring.nr_queues) {
		fc->ring.ready = 1;
		ret = fuse_dev_uring_fetch_fc(fc, queue, ring_req);
		if (ret < 0) {
			pr_info("q_id: %d tag: %d queue fetch err: %d\n",
				 queue->qid, ring_req->tag,
				 ret);
			goto out;
		}

		pr_devel("%s tag=%d req=%p list-req=%p bg=%d\n",
			 __func__, ring_req->tag,
			 &ring_req->req, ring_req->req_ptr,
			 test_bit(FR_BACKGROUND, &ring_req->req.flags));
		BUG_ON(ret > 1);
	}

	ret = 0;
out:
	return ret;
}

/**
 * Entry function from io_uring to handle the given passthrough command
 * (op cocde IORING_OP_URING_CMD)
 */
int fuse_dev_uring_cmd(struct io_uring_cmd *cmd, unsigned int issue_flags)
{
	const struct fuse_uring_cmd_req *cmd_req =
		(struct fuse_uring_cmd_req *)cmd->cmd;
	struct fuse_dev *fud = fuse_get_dev(cmd->file);
	struct fuse_conn *fc = fud->fc;
	struct fuse_ring_queue *queue;
	struct fuse_ring_req *ring_req = NULL;
	u32 cmd_op = cmd->cmd_op;
	int ret = -EIO;
	u64 prev_state;

	if (!(issue_flags & IO_URING_F_SQE128)) {
		pr_info("qid=%d tag=%d SQE128 not set\n",
			cmd_req->qid, cmd_req->tag);
		goto out;
	}

	if (unlikely(cmd_req->qid >= fc->ring.nr_queues)) {
		pr_info("qid=%u > nr-queues=%zu\n",
			cmd_req->qid, fc->ring.nr_queues);
		goto out;
	}

	queue = fuse_uring_get_queue(fc, cmd_req->qid);
	if (unlikely(queue == NULL)) {
		pr_info("Got NULL queue for qid=%d\n", cmd_req->qid);
		goto out;
	}

	if (unlikely(!fc->ring.configured || !queue->configured)) {
		pr_info("Ring or queue (qid=%u) not ready.\n", cmd_req->qid);
		goto out;
	}

	if (cmd_req->tag > fc->ring.queue_depth) {
		pr_info("tag=%u > queue-depth=%zu\n",
			cmd_req->tag, fc->ring.queue_depth);
		goto out;
	}
	ring_req = &queue->ring_req[cmd_req->tag];

	pr_devel("%s:%d received: cmd op %d qid %d (%p) tag %d  (%p)\n",
		 __func__, __LINE__,
		 cmd_op, cmd_req->qid, queue, cmd_req->tag, ring_req);

	spin_lock(&queue->waitq.lock);
	if (unlikely(queue->stop_requested)) {
		/* XXX how to ensure queue still exists? Add
		 * an rw fc->ring.stop lock? And take that at the beginning
		 * of this function? Better would be to advise uring
		 * not to call this function at all? Or free the queue memory
		 * only, on daemon PF_EXITING?
		 */
		ring_req = NULL;
		ret = -EINTR;
		spin_unlock(&queue->waitq.lock);
		goto out;
	}

	prev_state = ring_req->state;
	ring_req->state |= FRRS_FUSE_FETCH_COMMIT;
	ring_req->state &= ~FRRS_USERSPACE;
	spin_unlock(&queue->waitq.lock);

	switch (cmd_op) {
	case FUSE_URING_REQ_FETCH:
		if (prev_state != FRRS_INIT) {
			pr_info_ratelimited("Invalid state on req "
					    "register: %llu expected %d",
					    prev_state, FRRS_INIT);
			ret = -EINVAL;
			goto out;

			/* XXX error injection or test with malicious daemon */
		}

		ret = fuse_dev_uring_fetch(ring_req, cmd);
		break;
	case FUSE_URING_REQ_COMMIT_AND_FETCH:
		if (!(prev_state & FRRS_USERSPACE)) {
			pr_info("qid=%d tag=%d Invalid request state %llu, "
				"missing %d \n", queue->qid, ring_req->tag,
				ring_req->state, FRRS_USERSPACE);
			goto out;
		}

		/* XXX Test inject error */

		WRITE_ONCE(ring_req->cmd, cmd);
		fuse_dev_uring_commit_and_release(fud, ring_req);

		ret = 0;
		break;
	default:
		ret = -EINVAL;
		pr_devel("Unknown uring command %d", cmd_op);
		goto out;
	}

out:
	pr_devel("uring cmd op=%d, qid=%d tag=%d ret=%d\n",
		 cmd_op, queue->qid, cmd_req->tag, ret);

	if (ret < 0 && ring_req != NULL) {
		spin_lock(&queue->waitq.lock);
		ring_req->state |= (FRRS_CMD_ERR | FRRS_USERSPACE);
		spin_unlock(&queue->waitq.lock);

		io_uring_cmd_done(cmd, ret, 0);
	}

	return -EIOCBQUEUED;
}

/**
 * Finalize the ring destruction when queue ref counters are zero.
 *
 * Has to be called with
 */
void fuse_uring_ring_destruct(struct fuse_conn *fc)
{
	unsigned qid;

	if (READ_ONCE(fc->ring.queue_refs) != 0) {
		WARN_ON(1);
		return;
	}

	for (qid = 0; qid < fc->ring.nr_queues; qid++) {
		struct fuse_ring_queue *queue = fuse_uring_get_queue(fc, qid);
		vfree(queue->queue_req_buf);
	}

	cancel_delayed_work_sync(&fc->ring.stop_monitor);

	kfree(fc->ring.queues);
	fc->ring.nr_queues_ioctl_init = 0;
	fc->ring.queues = NULL;
	fc->ring.queue_depth = 0;
	fc->ring.nr_queues = 0;

	put_task_struct(fc->ring.daemon);
	fc->ring.daemon = NULL;
}

/* Abort all list queued request on the given ring queue */
static void fuse_uring_end_requests(struct fuse_ring_queue *queue)
{
	spin_lock(&queue->waitq.lock);
	while (!list_empty(&queue->bg_queue)) {
		struct fuse_req *req =
			list_first_entry(&queue->bg_queue,
					 struct fuse_req, list);
		req->out.h.error = -ECONNABORTED;
		clear_bit(FR_SENT, &req->flags);
		clear_bit(FR_PENDING, &req->flags);
		list_del_init(&req->list);

		spin_unlock(&queue->waitq.lock);
		/* This might call back into the ring queue and try to take
		 * the lock */
		fuse_request_end(req);
		spin_lock(&queue->waitq.lock);
	}
	spin_unlock(&queue->waitq.lock);
}

/*
 *  Start the ring destruction
 */
static void fuse_uring_start_destruct(struct fuse_conn *fc)
{
	int qid, tag;

	spin_lock(&fc->ring.stop_waitq.lock);

	/* Might be set already, but not in all call paths */
	fc->ring.stop_requested = 1;

	if (fc->ring.nr_queues == 0)
		goto out;

	for (qid = 0; qid < fc->ring.nr_queues; qid++) {
		struct fuse_ring_queue *queue =
			fuse_uring_get_queue(fc, qid);

		fuse_uring_end_requests(queue);

		spin_lock(&queue->waitq.lock);

		queue->stop_requested = 1;
		wake_up_all_locked(&queue->waitq);
		spin_unlock(&queue->waitq.lock);

		for (tag = 0; tag < fc->ring.queue_depth; tag++) {
			struct fuse_ring_req *rreq = &queue->ring_req[tag];
			fuse_uring_shutdown_release_req(fc, queue, rreq);
		}
	}
out:
	spin_unlock(&fc->ring.stop_waitq.lock);
}

/*
 * monitoring functon to check if fuse shall be destructed, run
 * as delayed task
 */
static void fuse_dev_ring_stop_mon(struct work_struct *work)
{
	struct fuse_conn *fc = container_of(work, struct fuse_conn,
					    ring.stop_monitor.work);
	struct fuse_iqueue *fiq = &fc->iq;

	if (!fiq->connected || fc->ring.stop_requested ||
	    (fc->ring.daemon->flags & PF_EXITING))
		fuse_uring_start_destruct(fc);

	if (READ_ONCE(fc->ring.queue_refs) > 0)
		schedule_delayed_work(&fc->ring.stop_monitor,
				      FURING_DAEMON_MON_PERIOD);
}

/**
 * use __vmalloc_node_range() (needs to be
 * exported?) or add a new (exported) function vm_alloc_user_node()
 */
static char *fuse_dev_uring_alloc_queue_buf(int size, int node)
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
static int fuse_dev_conn_uring_cfg(struct fuse_conn *fc,
				   struct fuse_uring_cfg *cfg)
{
	size_t queue_sz, req_sz;

	if (cfg->nr_queues == 0) {
		pr_info("zero number of queues is invalid.\n");
		return -EINVAL;
	}

	if (cfg->nr_queues > 1 &&
	    cfg->nr_queues != num_present_cpus()) {
		pr_info("Number of queues (%d) does not match the "
			"number of cores (%d).\n",
			cfg->nr_queues, num_present_cpus());
		return -EINVAL;
	}

	if (cfg->qid > cfg->nr_queues) {
		pr_info("qid (%d) exceeds number of queues (%d)\n",
			cfg->qid, cfg->nr_queues);
		return -EINVAL;
	}

	if (cfg->req_buf_sz < sizeof(struct fuse_uring_buf_req)) {
		pr_info("Per req buffer size too small (%d), min: %ld\n",
			cfg->req_buf_sz,
			sizeof(struct fuse_uring_buf_req));
		return -EINVAL;
	}

	if (cfg->backgnd_queue_depth >= cfg->queue_depth ||
	   !cfg->backgnd_queue_depth) {
		if (!cfg->backgnd_queue_depth) {
			pr_info("Invalid ring configuration, no background queue.\n");
		} else
			pr_info("Invalid ring configuration, "
				"nr-background > nr-requests.\n");
		return -EINVAL;
	}
	if (cfg->max_backgnd_aggr > cfg->backgnd_queue_depth) {
		pr_info("Background coalescence (%d) cannot be higher than "
			"background queue depth %d\n", cfg->max_backgnd_aggr,
			cfg->backgnd_queue_depth);
		return -EINVAL;
	}

	if (unlikely(fc->ring.queues)) {
		WARN_ON(1);
		return -EINVAL;
	}

	fc->ring.daemon = current;
	get_task_struct(fc->ring.daemon);
	INIT_DELAYED_WORK(&fc->ring.stop_monitor,
			  fuse_dev_ring_stop_mon);
	schedule_delayed_work(&fc->ring.stop_monitor,
			      FURING_DAEMON_MON_PERIOD);

	req_sz = cfg->queue_depth * sizeof(struct fuse_ring_req);
	fc->ring.nr_queues = cfg->nr_queues;
	fc->ring.queue_depth = cfg->queue_depth;
	fc->ring.per_core_queue = cfg->nr_queues > 1;
	fc->ring.req_buf_sz = cfg->req_buf_sz;
	fc->ring.queue_buf_size = fc->ring.req_buf_sz * fc->ring.queue_depth;
	spin_lock_init(&fc->ring.backgnd_qid_lock);

	queue_sz = (sizeof(*fc->ring.queues) + req_sz);
	fc->ring.queues = kcalloc(cfg->nr_queues, queue_sz, GFP_KERNEL);
	if (!fc->ring.queues)
		return -ENOMEM;
	fc->ring.queue_size = queue_sz;

	fc->ring.max_bg = cfg->backgnd_queue_depth;
	fc->ring.max_fg = cfg->queue_depth -
				  cfg->backgnd_queue_depth;

	fc->ring.max_backgnd_aggr =
		cfg->max_backgnd_aggr ? cfg->max_backgnd_aggr : 0;

	fc->ring.backgnd_queue_cnt = 0;
	fc->ring.queue_refs = 0;

	return 0;
}

static int fuse_dev_uring_queue_cfg(struct fuse_conn *fc, unsigned qid,
				    unsigned node_id)
{
	int tag;
	struct fuse_ring_queue *queue;

	if (qid > fc->ring.nr_queues) {
		pr_info("fuse ring queue config: qid=%u > nr-queues=%zu\n",
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
	smp_mb__before_atomic();
	init_waitqueue_head(&queue->waitq);
	INIT_LIST_HEAD(&queue->bg_queue);

	queue->queue_req_buf =
		fuse_dev_uring_alloc_queue_buf(fc->ring.queue_buf_size, node_id);
	if (IS_ERR(queue->queue_req_buf))
	{
		int err = PTR_ERR(queue->queue_req_buf);
		queue->queue_req_buf = NULL;
		return err;
	}

	for (tag = 0; tag < fc->ring.queue_depth; tag++) {
		struct fuse_ring_req *req = &queue->ring_req[tag];
		req->queue = queue;
		req->tag = tag;
		req->req_ptr = NULL;
		req->kbuf = (struct fuse_uring_buf_req *)(queue->queue_req_buf +
				fc->ring.req_buf_sz * tag);

		pr_devel("initialize qid=%d tag=%d queue=%p req=%p",
			 qid, tag, queue, req);

		req->kbuf->flags = 0;

		WRITE_ONCE(req->state, FRRS_INIT);
		fc->ring.queue_refs++;
	}

	queue->configured = 1;
	queue->stop_requested = 0;
	fc->ring.nr_queues_ioctl_init++;
	if (fc->ring.nr_queues_ioctl_init == fc->ring.nr_queues)
		fc->ring.configured = 1;

	return 0;
}

/**
 * Configure the queue for t he given qid. First call will also initialize
 * the ring for this connection.
 */
static int fuse_dev_uring_cfg(struct fuse_conn *fc, unsigned qid,
			      struct fuse_uring_cfg *cfg)
{
	int rc;

	/* The lock is taken, so that user space may configure all queues
	 * in parallel
	 */
	spin_lock(&fc->ring.stop_waitq.lock);

	if (fc->ring.configured) {
		rc = -EALREADY;
		goto unlock;
	}

	if (fc->ring.daemon == NULL) {
		rc = fuse_dev_conn_uring_cfg(fc, cfg);
		if (rc != 0)
			goto unlock;
	}

	rc = fuse_dev_uring_queue_cfg(fc, qid, cfg->numa_node_id);

unlock:
	spin_unlock(&fc->ring.stop_waitq.lock);

	return rc;
}

/**
 * Wait until uring shall be destructed and then release uring resources
 */
static int fuse_dev_uring_wait_stop(struct fuse_conn *fc)
{
	struct fuse_iqueue *fiq = &fc->iq;

	/* This userspace thread can stop uring on process stop, no need
	 * for the interval worker
	 */
	mod_delayed_work(system_wq, &fc->ring.stop_monitor, -1UL);

	wait_event_interruptible_exclusive(fc->ring.stop_waitq,
					   !fiq->connected ||
					   fc->ring.stop_requested);

	/* The userspace task gets scheduled to back userspace, we need
	 * the interval worker again. It runs immediately for quick cleanup
	 * in shutdown/process kill.
	 */
	mod_delayed_work(system_wq, &fc->ring.stop_monitor, 0);

	return 0;
}

static int fuse_dev_wakeup_destruct_wait(struct fuse_conn *fc)
{
	fc->ring.stop_requested = 1;
	wake_up(&fc->ring.stop_waitq);

	return 0;
}

int fuse_dev_uring_ioctl(struct file *file, struct fuse_uring_cfg *cfg)
{
	struct fuse_dev *fud = fuse_get_dev(file);
	struct fuse_conn *fc;

	if (fud == NULL)
		return -ENODEV;

	fc = fud->fc;
	pr_devel("%s fc=%p flags=%llx qid=%d nq=%d  qdepth=%d\n",
		 __func__, fc, cfg->flags, cfg->qid, cfg->nr_queues,
		 cfg->queue_depth);


	if (cfg->flags & FUSE_URING_IOCTL_FLAG_QUEUE_CFG) {
		/* config flag is incompatible to WAIT and STOP */
		if ((cfg->flags & FUSE_URING_IOCTL_FLAG_WAIT) ||
		    (cfg->flags & FUSE_URING_IOCTL_FLAG_STOP))
			return -EINVAL;

		return fuse_dev_uring_cfg(fc, cfg->qid, cfg);
	}

	if (cfg->flags & FUSE_URING_IOCTL_FLAG_WAIT) {
		if (cfg->flags & FUSE_URING_IOCTL_FLAG_STOP)
			return -EINVAL;

		return fuse_dev_uring_wait_stop(fc);
	}

	if (cfg->flags & FUSE_URING_IOCTL_FLAG_STOP) {
		return fuse_dev_wakeup_destruct_wait(fc);
	}

	/* no command flag set */
	return -EINVAL;
}

/**
 * fuse uring mmap, per ring qeuue. The queue is identified by the offset
 * parameter
 */
int fuse_dev_ring_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct fuse_dev *fud = fuse_get_dev(filp);
	struct fuse_conn *fc = fud->fc;
	size_t sz = vma->vm_end - vma->vm_start;
	unsigned qid;
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
