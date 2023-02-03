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


static struct fuse_ring_queue *
fuse_uring_get_queue(struct fuse_conn *fc, int qid)
{
	char *ptr = (char *)fc->ring.queues;

	if (unlikely(qid > fc->ring.nr_queues))
		return NULL;

	return (struct fuse_ring_queue *)(ptr + qid * fc->ring.queue_size);
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
int fuse_dev_uring_write_to_ring(struct fuse_ring_req *ring_req)
{
	struct fuse_conn *fc = ring_req->queue->fc;
	struct fuse_uring_buf_req *buf_req = ring_req->kbuf;
	struct fuse_req *req = &ring_req->req;
	int err = -EIO;

	pr_devel("%s:%d ring-req=%p buf_req=%p state=%lu args=%p \n", __func__,
		 __LINE__, ring_req, buf_req, ring_req->state, req->args);

	if (READ_ONCE(ring_req->state) != FRRS_REQ) {
		WARN_RATELIMIT(1, "Invalid ring-req state: %lu\n",
				ring_req->state);
		goto err;
	}

	err = fuse_uring_copy_to_ring(fc, req, buf_req);
	if (err)
		goto err;

	/* ring req go directly into the shared memory buffer
	 *
	 * XXX avoid this have the data for uring immediately in the
	 * shared userspace buffer. Lots of if-conditions in the code,
	 * though */
	buf_req->in = req->in.h;

	pr_devel("%s cmd-done op=%d unique=%llu\n",
		__func__, buf_req->in.opcode, buf_req->in.unique);

	clear_bit(FR_PENDING, &req->flags);
	set_bit(FR_SENT, &req->flags);

	spin_lock(&ring_req->queue->waitq.lock);
	ring_req->state = FRRS_USERSPACE;
	spin_unlock(&ring_req->queue->waitq.lock);
	io_uring_cmd_done(ring_req->cmd, 0, 0);

	return 0;

err:
	req->out.h.error = -EIO;
	if (ring_req->req_ptr) {
		*ring_req->req_ptr = *req;
		fuse_request_end(ring_req->req_ptr);
		ring_req->req_ptr = NULL;

		/* release the ring req, as if it has done work */
		WRITE_ONCE(ring_req->state, FRRS_USERSPACE);
		fuse_dev_uring_req_release(&ring_req->req);
	}
	else
		fuse_request_end(req);

	return err;
}
EXPORT_SYMBOL_GPL(fuse_dev_uring_write_to_ring);

/*
 * Checks for errors and stores it into the request
 */
static int fuse_dev_uring_ring_has_err(struct fuse_conn *fc,
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
 * This is comparible with classical write(/dev/fuse)
 */
void fuse_dev_uring_read_from_ring(struct fuse_dev *fud,
				   struct fuse_ring_req *ring_req)
{
	struct fuse_uring_buf_req *buf_req = ring_req->kbuf;
	struct fuse_req *req = &ring_req->req;
	ssize_t err = 0;

	pr_devel("%s:%d req=%p\n", __func__, __LINE__, req);

	clear_bit(FR_SENT, &req->flags);

	req->out.h = buf_req->out;

	err = fuse_dev_uring_ring_has_err(fud->fc, ring_req);
	if (err) {
		pr_devel("%s:%d err=%zd oh->err=%d \n", __func__, __LINE__,
			 err, req->out.h.error);
		goto out;
	}

	err = fuse_uring_copy_from_ring(fud->fc, req, buf_req);
	if (err)
		goto seterr;

out:
	pr_devel("%s:%d ret=%zd op=%d req-ret=%d",
		 __func__, __LINE__, err, req->args->opcode, req->out.h.error);
	if (ring_req->req_ptr) {
		*ring_req->req_ptr = *req;
		fuse_request_end(ring_req->req_ptr);
		ring_req->req_ptr = NULL;

		/* the ring req is available now */
		fuse_dev_uring_req_release(&ring_req->req);
	}
	else
		fuse_request_end(&ring_req->req);
	return;

seterr:
	req->out.h.error = err;
	goto out;
}
EXPORT_SYMBOL_GPL(fuse_dev_uring_read_from_ring);

/**
 * Check if an application command was queued into the list-queue
 *
 * @return 1 if a reqesust was taken from the queue, 0 if the queue was empty
 * 	   negative values on error
 *
 * negative values for error
 */
static int fuse_dev_uring_fetch_queued(struct fuse_conn *fc,
				       struct fuse_ring_queue *queue,
				       struct fuse_ring_req *ring_req)
{
	struct fuse_iqueue *fiq = &fc->iq;
	struct fuse_req *q_req = NULL;
	int rc, ret = 0;

	spin_lock(&queue->waitq.lock);
	ring_req->state = FRRS_REQ;
	spin_unlock(&queue->waitq.lock);

	spin_lock(&fiq->lock);
	if (!list_empty(&fiq->pending)) {
		q_req = list_entry(fiq->pending.next, struct fuse_req, list);
		clear_bit(FR_PENDING, &q_req->flags);
		list_del_init(&q_req->list);
	}
	spin_unlock(&fiq->lock);

	if (!q_req)
		goto out;

	ring_req->kbuf->flags = 0;

	if (test_bit(FR_BACKGROUND, &q_req->flags))
		ring_req->kbuf->flags |= FUSE_RING_REQ_FLAG_BACKGROUND;

	/* copy over and store the initial req, on completion copy back has to
	 * be done */
	ring_req->req = *q_req;
	ring_req->req_ptr = q_req;

	pr_devel("%s: args=%p ring-args=%p req=%p list-req=%p\n",
		 __func__, q_req->args, ring_req->req.args, &ring_req->req, q_req);

	rc = fuse_dev_uring_write_to_ring(ring_req);
	if (rc) {
		if (unlikely(rc == -ENOENT)) {
			/* ENOENT is specially treated by the caller,
			 * as no reqest in the list, so must not be used here */
			rc = -EIO;
		}

		if (rc > 0) {
			WARN(1, "Unexpected return code: %d", rc);
			rc = -EIO;
		}

		ret = rc;
	}

	ret = rc != 0 ? rc : 1;

out:
	return ret;
}

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
		if (queue->req_active_background >= fc->ring.max_background) {
			/* no need to wait for background requests, the caller
			 * can handle request allocation failures
			 */
			pr_devel("%s Active bgnd=%d max-bnd=%zu\n", __func__,
				 queue->req_active_background,
				 fc->ring.max_background);
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

/*
 * @return queue to that will take the request, might be NULL if for_background
 * The returned queue is waitq locked
 */
static struct fuse_ring_queue *
fuse_dev_uring_queue_from_current_task(struct fuse_conn *fc, bool for_background)
{
	const struct fuse_iqueue *fiq = &fc->iq;
	unsigned int qid = 0;
	struct fuse_ring_queue *queue;

	if (for_background && fc->ring.per_core_queue) {
		/* more complex handling, for coalescencing */
		return fuse_dev_uring_queue_for_background_req(fc);
	}

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

	if (queue->req_active_foreground >= fc->ring.max_foreground) {
		wait_event_interruptible_exclusive_locked(queue->waitq,
			queue->req_active_foreground < fc->ring.max_foreground);

		if ((fc->ring.daemon->flags & PF_EXITING) ||
		    !fiq->connected || fc->ring.stop_requested ||
		    (current->flags & PF_EXITING)) {
			spin_unlock(&queue->waitq.lock);
			queue = NULL;
		}
	}

	return queue;
}

struct fuse_req *fuse_request_alloc_ring(struct fuse_mount *fm,
					 bool for_background)
{
	struct fuse_conn *fc = fm->fc;
	struct fuse_ring_queue *queue;
	struct fuse_ring_req *ring_req;
	struct fuse_req *req = NULL;
	uint64_t req_cnt;
	unsigned int tag = -1;
	const size_t queue_depth = fc->ring.queue_depth;

again:
	pr_devel("%s:%d backgnd=%d\n", __func__, __LINE__, for_background);

	/* returned queue is locked */
	queue = fuse_dev_uring_queue_from_current_task(fc, for_background);
	if (!queue)
		return NULL;

	pr_devel("%s:%d ac-foregnd=%d ac-backgnd=%d max-foregnd=%zu "
		"max-backgnd=%zu\n", __func__, __LINE__,
		 queue->req_active_foreground, queue->req_active_background,
		 fc->ring.max_foreground, fc->ring.max_background);


	tag = find_first_bit(queue->req_avail_map, queue_depth);
	if (unlikely(tag == queue_depth)) {
		pr_info("ring: no free bit found for qid=%d backgnd=%d "
			"ac-foregnd=%d ac-backgnd=%d max-foregnd=%zu "
			"max-backgnd=%zu\n", queue->qid, for_background,
			queue->req_active_foreground,
			queue->req_active_background,
			fc->ring.max_foreground, fc->ring.max_background);

		/* XXX run fstests generic/029 and generic/030 */
		WARN_ON(1);
		spin_unlock(&queue->waitq.lock);
		goto again;
	}

	ring_req = &queue->ring_req[tag];
	if (unlikely(ring_req->state != FRRS_WAITING)) {
		pr_info("Invalid request state %lu.\n",
			ring_req->state);
		WARN_ON(1);
		goto out;
	}

	ring_req->state = FRRS_REQ;
	ring_req->kbuf->flags = 0;

	if (for_background) {
		ring_req->kbuf->flags |= FUSE_RING_REQ_FLAG_BACKGROUND;
		queue->req_active_background++;
	}
	else {
		queue->req_active_foreground++;
	}


	req = &ring_req->req;
	pr_devel("queue bit op fc=%p qid=%d tag=%d -> 0\n",
		fc, queue->qid, ring_req->tag);
	__clear_bit(tag, queue->req_avail_map);

out:
	spin_unlock(&queue->waitq.lock);

	if (req) {
		memset(req, 0, sizeof(*req));
		fuse_request_init(fm, req);
		__set_bit(FR_URING, &req->flags);
	}

	pr_devel("%s: tag=%d cnt=%llu req=%p background=%d\n",
		 __func__, tag, req_cnt, req, for_background);

	return req;
}
EXPORT_SYMBOL_GPL(fuse_request_alloc_ring);


/*
 * @return true when the request could be released
 */
static bool _fuse_uring_free_req(struct fuse_conn *fc,
				 struct fuse_ring_queue *queue,
				 struct fuse_ring_req *req)
{
	bool freed = false;
	unsigned int stop_state = FRRS_WAITING | FRRS_FREEING;
	if (0 && fc->ring.daemon->flags & PF_EXITING) {
		/* the process is exiting, userspace is not going to complete
		 * the request anymore
		 */
		stop_state |= FRRS_USERSPACE;
	}

	if (req->state & stop_state) {
		req->state = FRRS_FREED;
		io_uring_cmd_done(req->cmd, -EIO, 0);
		freed = true;
	}

	return freed;
}

/*
 * This is called on shutdown
 */
static void fuse_uring_free_req(struct fuse_conn *fc,
				struct fuse_ring_queue *queue,
				struct fuse_ring_req *rreq)
__must_hold(&fc->ring.stop_waitq.lock)
{
	bool can_free = false;

	spin_lock(&queue->waitq.lock);

	if (rreq->state == FRRS_FREED)
		goto out; /* no work left, freed in another code path */

	if (rreq->state == FRRS_USERSPACE) {
		struct fuse_req *req = &rreq->req;

		/* ensure there is an error set, to avoid using invalid data */
		if (req->out.h.error == 0)
			req->out.h.error = -EINTR;

		/* Not always done yet on shutdown */
		clear_bit(FR_PENDING, &req->flags);
		set_bit(FR_SENT, &req->flags);

		rreq->state = FRRS_FREEING;
		spin_unlock(&queue->waitq.lock);
		fuse_request_end(req);
		spin_lock(&queue->waitq.lock);
	} else
		can_free = _fuse_uring_free_req(fc, queue, rreq);

	if (can_free)
		rreq->state = FRRS_FREED;

out:
	spin_unlock(&queue->waitq.lock);

	/* might free the queue - needs to have the queue waitq lock released */
	if (can_free) {
		int refs = --fc->ring.queue_refs;
		pr_devel("free-req fc=%p qid=%d tag=%d refs=%d\n",
			 fc, queue->qid, rreq->tag, refs);
		if (refs == 0)
			wake_up_locked(&fc->ring.stop_waitq);
	}

}

/**
 * Release a ring request, it is no longer needed and can handle new data
 */
void fuse_dev_uring_req_release(struct fuse_req *req)
{
	struct fuse_ring_req *ring_req =
		container_of(req, struct fuse_ring_req, req);
	struct fuse_ring_queue *queue = ring_req->queue;
	struct fuse_conn *fc = queue->fc;
	int old_state;
	bool backgnd = !!(ring_req->kbuf->flags & FUSE_RING_REQ_FLAG_BACKGROUND);

	spin_lock(&queue->waitq.lock);

	old_state = ring_req->state;
	if (ring_req->state != FRRS_USERSPACE &&
	    ring_req->state != FRRS_FREEING) {
		WARN(1, "Invalid req old_state: %lu\n", ring_req->state);
		goto out;
	}

	ring_req->state = FRRS_WAITING;

	pr_devel("queue bit op fc=%p qid=%d tag=%d -> 1\n",
		 fc, queue->qid, ring_req->tag);

	/* Note: the bit in req->flag got already cleared in fuse_request_end */
	ring_req->kbuf->flags = 0;


	/* XXX: Split the map into two, makes debugging easier */
	__set_bit(ring_req->tag, queue->req_avail_map);

	if (backgnd)
		queue->req_active_background--;
	else {
		queue->req_active_foreground--;
		wake_up_locked(&queue->waitq);
	}

out:
	spin_unlock(&queue->waitq.lock);

	if (unlikely(fc->ring.stop_requested))
		schedule_delayed_work(&fc->ring.stop_monitor, 0);

}
EXPORT_SYMBOL_GPL(fuse_dev_uring_req_release);

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
	struct fuse_ring_req *ring_req;
	u32 cmd_op = cmd->cmd_op;
	int ret = -EIO;

	if (!(issue_flags & IO_URING_F_SQE128)) {
		pr_info("qid=%d tag=%d SQE128 not set\n",
			cmd_req->q_id, cmd_req->tag);
		goto out;
	}

	if (unlikely(cmd_req->q_id >= fc->ring.nr_queues)) {
		pr_info("qid=%u > nr-queues=%zu\n",
			cmd_req->q_id, fc->ring.nr_queues);
		goto out;
	}

	queue = fuse_uring_get_queue(fc, cmd_req->q_id);
	if (unlikely(queue == NULL)) {
		pr_info("Got NULL queue for qid=%d\n", cmd_req->q_id);
		goto out;
	}

	if (unlikely(!fc->ring.configured || !queue->configured)) {
		pr_info("Ring or queue (qid=%u) not ready.\n", cmd_req->q_id);
		goto out;
	}

	if (cmd_req->tag > fc->ring.queue_depth) {
		pr_info("tag=%u > queue-depth=%zu\n",
			cmd_req->tag, fc->ring.queue_depth);
		goto out;
	}
	ring_req = &queue->ring_req[cmd_req->tag];

	pr_devel("%s:%d received: cmd op %d queue %d (%p) tag %d  (%p)\n",
		 __func__, __LINE__,
		 cmd_op, cmd_req->q_id, queue, cmd_req->tag, ring_req);

	switch (cmd_op) {
	case FUSE_URING_REQ_FETCH:
		if (READ_ONCE(ring_req->state) != FRRS_INIT) {
			pr_devel("%s: q_id: %d tag: %d invalid req state: %lu\n",
				 __func__, cmd_req->q_id, cmd_req->tag,
				 ring_req->state);
			goto out;
		}

		WRITE_ONCE(ring_req->cmd, cmd);

		ret = fuse_dev_uring_fetch_queued(fc, queue, ring_req);
		if (ret >= 0) {
			pr_devel("%s tag=%d req=%p list-req=%p bgnd=%d\n",
				 __func__, ring_req->tag,
				 &ring_req->req, ring_req->req_ptr,
				 test_bit(FR_BACKGROUND, &ring_req->req.flags));

			/* command registration or list req fetch - assing
			 * credits to make subtraction logic to work
			 */
			spin_lock(&queue->waitq.lock);
			if (test_bit(FR_BACKGROUND, &ring_req->req.flags))
				queue->req_active_background++;
			else {
				queue->req_active_foreground++;
				pr_devel("%s:%d ac-foregnd=%d\n", __func__, __LINE__,
					 queue->req_active_foreground);
			}
			spin_unlock(&queue->waitq.lock);

			if (ret == 0) {
				/* just a queue entry registration, without a
				 *  fuse req - make it available
				 */
				WRITE_ONCE(ring_req->state,
					   FRRS_USERSPACE);
				fuse_dev_uring_req_release(&ring_req->req);
			}
		}

		break;
	case FUSE_URING_REQ_COMMIT_AND_FETCH:
		if (READ_ONCE(ring_req->state) != FRRS_USERSPACE) {
			pr_devel("Invalid request state %lu, expected %d \n",
				ring_req->state, FRRS_USERSPACE);

			/* check if shutdown is in process and the request
			 * gets already handled
			 */
			if (fc->ring.stop_requested)
				ret = 0;

			goto out;
		}
		ring_req->cmd = cmd;

		fuse_dev_uring_read_from_ring(fud, ring_req);

		ret = 0;

		break;
	default:
		ret = -EINVAL;
		pr_devel("Unknown uring command %d", cmd_op);
		goto out;
	}

	pr_devel("%s:%d ret=%d", __func__, __LINE__, ret);

out:
	if (ret < 0) {
		spin_lock(&queue->waitq.lock);
		ring_req->state =  FRRS_USERSPACE;
		spin_unlock(&queue->waitq.lock);
	}
	else if (ret == 0) {
		/* nothing */
	} else {
		/* the request already got handled/busy with a list req */
		BUG_ON(ret > 1);
	}

	if (ret < 0) {
		io_uring_cmd_done(cmd, ret, 0);
		pr_devel("%s: req error: op=%d, tag=%d ret=%d io_flags=%x\n",
			__func__, cmd_op, cmd_req->tag, ret, issue_flags);
	} else {
		pr_devel("%s: %s cmd op %d queue %d tag %d result %d\n",
			 __func__, ret == 0 ? "req ring queued" : "req sent back",
			cmd_op, cmd_req->q_id, cmd_req->tag, ret);

	}
	return -EIOCBQUEUED;
}
EXPORT_SYMBOL(fuse_dev_uring_cmd);

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

	kfree(fc->ring.queues);
	fc->ring.nr_queues_initialized = 0;
	fc->ring.queues = NULL;
	fc->ring.queue_depth = 0;
	fc->ring.nr_queues = 0;

	/* Actually should not be running anymore already, for safety */
	cancel_delayed_work_sync(&fc->ring.stop_monitor);
	put_task_struct(fc->ring.daemon);
	fc->ring.daemon = NULL;
}
EXPORT_SYMBOL(fuse_uring_ring_destruct);

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

		wake_up_all(&queue->waitq);

		for (tag = 0; tag < fc->ring.queue_depth; tag++) {
			struct fuse_ring_req *rreq = &queue->ring_req[tag];
			fuse_uring_free_req(fc, queue, rreq);
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

	if (cfg->queue.nr_queues == 0) {
		pr_info("zero number of queues is invalid.\n");
		return -EINVAL;
	}

	if (cfg->queue.nr_queues > 1 &&
	    cfg->queue.nr_queues != num_present_cpus()) {
		pr_info("Number of queues (%d) does not match the "
			"number of cores (%d).\n",
			cfg->queue.nr_queues, num_present_cpus());
		return -EINVAL;
	}

	if (cfg->queue.qid > cfg->queue.nr_queues) {
		pr_info("qid (%d) exceeds number of queues (%d)\n",
			cfg->queue.qid, cfg->queue.nr_queues);
		return -EINVAL;
	}

	if (cfg->queue.req_buf_sz < sizeof(struct fuse_uring_buf_req)) {
		pr_info("Per req buffer size too small (%d), min: %ld\n",
			cfg->queue.req_buf_sz,
			sizeof(struct fuse_uring_buf_req));
		return -EINVAL;
	}

	if (cfg->queue.backgnd_queue_depth >= cfg->queue.queue_depth ||
	   !cfg->queue.backgnd_queue_depth) {
		if (!cfg->queue.backgnd_queue_depth) {
			pr_info("Invalid ring configuration, no background queue.\n");
		} else
			pr_info("Invalid ring configuration, "
				"nr-background > nr-requests.\n");
		return -EINVAL;
	}
	if (cfg->queue.max_backgnd_aggr > cfg->queue.backgnd_queue_depth) {
		pr_info("Background coalescence (%d) cannot be higher than "
			"background queue depth %d\n", cfg->queue.max_backgnd_aggr,
			cfg->queue.backgnd_queue_depth);
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

	req_sz = cfg->queue.queue_depth * sizeof(struct fuse_ring_req);
	fc->ring.nr_queues = cfg->queue.nr_queues;
	fc->ring.queue_depth = cfg->queue.queue_depth;
	fc->ring.per_core_queue = cfg->queue.nr_queues > 1;
	fc->ring.req_buf_sz = cfg->queue.req_buf_sz;
	fc->ring.queue_buf_size = fc->ring.req_buf_sz * fc->ring.queue_depth;
	spin_lock_init(&fc->ring.backgnd_qid_lock);

	queue_sz = (sizeof(*fc->ring.queues) + req_sz);
	fc->ring.queues = kcalloc(cfg->queue.nr_queues, queue_sz, GFP_KERNEL);
	if (!fc->ring.queues)
		return -ENOMEM;
	fc->ring.queue_size = queue_sz;

	fc->ring.max_background = cfg->queue.backgnd_queue_depth;
	fc->ring.max_foreground = cfg->queue.queue_depth -
				  cfg->queue.backgnd_queue_depth;

	fc->ring.max_backgnd_aggr =
		cfg->queue.max_backgnd_aggr ? cfg->queue.max_backgnd_aggr : 0;

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
	queue->req_active_foreground = 0;
	bitmap_zero(queue->req_avail_map, FUSE_URING_MAX_QUEUE_DEPTH);
	init_waitqueue_head(&queue->waitq);

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
	fc->ring.nr_queues_initialized++;
	if (fc->ring.nr_queues_initialized == fc->ring.nr_queues)
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

	rc = fuse_dev_uring_queue_cfg(fc, qid, cfg->queue.numa_node_id);

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
		 __func__, fc, cfg->flags, cfg->queue.qid, cfg->queue.nr_queues,
		 cfg->queue.queue_depth);


	if (cfg->flags & FUSE_URING_IOCTL_FLAG_QUEUE_CFG) {
		/* config flag is incompatible to WAIT and STOP */
		if ((cfg->flags & FUSE_URING_IOCTL_FLAG_WAIT) ||
		    (cfg->flags & FUSE_URING_IOCTL_FLAG_STOP))
			return -EINVAL;

		return fuse_dev_uring_cfg(fc, cfg->queue.qid, cfg);
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
 * This is mmap for userspace uring
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
EXPORT_SYMBOL_GPL(fuse_dev_ring_mmap);


