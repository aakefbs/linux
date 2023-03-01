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

static bool fuse_dev_uring_ent_release(struct fuse_ring_ent *ring_ent);
static void fuse_dev_uring_send_to_ring(struct fuse_ring_ent *ring_ent);


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

/*
 * has lock/unlock/lock to avoid holding the lock on calling fuse_request_end
 */
static void
fuse_uring_entuest_end(struct fuse_ring_ent *ring_ent, bool set_err, int error)
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
			pr_info("request end not needed state=%llu end-bit=%d \n",
				ring_ent->state, ring_ent->need_req_end);
			WARN_ON(1);
		}
		return;
	}

	if (set_err)
		req->out.h.error = error;

	pr_devel("Ending req %p\n", ring_ent->fuse_req);
	fuse_request_end(ring_ent->fuse_req);
	ring_ent->fuse_req = NULL;

	send = fuse_dev_uring_ent_release(ring_ent);

	if (send)
		fuse_dev_uring_send_to_ring(ring_ent);
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
static void fuse_dev_uring_send_to_ring(struct fuse_ring_ent *ring_ent)
{
	struct fuse_conn *fc = ring_ent->queue->fc;
	struct fuse_uring_buf_req *buf_req = ring_ent->kbuf;
	struct fuse_req *req = ring_ent->fuse_req;
	int err = 0;

	pr_devel("%s:%d ring-req=%p fuse_req=%p state=%llu args=%p \n", __func__,
		 __LINE__, ring_ent, ring_ent->fuse_req, ring_ent->state, req->args);

	spin_lock(&ring_ent->queue->lock);
	if (unlikely((ring_ent->state & FRRS_USERSPACE) ||
		     (ring_ent->state & FRRS_FREED))) {
		pr_err("ring-req=%p buf_req=%p invalid state %llu on send\n",
		       ring_ent, buf_req, ring_ent->state);
		WARN_ON(1);
		err = -EIO;
	} else
		ring_ent->state |= FRRS_USERSPACE;

	ring_ent->need_cmd_done = 0;
	spin_unlock(&ring_ent->queue->lock);
	if (err)
		goto err;

	err = fuse_uring_copy_to_ring(fc, req, buf_req);
	if (unlikely(err)) {
		ring_ent->state &= ~FRRS_USERSPACE;
		ring_ent->need_cmd_done = 1;
		goto err;
	}

	/* ring req go directly into the shared memory buffer */
	buf_req->in = req->in.h;

	pr_devel("%s qid=%d tag=%d state=%llu cmd-done op=%d unique=%llu\n",
		__func__, ring_ent->queue->qid, ring_ent->tag, ring_ent->state,
		buf_req->in.opcode, buf_req->in.unique);

	io_uring_cmd_done(ring_ent->cmd, 0, 0);
	return;

err:
	fuse_uring_entuest_end(ring_ent, true, err);
}

static void fuse_dev_uring_bit_set(struct fuse_ring_ent *ring_ent, bool bg,
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
	if (bg)
		queue->req_bg++;
	else {
		queue->req_fg++;
	}

	pr_devel("%35s ring bit set   fc=%p is_bg=%d qid=%d tag=%d fg=%d bg=%d "
		 "bgq: %d\n",
		 str, fc, bg, queue->qid, ring_ent->tag, queue->req_fg,
		 queue->req_bg, !list_empty(&queue->bg_queue));
}

static int fuse_dev_uring_bit_clear(struct fuse_ring_ent *ring_ent, int is_bg,
				     const char *str)
__must_hold(ring_ent->queue->lock)
{
	int old;
	struct fuse_ring_queue *queue = ring_ent->queue;
	const struct fuse_conn *fc = queue->fc;
	int tag = ring_ent->tag;
	int *value = is_bg ? &queue->req_bg : &queue->req_fg;

	if (unlikely(*value <= 0)) {
		pr_warn("%s bug: qid=%d tag=%d is_bg=%d "
			"zero requests available fg=%d bg=%d\n",
			str, queue->qid, ring_ent->tag, is_bg,
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

	ring_ent->kbuf->flags = 0;

	if (is_bg) {
		ring_ent->kbuf->flags |= FUSE_RING_REQ_FLAG_BACKGROUND;
		queue->req_bg--;
	} else
		queue->req_fg--;

	pr_devel("%35s ring bit clear fc=%p is_bg=%d qid=%d tag=%d fg=%d bg=%d \n",
		 str, fc, is_bg, queue->qid, ring_ent->tag,
		 queue->req_fg, queue->req_bg);

	ring_ent->state |= FRRS_FUSE_REQ;

	return 0;
}

/*
 * Assign a fuse queue entry to the given entry
 *
 */
static bool fuse_dev_uring_assign_ring_entry(struct fuse_ring_ent *ring_ent,
					     struct list_head *head,
					     int is_bg)
__must_hold(&queue.waitq.lock)
{
	struct fuse_req *req;
	int res;

	if (list_empty(head))
		return false;

	res = fuse_dev_uring_bit_clear(ring_ent, is_bg, __func__);
	if (unlikely(res))
		return false;

	req = list_first_entry(head, struct fuse_req, list);
	list_del_init(&req->list);
	clear_bit(FR_PENDING, &req->flags);
	ring_ent->fuse_req = req;
	ring_ent->need_req_end = 1;

	return true;
}

int fuse_dev_uring_queue_fuse_req(struct fuse_conn *fc, struct fuse_req *req)
{
	struct fuse_ring_queue *queue;
	int qid = 0;
	struct fuse_ring_ent *ring_ent = NULL;
	const size_t queue_depth = fc->ring.queue_depth;
	int res;
	int is_bg = test_bit(FR_BACKGROUND, &req->flags);
	struct list_head *head;
	int *queue_avail;

	pr_devel("%s req=%p bg=%d\n", __func__, req, is_bg);

	if (fc->ring.per_core_queue) {
		qid = task_cpu(current);
		if (unlikely(qid) >= fc->ring.nr_queues) {
			WARN_ONCE(1, "Core number (%u) exceeds nr of ring "
				  "queues (%zu)\n", qid, fc->ring.nr_queues);
			qid = 0;
		}
	}

	queue = fuse_uring_get_queue(fc, qid);
	head = is_bg ?  &queue->bg_queue : &queue->fg_queue;
	queue_avail = is_bg ? &queue->req_bg : &queue->req_fg;

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
				"qdepth=%zu av-fg=%d av-bg=%d max-fg=%zu "
				"max-bg=%zu is_bg=%d\n", queue->qid,
				queue_depth, queue->req_fg, queue->req_bg,
				fc->ring.max_fg, fc->ring.max_bg, is_bg);

			WARN_ON(1);
			res = -ENOENT;
			goto err_unlock;
		}
		ring_ent = &queue->ring_ent[tag];
		got_req = fuse_dev_uring_assign_ring_entry(ring_ent, head, is_bg);
		if (unlikely(!got_req)) {
			WARN_ON(1);
			ring_ent = NULL;
		}
	}
	spin_unlock(&queue->lock);

	if (ring_ent != NULL)
		fuse_dev_uring_send_to_ring(ring_ent);

	return 0;

err_unlock:
	spin_unlock(&queue->lock);
	return res;
}

/*
 * Checks for errors and stores it into the request
 */
static int fuse_dev_uring_ring_ent_has_err(struct fuse_conn *fc,
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
					      struct fuse_ring_ent *ring_ent)
{
	struct fuse_uring_buf_req *buf_req = ring_ent->kbuf;
	struct fuse_req *req = ring_ent->fuse_req;
	ssize_t err = 0;
	bool set_err = false;

	req->out.h = buf_req->out;

	err = fuse_dev_uring_ring_ent_has_err(fud->fc, ring_ent);
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
	pr_devel("%s:%d ret=%zd op=%d req-ret=%d\n",
		 __func__, __LINE__, err, req->args->opcode, req->out.h.error);
	fuse_uring_entuest_end(ring_ent, set_err, err);
	return;
}

/*
 * This is called on shutdown
 *
 * XXX This unlocks the queue in the middle
 */
static void fuse_uring_shutdown_release_req(struct fuse_conn *fc,
					    struct fuse_ring_queue *queue,
					    struct fuse_ring_ent *rreq)
__must_hold(&fc->ring.start_stop_lock)
__must_hold(&queue->lock)
{
	bool may_release = false;
	int state;

	pr_devel("%s fc=%p qid=%d tag=%d state=%llu\n",
		 __func__, fc, queue->qid, rreq->tag, rreq->state);

	if (rreq->state & FRRS_FREED)
		goto out; /* no work left, freed before */

	state = rreq->state;

	if (state == FRRS_INIT || state == FRRS_FUSE_WAIT ||
	    ((state & FRRS_USERSPACE) && queue->aborted)) {

		rreq->state |= FRRS_FREED;

		if (rreq->need_cmd_done) {
			pr_devel("qid=%d tag=%d sending cmd_done\n",
				queue->qid, rreq->tag);
			io_uring_cmd_done(rreq->cmd, -ENOTCONN, 0);
			rreq->need_cmd_done = 0;
		}

		if (rreq->need_req_end) {
			spin_unlock(&queue->lock);
			fuse_uring_entuest_end(rreq, true, -ENOTCONN);
			spin_lock(&queue->lock);
		}
		may_release = true;
	} else {
		/* somewhere in between states, another thread should currently
		 * handle it */
		pr_devel("%s qid=%d tag=%d state=%llu\n",
			 __func__, queue->qid, rreq->tag, rreq->state);
	}

out:

	/* might free the queue - needs to have the queue waitq lock released */
	if (may_release) {
		int refs = --fc->ring.queue_refs;
		pr_devel("free-req fc=%p qid=%d tag=%d refs=%d\n",
			 fc, queue->qid, rreq->tag, refs);
		if (refs == 0) {
			fc->ring.queues_stopped = 1;
			wake_up(&fc->ring.stop_waitq);
		}
	}
}

/*
 * Release a ring request, it is no longer needed and can handle new data
 *
 */
static void _fuse_dev_uring_ent_release_locked(struct fuse_ring_ent *ring_ent,
					      struct fuse_ring_queue *queue,
					      bool bg)
__must_hold(&queue->lock)
{
	struct fuse_conn *fc = queue->fc;

	/* unsets all previous flags - basically resets */
	pr_devel("%s fc=%p qid=%d tag=%d state=%llu bg=%d\n",
		__func__, fc, ring_ent->queue->qid, ring_ent->tag,
		ring_ent->state, bg);

	if (ring_ent->state & FRRS_USERSPACE) {
		pr_warn("%s qid=%d tag=%d state=%llu is_bg=%d\n",
			__func__, ring_ent->queue->qid, ring_ent->tag,
			ring_ent->state, bg);
		WARN_ON(1);
		return;
	}

	fuse_dev_uring_bit_set(ring_ent, bg, __func__);

	/* Check if this is call through shutdown/release task and already and
	 * the request is about to be released - the state must not be reset
	 * then, as state FRRS_FUSE_WAIT would introduce a double
	 * io_uring_cmd_done
	 */
	if (ring_ent->state & FRRS_FREEING)
		return;

	/* Note: the bit in req->flag got already cleared in fuse_request_end */
	ring_ent->kbuf->flags = 0;
	ring_ent->state = FRRS_FUSE_WAIT;
}

/*
 * Release a uring entry, called internally of dev_uring
 */
static bool fuse_dev_uring_ent_release(struct fuse_ring_ent *ring_ent)
{
	struct fuse_ring_queue *queue = ring_ent->queue;
	bool is_bg = !!(ring_ent->kbuf->flags & FUSE_RING_REQ_FLAG_BACKGROUND);
	bool send = false;
	struct list_head *head = is_bg ? &queue->bg_queue : &queue->fg_queue;

	spin_lock(&ring_ent->queue->lock);
	_fuse_dev_uring_ent_release_locked(ring_ent, queue, is_bg);
	send = fuse_dev_uring_assign_ring_entry(ring_ent, head, is_bg);
	spin_unlock(&ring_ent->queue->lock);

	return send;
}

/*
 * FUSE_URING_REQ_FETCH command handling
 */
static int fuse_dev_uring_fetch(struct fuse_ring_ent *ring_ent,
				struct io_uring_cmd *cmd)
{
	struct fuse_ring_queue *queue = ring_ent->queue;
	struct fuse_conn *fc = queue->fc;
	int ret;
	bool is_bg = false;
	int nr_queue_init = 0;

	spin_lock(&queue->lock);

	/* register requests for foreground requests first, then backgrounds */
	if (queue->req_fg >= fc->ring.max_fg)
		is_bg = true;
	_fuse_dev_uring_ent_release_locked(ring_ent, queue, is_bg);

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
			"queue-depth=%zu", queue->qid, ring_ent->tag,
			queue->req_fg, queue->req_bg, fc->ring.queue_depth);
		ret = -ERANGE;

		/* avoid completion through fuse_req_end, as there is no
		 * fuse req assigned yet
		 */
		ring_ent->state = FRRS_INIT;
	}

	pr_devel("%s:%d qid=%d tag=%d nr-fg=%d nr-bg=%d nr_queue_init=%d\n",
		__func__, __LINE__,
		queue->qid, ring_ent->tag, queue->req_fg, queue->req_bg,
		nr_queue_init);

	spin_unlock(&queue->lock);
	if (ret)
		goto out; /* ERANGE */

	WRITE_ONCE(ring_ent->cmd, cmd);

	if (nr_queue_init == fc->ring.nr_queues)
		fc->ring.ready = 1;

out:
	return ret;
}

struct fuse_ring_queue *
fuse_dev_uring_cmd_get_queue(struct fuse_conn *fc,
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
		ret =-ENOTCONN;
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
int fuse_dev_uring_cmd(struct io_uring_cmd *cmd, unsigned int issue_flags)
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

	queue = fuse_dev_uring_cmd_get_queue(fc, cmd_req, issue_flags);
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
			pr_info_ratelimited("Invalid state on req "
					    "register: %llu expected %d",
					    prev_state, FRRS_INIT);
			ret = -EINVAL;
			goto out;

			/* XXX error injection or test with malicious daemon */
		}

		ret = fuse_dev_uring_fetch(ring_ent, cmd);
		break;
	case FUSE_URING_REQ_COMMIT_AND_FETCH:
		if (unlikely(!fc->ring.ready)) {
			pr_info("commit and fetch, but the ring is not ready yet");
			goto out;
		}

		if (!(prev_state & FRRS_USERSPACE)) {
			pr_info("qid=%d tag=%d Invalid request state %llu, "
				"missing %d \n", queue->qid, ring_ent->tag,
				ring_ent->state, FRRS_USERSPACE);
			goto out;
		}

		/* XXX Test inject error */

		WRITE_ONCE(ring_ent->cmd, cmd);
		fuse_dev_uring_commit_and_release(fud, ring_ent);

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
		io_uring_cmd_done(cmd, ret, 0);
	}

	return -EIOCBQUEUED;
}

/**
 * Finalize the ring destruction when queue ref counters are zero.
 */
void fuse_uring_ring_destruct(struct fuse_conn *fc)
{
	unsigned qid;

	if (READ_ONCE(fc->ring.queue_refs) != 0) {
		WARN_ON(1);
		return;
	}

	pr_devel("fc=%p canceling stop-monitor\n", fc);
	cancel_delayed_work_sync(&fc->ring.stop_monitor);

	put_task_struct(fc->ring.daemon);
	fc->ring.daemon = NULL;

	for (qid = 0; qid < fc->ring.nr_queues; qid++) {
		int tag;
		struct fuse_ring_queue *queue = fuse_uring_get_queue(fc, qid);
		if (!queue->configured)
			continue;

		for (tag = 0; tag < fc->ring.queue_depth; tag++) {
			struct fuse_ring_ent *rreq = &queue->ring_ent[tag];
			if (rreq->need_cmd_done) {
				pr_warn("fc=%p qid=%d tag=%d cmd not done\n",
					fc, qid, tag);
				io_uring_cmd_done(rreq->cmd, -ENOTCONN, 0);
				rreq->need_cmd_done = 0;
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
		struct fuse_ring_ent *rreq = &queue->ring_ent[tag];
		fuse_uring_shutdown_release_req(fc, queue, rreq);
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
static void fuse_dev_ring_stop_mon(struct work_struct *work)
{
	struct fuse_conn *fc = container_of(work, struct fuse_conn,
					    ring.stop_monitor.work);
	struct fuse_iqueue *fiq = &fc->iq;

	pr_devel("fc=%p running stop-mon, queues-stopped=%d\n",
		fc, fc->ring.queues_stopped);

	mutex_lock(&fc->ring.start_stop_lock);

	if (!fiq->connected || fc->ring.stop_requested ||
	    (fc->ring.daemon->flags & PF_EXITING)) {
		pr_devel("%s Stopping queues connected=%d stop-req=%d exit=%d\n",
			__func__, fiq->connected, fc->ring.stop_requested,
			(fc->ring.daemon->flags & PF_EXITING));
		fuse_uring_stop_queues(fc);
	}

	if (!fc->ring.queues_stopped) {
		pr_info("%s fc=%p schedule stop_mon\n", __func__, fc);
		schedule_delayed_work(&fc->ring.stop_monitor,
				      FURING_DAEMON_MON_PERIOD);
	} else
		pr_devel("%s fc=%p not scheduling, queues stopped\n", __func__, fc);

	mutex_unlock(&fc->ring.start_stop_lock);
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
__must_hold(fc->ring.stop_waitq.lock)
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

	req_sz = cfg->queue_depth * sizeof(struct fuse_ring_ent);
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

	buf = fuse_dev_uring_alloc_queue_buf(fc->ring.queue_buf_size, node_id);
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
		ent->kbuf = (struct fuse_uring_buf_req *)buf;

		pr_devel("initialize qid=%d tag=%d queue=%p req=%p",
			 qid, tag, queue, ent);

		ent->kbuf->flags = 0;

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
		pr_info("fc=%p nr-queues=%zu depth=%zu ioctl ready\n",
			fc, fc->ring.nr_queues, fc->ring.queue_depth);
	}

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
	mutex_lock(&fc->ring.start_stop_lock);

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
	mutex_unlock(&fc->ring.start_stop_lock);

	return rc;
}

/**
 * Wait until uring shall be destructed and then release uring resources
 */
static int fuse_dev_uring_wait_stop(struct fuse_conn *fc)
{
	struct fuse_iqueue *fiq = &fc->iq;

	if (fc->ring.stop_requested)
		return -EINTR;

	/* This userspace thread can stop uring on process stop, no need
	 * for the interval worker
	 */
	cancel_delayed_work_sync(&fc->ring.stop_monitor);

	wait_event_interruptible_exclusive(fc->ring.stop_waitq,
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

static int fuse_dev_stop_wakeup(struct fuse_conn *fc)
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
		return fuse_dev_stop_wakeup(fc);
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
