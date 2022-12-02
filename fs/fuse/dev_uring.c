/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
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
#include <asm/io.h>
#include <linux/io_uring.h>

/* default monitor interval for a dying daemon */
#define FURING_DAEMON_MON_PERIOD (5 * HZ)


void fuse_uring_check_ring_destruct_destruct(struct fuse_conn *fc);

static struct fuse_ring_queue *
fuse_uring_get_queue(struct fuse_conn *fc, int qid)
{
	char *ptr = (char *)fc->ring.queues;
	return (struct fuse_ring_queue *)(ptr + qid * fc->ring.queue_size);
}

static int fuse_uring_copy_to_ring(struct fuse_conn *fc,
				   struct fuse_req *req,
				   struct fuse_uring_buf_req *buf_req)
{
	struct fuse_copy_state cs;
	struct fuse_args *args = req->args;
	int err;
	size_t max_buf = sizeof(buf_req->in_out_arg) + fc->ring.ring_req_size;

	fuse_copy_init(&cs, 1, NULL);
	cs.is_uring = 1;
	cs.ring.buf = buf_req->in_out_arg;
	cs.ring.len = max_buf;
	cs.req = req;

	pr_debug("%s:%d buf=%p len=%d args=%d\n", __func__, __LINE__,
		 cs.ring.buf, cs.ring.len, args->out_numargs);

	err = fuse_copy_args(&cs, args->in_numargs, args->in_pages,
			     (struct fuse_arg *) args->in_args, 0);
	buf_req->in_out_arg_len = cs.ring.offset;

	pr_debug("%s:%d buf=%p len=%d args=%d err=%d\n", __func__, __LINE__,
		 cs.ring.buf, cs.ring.len, args->out_numargs, err);

	return err;
}

static int fuse_uring_copy_from_ring(struct fuse_conn *fc,
				     struct fuse_req *req,
				     struct fuse_uring_buf_req *buf_req)
{
	struct fuse_copy_state cs;
	struct fuse_args *args = req->args;
	size_t max_buf = sizeof(buf_req->in_out_arg) + fc->ring.ring_req_size;

	fuse_copy_init(&cs, 0, NULL);
	cs.is_uring = 1;
	cs.ring.buf = buf_req->in_out_arg;

	if (buf_req->in_out_arg_len > max_buf) {
		pr_debug("Max ring buffer len exceeded (%u vs %zu\n",
			 buf_req->in_out_arg_len, max_buf);
		return -EINVAL;
	}
	cs.ring.len = buf_req->in_out_arg_len;

	cs.req = req;

	pr_debug("%s:%d buf=%p len=%d args=%d\n", __func__, __LINE__,
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

	pr_debug("%s:%d Here ring-req=%p buf_req=%p state=%d args=%p \n",
		 __func__, __LINE__, ring_req, buf_req, ring_req->state, req->args);

	if (READ_ONCE(ring_req->state) != FUSE_RING_REQ_STATE_REQ) {
		WARN_RATELIMIT(1, "Invalid ring-req state: %d\n",
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

	pr_debug("%s cmd-done op=%d unique=%llu\n",
		__func__, buf_req->in.opcode, buf_req->in.unique);

	clear_bit(FR_PENDING, &req->flags);
	set_bit(FR_SENT, &req->flags);

	spin_lock(&ring_req->queue->waitq.lock);
	ring_req->state = FUSE_RING_REQ_STATE_USERSPACE;
	spin_unlock(&ring_req->queue->waitq.lock);
	io_uring_cmd_done(ring_req->cmd, 0, 0);

	return 0;

err:
	req->out.h.error = -EIO;
	if (ring_req->req_ptr) {
		*ring_req->req_ptr = *req;
		fuse_request_end(ring_req->req_ptr);
		ring_req->req_ptr = NULL;
	}
	else
		fuse_request_end(req);

	return err;
}
EXPORT_SYMBOL_GPL(fuse_dev_uring_write_to_ring);

/**
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
		pr_debug("%s:%d err=%d op=%d req-ret=%d",
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
	pr_debug("%s:%d err=%d op=%d req-ret=%d",
		 __func__, __LINE__, err, req->args->opcode,
		 req->out.h.error);
	oh->error = err;
err:
	pr_debug("%s:%d err=%d op=%d req-ret=%d",
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

	pr_debug("%s:%d req=%p\n", __func__, __LINE__, req);

	clear_bit(FR_SENT, &req->flags);

	req->out.h = buf_req->out;

	err = fuse_dev_uring_ring_has_err(fud->fc, ring_req);
	if (err) {
		pr_debug("%s:%d err=%zd oh->err=%d \n", __func__, __LINE__,
			 err, req->out.h.error);
		goto out;
	}

	err = fuse_uring_copy_from_ring(fud->fc, req, buf_req);
	if (err)
		goto seterr;

out:
	pr_debug("%s:%d ret=%zd op=%d req-ret=%d",
		 __func__, __LINE__, err, req->args->opcode, req->out.h.error);
	if (ring_req->req_ptr) {
		*ring_req->req_ptr = *req;
		fuse_request_end(ring_req->req_ptr);
		ring_req->req_ptr = NULL;
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
	ring_req->state = FUSE_RING_REQ_STATE_REQ;
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

	pr_debug("%s: args=%p ring-args=%p\n",
		 __func__, q_req->args, ring_req->req.args);

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

static struct fuse_ring_queue *
fuse_dev_uring_queue_from_current_task(struct fuse_conn *fc)
{
	unsigned int core = 0;

	if (fc->ring.per_core_queue)
		core = task_cpu(current);

	if (unlikely(core) >= fc->ring.nr_queues) {
		WARN_ONCE(1, "Core number (%u) exceeds nr of ring queues (%zu)\n",
			  core, fc->ring.nr_queues);
		core = 0;
	}

	return fuse_uring_get_queue(fc, core);
}

/**
 * XXX Add a different ring queue for background requests? Or queue to list
 *     and take from there when idle?
 */
struct fuse_req *fuse_request_alloc_ring(struct fuse_mount *fm, gfp_t flags,
					 bool for_background)
{
	struct fuse_conn *fc = fm->fc;
	struct fuse_ring_queue *queue;
	struct fuse_ring_req *ring_req;
	struct fuse_req *req = NULL;
	uint64_t req_cnt;
	unsigned int tag;
	const size_t queue_depth = fc->ring.queue_depth;
	const struct fuse_iqueue *fiq = &fc->iq;

	queue = fuse_dev_uring_queue_from_current_task(fc);
	spin_lock(&queue->waitq.lock);

	/* The conditions below require that neither fore- nor background
	 * requests can take all queue entries
	 */
	if (for_background) {
		if (queue->req_active_background >= fc->ring.max_background) {
			/* no need to wait for background requests, the caller
			 * can handle request allocation failures
			 */
			goto out;
		}
	} else {


		/* foreground waits until there is space in the queue */
		while (queue->req_avtive_foreground >= fc->ring.max_foreground)
		{
			wait_event_interruptible_exclusive_locked
				(queue->waitq, (queue->req_avtive_foreground > 0));

			if ((fc->ring.daemon->flags & PF_EXITING) ||
			    !fiq->connected || fc->ring.stop_requested ||
			    (current->flags & PF_EXITING))
				goto out;
		}
	}

	tag = find_first_bit(queue->req_avail_map, queue_depth);
	if (unlikely(tag == queue_depth)) {
		pr_info("No free bit found\n");
		BUG_ON(1);
		goto out;
	}

	ring_req = &queue->ring_req[tag];
	if (unlikely(ring_req->state != FUSE_RING_REQ_STATE_WAITING)) {
		pr_info("Invalid request state %d.\n",
			ring_req->state);
		BUG_ON(1);
		goto out;
	}

	ring_req->state = FUSE_RING_REQ_STATE_REQ;
	ring_req->kbuf->flags = 0;

	if (for_background) {
		ring_req->kbuf->flags |= FUSE_RING_REQ_FLAG_BACKGROUND;
		queue->req_active_background++;
	}
	else {
		queue->req_avtive_foreground++;
		pr_debug("%s:%d ac-foregnd=%d\n", __func__, __LINE__,
			 queue->req_avtive_foreground);
	}

	req = &ring_req->req;
	__clear_bit(tag, queue->req_avail_map);

out:
	spin_unlock(&queue->waitq.lock);

	if (req) {
		memset(req, 0, sizeof(*req));
		fuse_request_init(fm, req);
		__set_bit(FR_URING, &req->flags);
	}

	pr_debug("%s tag %d cnt=%llu req=%p\n", __func__, tag, req_cnt, req);

	return req;
}
EXPORT_SYMBOL_GPL(fuse_request_alloc_ring);


/**
 * @return true when the request could be released
 */
bool fuse_uring_free_req(struct fuse_conn *fc, struct fuse_ring_queue *queue,
			 struct fuse_ring_req *req)
{
	bool can_free = false;

	spin_lock(&queue->waitq.lock);
	if (req->state == FUSE_RING_REQ_STATE_WAITING) {
		req->state = FUSE_RING_REQ_STATE_FREED;
		can_free = true;
	}
	spin_unlock(&queue->waitq.lock);

	if (can_free) {
		kvfree(req->kbuf);

		pr_debug("releasing cmd qid=%d tag=%d\n", queue->q_id, req->tag);
		io_uring_cmd_done(req->cmd, -EIO, 0);
	}

	return can_free;
}

/**
 * The request is no longer needed, it can handle new data
 */
void fuse_dev_uring_req_release(struct fuse_req *req)
{
	struct fuse_ring_req *ring_req =
		container_of(req, struct fuse_ring_req, req);
	struct fuse_ring_queue *queue = ring_req->queue;
	struct fuse_conn *fc = queue->fc;

	spin_lock(&queue->waitq.lock);
	if (ring_req->state != FUSE_RING_REQ_STATE_USERSPACE) {
		WARN(1, "Invalid req state: %d\n", ring_req->state);
		goto out;
	}

	ring_req->state = FUSE_RING_REQ_STATE_WAITING;

	if (test_bit(FR_BACKGROUND, &req->flags))
		queue->req_active_background--;
	else {
		queue->req_avtive_foreground--;
		pr_debug("%s:%d ac-foregnd=%d\n", __func__, __LINE__,
			 queue->req_avtive_foreground);
	}

	ring_req->kbuf->flags = 0;
	__set_bit(ring_req->tag, queue->req_avail_map);
	wake_up_locked(&queue->waitq);
out:
	spin_unlock(&queue->waitq.lock);
	if (fc->ring.stop_requested) {
		bool released = fuse_uring_free_req(fc, queue, ring_req);
		if (released) {
			spin_lock(&fc->ring.stop_waitq.lock);
			fc->ring.queue_refs--;
			fuse_uring_check_ring_destruct_destruct(fc);
			spin_unlock(&fc->ring.stop_waitq.lock);
		}
	}
}
EXPORT_SYMBOL_GPL(fuse_dev_uring_req_release);

int fuse_dev_uring(struct io_uring_cmd *cmd, unsigned int issue_flags)
{
	const struct fuse_uring_cmd_req *cmd_req =
		(struct fuse_uring_cmd_req *)cmd->cmd;
	struct fuse_dev *fud = fuse_get_dev(cmd->file);
	struct fuse_conn *fc = fud->fc;
	struct fuse_ring_queue *queue;
	struct fuse_ring_req *ring_req;
	u32 cmd_op = cmd->cmd_op;
	int ret;

	if (!(issue_flags & IO_URING_F_SQE128)) {
		pr_info("qid=%d tag=%d SQE128 not set\n",
			cmd_req->q_id, cmd_req->tag);
		goto out;
	}

	if (cmd_req->q_id >= fc->ring.nr_queues) {
		pr_info("qid=%u > nr-queues=%zu\n",
			cmd_req->q_id, fc->ring.nr_queues);
		goto out;
	}
	queue = fuse_uring_get_queue(fc, cmd_req->q_id);

	if (cmd_req->tag > fc->ring.queue_depth) {
		pr_info("tag=%u > queue-depth=%zu\n",
			cmd_req->tag, fc->ring.queue_depth);
		goto out;
	}
	ring_req = &queue->ring_req[cmd_req->tag];

	pr_debug("%s:%d received: cmd op %d queue %d (%p) tag %d  (%p)\n",
		 __func__, __LINE__,
		 cmd_op, cmd_req->q_id, queue, cmd_req->tag, ring_req);

	switch (cmd_op) {
	case FUSE_URING_REQ_FETCH:
		if (READ_ONCE(ring_req->state) != FUSE_RING_REQ_STATE_INIT) {
			pr_debug("%s: q_id: %d tag: %d invalid req state: %d\n",
				 __func__, cmd_req->q_id, cmd_req->tag,
				 ring_req->state);
			goto out;
		}

		WRITE_ONCE(ring_req->cmd, cmd);


		ret = fuse_dev_uring_fetch_queued(fc, queue, ring_req);

		if (ret >= 0) {

			/* command registration or list req fetch - assing
			 * credits to make subtraction logic to work
			 */
			spin_lock(&queue->waitq.lock);
			if (test_bit(FR_BACKGROUND, &ring_req->req.flags))
				queue->req_active_background++;
			else {
				queue->req_avtive_foreground++;
				pr_debug("%s:%d ac-foregnd=%d\n", __func__, __LINE__,
					 queue->req_avtive_foreground);
			}
			spin_unlock(&queue->waitq.lock);

			if (ret == 0) {
				/* just a queue entry registration, without a
				 *  fuse req - make it available
				 */
				WRITE_ONCE(ring_req->state,
					   FUSE_RING_REQ_STATE_USERSPACE);
				fuse_dev_uring_req_release(&ring_req->req);
			}
		}


		break;
	case FUSE_URING_REQ_COMMIT_AND_FETCH:
		/* user space forgot to send the buffer - invalid command */
		if (!cmd_req->req_buf) {
			goto out;
		}
		if (READ_ONCE(ring_req->state) != FUSE_RING_REQ_STATE_USERSPACE) {
			pr_info("Invalid request state %d, expected %d \n",
				ring_req->state, FUSE_RING_REQ_STATE_USERSPACE);
			goto out;
		}
		ring_req->cmd = cmd;

		fuse_dev_uring_read_from_ring(fud, ring_req);

		ret = 0;

		break;
	default:
		ret = -EINVAL;
		pr_debug("Unknown uring command %d", cmd_op);
		goto out;
	}

	pr_debug("%s:%d ret=%d", __func__, __LINE__, ret);

out:
	if (ret < 0) {
		spin_lock(&queue->waitq.lock);
		ring_req->state =  FUSE_RING_REQ_STATE_USERSPACE;
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
		pr_info("%s: req error: op=%d, tag=%d ret=%d io_flags=%x\n",
			__func__, cmd_op, cmd_req->tag, ret, issue_flags);
	} else {
		pr_info("%s: %s cmd op %d queue %d tag %d result %d\n",
			 __func__, ret == 0 ? "req ring queued" : "req sent back",
			cmd_op, cmd_req->q_id, cmd_req->tag, ret);

	}
	return -EIOCBQUEUED;
}
EXPORT_SYMBOL(fuse_dev_uring);

/**
 * Finalize the ring destruction when queue ref counters are zero.
 *
 * Has to be called with
 */
void fuse_uring_check_ring_destruct_destruct(struct fuse_conn *fc)
__must_hold(&fc->ring.stop_waitq.lock)
{
	if (fc->ring.queue_refs == 0) {
		kfree(fc->ring.queues);
		fc->ring.initialized = 0;
		fc->ring.queues = NULL;
		fc->ring.queue_depth = 0;
		fc->ring.nr_queues = 0;
	}
}

/**
 *  Destruct the ring
 */
void fuse_uring_start_destruct(struct fuse_conn *fc)
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
			struct fuse_ring_req *req = &queue->ring_req[tag];
			bool released = fuse_uring_free_req(fc, queue, req);
			if (released)
				fc->ring.queue_refs--;
			BUG_ON(fc->ring.queue_refs > 0);
		}
	}

	fuse_uring_check_ring_destruct_destruct(fc);
out:
	spin_unlock(&fc->ring.stop_waitq.lock);
}
EXPORT_SYMBOL_GPL(fuse_uring_start_destruct);

/**
 * Fallback to stop uring resources if there is no thread from
 * userspace doing that.
 * Having a waiting userspace process if preferred, as this
 * method requires interval monitoring and hence, repeating cpu resources.
 */
static void fuse_dev_ring_stop_monitor_fn(struct work_struct *work)
{
	struct fuse_conn *fc = container_of(work, struct fuse_conn,
					      ring.stop_monitor.work);
	struct fuse_iqueue *fiq = &fc->iq;

	if ((fc->ring.daemon->flags & PF_EXITING) || !fiq->connected ||
	    fc->ring.stop_requested)
		fuse_uring_start_destruct(fc);
}

/**
 * XXX Use __vmalloc and switch mmap to vmalloc
 */
static int fuse_dev_create_uring_req_mem(struct fuse_ring_req *req, int size)
{
	const int flags = GFP_KERNEL_ACCOUNT | __GFP_ZERO | __GFP_NOWARN | __GFP_COMP;
	req->kbuf = (void *)__get_free_pages(flags, get_order(size));

	return req->kbuf ? 0 : -ENOMEM;
}

static int fuse_dev_uring_setup(struct fuse_conn *fc, struct fuse_uring_cfg *cfg)
{
	size_t req_size;
	size_t queue_size;
	int q_id;
	int rc;

	if (cfg->flags & FUSE_URING_IOCTL_FLAG_PER_CORE_QUEUE) {
		if (!cpu_possible(cfg->num_queues - 1)) {
			pr_info("per-core-queue, but number of queue "
				"mismatches number of cpus");
			return -EINVAL;
		}
	} else {
		if (cfg->num_queues != 1) {
			pr_info("Per-core-queue not set, expecting a single "
				"queue");
			return -EINVAL;
		}
	}

	if (cfg->mmap_req_size < FUSE_RING_HEADER_BUF_SIZE + PAGE_SIZE) {
		pr_info("Per req mmap size too small (%d), min: %ld\n",
			cfg->mmap_req_size,
			FUSE_RING_HEADER_BUF_SIZE + PAGE_SIZE);
		return -EINVAL;
	}

	spin_lock(&fc->ring.stop_waitq.lock);

	if (fc->ring.initialized) {
		rc = -EALREADY;
		goto unlock;
	}

	INIT_DELAYED_WORK(&fc->ring.stop_monitor, fuse_dev_ring_stop_monitor_fn);
	schedule_delayed_work(&fc->ring.stop_monitor, FURING_DAEMON_MON_PERIOD);

	req_size = cfg->queue_depth * sizeof(struct fuse_ring_req);
	queue_size = (sizeof(*fc->ring.queues) + req_size) * cfg->num_queues;

	fc->ring.daemon = current;
	fc->ring.nr_queues = cfg->num_queues;
	fc->ring.queue_depth = cfg->queue_depth;
	fc->ring.per_core_queue = cfg->flags & FUSE_URING_IOCTL_FLAG_PER_CORE_QUEUE;
	fc->ring.ring_req_size = cfg->mmap_req_size;
	fc->ring.queues = kcalloc(cfg->num_queues, queue_size, GFP_KERNEL);
	if (!fc->ring.queues) {
		rc = -ENOMEM;
		goto unlock;
	}
	fc->ring.queue_size = queue_size;

	fc->ring.max_background = cfg->max_background;

	if (cfg->max_background >= cfg->queue_depth) {
		pr_info("Invalid ring configuration, nr-background > nr-requests\n");
		rc = -EINVAL;
		goto unlock;
	}

	fc->ring.queue_refs = 0;
	fc->ring.max_foreground = cfg->queue_depth - cfg->max_background;
	for (q_id = 0; q_id < cfg->num_queues; q_id++) {
		int tag;
		struct fuse_ring_queue *queue = fuse_uring_get_queue(fc, q_id);
		queue->q_id = q_id;
		queue->fc = fc;
		queue->req_avtive_foreground = 0;
		bitmap_zero(queue->req_avail_map, FUSE_URING_MAX_QUEUE_DEPTH);
		init_waitqueue_head(&queue->waitq);

		for (tag = 0; tag < fc->ring.queue_depth; tag++) {
			struct fuse_ring_req *req = &queue->ring_req[tag];
			req->queue = queue;
			req->tag = tag;
			req->req_ptr = NULL;


			rc = fuse_dev_create_uring_req_mem(req, cfg->mmap_req_size);

			pr_debug("initialize qid=%d tag=%d queue=%p req=%p kbuf=%p",
				 q_id, tag, queue, req, req->kbuf);

			if (rc != 0)
				goto unlock;
			req->kbuf->flags = 0;

			WRITE_ONCE(req->state, FUSE_RING_REQ_STATE_INIT);
			fc->ring.queue_refs++;
		}
	}

	fc->ring.initialized = 1;
	rc = 0;

unlock:
	spin_unlock(&fc->ring.stop_waitq.lock);
	return rc;
}

/**
 * Wait until uring shall be destructed and then release uring resources
 */
static int fuse_dev_uring_wait_destruct(struct fuse_conn *fc)
{
	struct fuse_iqueue *fiq = &fc->iq;

	pr_debug("%s exiting=%d connected=%d stop-req=%d\n", __func__,
		 fc->ring.daemon->flags & PF_EXITING, fiq->connected,
		 fc->ring.stop_requested);

	/* This userspace thread can stop uring on process stop, no need
	 * for the interval worker
	 */
	mod_delayed_work(system_wq, &fc->ring.stop_monitor, -1UL);

	wait_event_interruptible_exclusive(fc->ring.stop_waitq,
					   !fiq->connected ||
					   fc->ring.stop_requested ||
					   (fc->ring.daemon->flags & PF_EXITING));

	if ((fc->ring.daemon->flags & PF_EXITING) || !fiq->connected ||
	    fc->ring.stop_requested)
		fuse_uring_start_destruct(fc);
	else {
		/* The userspace task gets scheduled to back userspace, we need
		 * the interval worker again.
		 */
		mod_delayed_work(system_wq, &fc->ring.stop_monitor,
				 FURING_DAEMON_MON_PERIOD);
	}

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

	pr_debug("%s flags=%llx nq=%d  qdepth=%d\n",
		 __func__, cfg->flags, cfg->num_queues, cfg->queue_depth);

	fc = fud->fc;

	if (cfg->flags & FUSE_URING_IOCTL_FLAG_CFG) {
		/* config flag is incompatible to WAIT and STOP */
		if ((cfg->flags & FUSE_URING_IOCTL_FLAG_WAIT) ||
		    (cfg->flags & FUSE_URING_IOCTL_FLAG_STOP))
			return -EINVAL;

		return fuse_dev_uring_setup(fc, cfg);
	}

	if (cfg->flags & FUSE_URING_IOCTL_FLAG_WAIT) {
		if (cfg->flags & FUSE_URING_IOCTL_FLAG_STOP)
			return -EINVAL;

		return fuse_dev_uring_wait_destruct(fc);
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
	phys_addr_t pfn;
	unsigned qid, tag;
	int ret;
	loff_t off;
	struct fuse_ring_queue *queue;
	struct fuse_ring_req *req;

	/* check if uring is configured and if the requested size matches */
	if (fc->ring.nr_queues == 0 || fc->ring.queue_depth == 0 ||
	    sz != fc->ring.ring_req_size) {
		ret = -EINVAL;
		goto out;
	}

	/* offset actually has the specifies which ring request the mmap is for
	 * additional PAGE_SIZE division is done as offset has to be page
	 * aligned, so actual values had been multiplied by PAGE_SIZE by the
	 * mmap requesting side */
	off = (vma->vm_pgoff << PAGE_SHIFT) / PAGE_SIZE;
	qid = off / (fc->ring.queue_depth);
	tag = off % (fc->ring.queue_depth);
	if (qid + 1 > fc->ring.nr_queues || tag + 1 > fc->ring.queue_depth) {
		ret = -EINVAL;
		goto out;
	}

	queue = fuse_uring_get_queue(fc, qid);
	req = &queue->ring_req[tag];

	pfn = virt_to_phys(req->kbuf) >> PAGE_SHIFT;
	ret = remap_pfn_range(vma, vma->vm_start, pfn, sz, vma->vm_page_prot);
out:
	pr_debug("%s: pid %d req=%p addr %p sz %zu qid: %d tag: %d ret %d\n",
		 __func__, current->pid, req, (char *)vma->vm_start,
		 sz, qid, tag, ret);

	return ret;
}
EXPORT_SYMBOL_GPL(fuse_dev_ring_mmap);


