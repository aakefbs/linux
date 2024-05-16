.. SPDX-License-Identifier: GPL-2.0

===============================
FUSE Uring design documentation
==============================

This documentation covers basic details how the fuse
kernel/userspace communication through uring is configured
and works. For generic details about FUSE see fuse.rst.

This document also covers the current interface, which is
still in development and might change.

Limitations
===========
As of now not all requests types are supported through uring, userspace
side is required to also handle requests through /dev/fuse after
uring setup is complete. These are especially notifications (initiated
from daemon side), interrupts and forgets.
Interrupts are probably not working at all when uring is used. At least
current state of libfuse will not be able to handle those for requests
on ring queues.
All these limitation will be addressed later.

Fuse uring configuration
========================

Fuse kernel requests are queued through the classical /dev/fuse
read/write interface - until uring setup is complete.

In order to set up fuse-over-io-uring userspace has to send ioctls,
mmap requests in the right order

1) FUSE_DEV_IOC_URING ioctl with FUSE_URING_IOCTL_CMD_RING_CFG

First the basic kernel data structure has to be set up, using
FUSE_DEV_IOC_URING with subcommand FUSE_URING_IOCTL_CMD_RING_CFG.

Example (from libfuse)

static int fuse_uring_setup_kernel_ring(int session_fd,
					int nr_queues, int sync_qdepth,
					int async_qdepth, int req_arg_len,
					int req_alloc_sz)
{
	int rc;

	struct fuse_ring_config rconf = {
		.nr_queues		    = nr_queues,
		.sync_queue_depth	= sync_qdepth,
		.async_queue_depth	= async_qdepth,
		.req_arg_len		= req_arg_len,
		.user_req_buf_sz	= req_alloc_sz,
		.numa_aware		    = nr_queues > 1,
	};

	struct fuse_uring_cfg ioc_cfg = {
		.flags = 0,
		.cmd = FUSE_URING_IOCTL_CMD_RING_CFG,
		.rconf = rconf,
	};

	rc = ioctl(session_fd, FUSE_DEV_IOC_URING, &ioc_cfg);
	if (rc)
		rc = -errno;

	return rc;
}

2) MMAP

For shared memory communication between kernel and userspace
each queue has to allocate and map memory buffer.
For numa awares kernel side verifies if the allocating thread
is bound to a single core - in general kernel side has expectations
that only a single thread accesses a queue and for numa aware
memory alloation the core of the thread sending the mmap request
is used to identify the numa node.

The offsset parameter has to be FUSE_URING_MMAP_OFF to identify
it is a request concerning fuse-over-io-uring.

3) FUSE_DEV_IOC_URING ioctl with FUSE_URING_IOCTL_CMD_QUEUE_CFG

This ioctl has to be send for every queue and takes the queue-id (qid)
and memory address obtained by mmap to set up queue data structures.

Kernel - userspace interface using uring
========================================

After queue ioctl setup and memory mapping userspace submits
SQEs (opcode = IORING_OP_URING_CMD) in order to fetch
fuse requests. Initial submit is with the sub command
FUSE_URING_REQ_FETCH, which will just register entries
to be available on the kernel side - it sets the according
entry state and marks the entry as available in the queue bitmap.

Once all entries for all queues are submitted kernel side starts
to enqueue to ring queue(s). The request is copied into the shared
memory queue entry buffer and submitted as CQE to the userspace
side.
Userspace side handles the CQE and submits the result as subcommand
FUSE_URING_REQ_COMMIT_AND_FETCH - kernel side does completes the requests
and also marks the queue entry as available again. If there are
pending requests waiting the request will be immediately submitted
to userspace again.

Initial SQE
-----------

 |                                    |  FUSE filesystem daemon
 |                                    |
 |                                    |  >io_uring_submit()
 |                                    |   IORING_OP_URING_CMD /
 |                                    |   FUSE_URING_REQ_FETCH
 |                                    |  [wait cqe]
 |                                    |   >io_uring_wait_cqe() or
 |                                    |   >io_uring_submit_and_wait()
 |                                    |
 |  >fuse_uring_cmd()                 |
 |   >fuse_uring_fetch()              |
 |    >fuse_uring_ent_release()       |


Sending requests with CQEs
--------------------------

 |                                         |  FUSE filesystem daemon
 |                                         |  [waiting for CQEs]
 |  "rm /mnt/fuse/file"                    |
 |                                         |
 |  >sys_unlink()                          |
 |    >fuse_unlink()                       |
 |      [allocate request]                 |
 |      >__fuse_request_send()             |
 |        ...                              |
 |       >fuse_uring_queue_fuse_req        |
 |        [queue request on fg or          |
 |          bg queue]                      |
 |         >fuse_uring_assign_ring_entry() |
 |         >fuse_uring_send_to_ring()      |
 |          >fuse_uring_copy_to_ring()     |
 |          >io_uring_cmd_done()           |
 |          >request_wait_answer()         |
 |           [sleep on req->waitq]         |
 |                                         |  [receives and handles CQE]
 |                                         |  [submit result and fetch next]
 |                                         |  >io_uring_submit()
 |                                         |   IORING_OP_URING_CMD/
 |                                         |   FUSE_URING_REQ_COMMIT_AND_FETCH
 |  >fuse_uring_cmd()                      |
 |   >fuse_uring_commit_and_release()      |
 |    >fuse_uring_copy_from_ring()         |
 |     [ copy the result to the fuse req]  |
 |     >fuse_uring_req_end_and_get_next()  |
 |      >fuse_request_end()                |
 |       [wake up req->waitq]              |
 |      >fuse_uring_ent_release_and_fetch()|
 |       [wait or handle next req]         |
 |                                         |
 |                                         |
 |       [req->waitq woken up]             |
 |    <fuse_unlink()                       |
 |  <sys_unlink()                          |



