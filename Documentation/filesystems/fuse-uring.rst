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

IOCTL configuration
-------------------

Userspace daemon side has to initiate ring confuration through
the FUSE_DEV_IOC_URING ioctl, with cmd FUSE_URING_IOCTL_CMD_QUEUE_CFG.

Number of queues can be
    - 1
        - One ring for all cores and all requests.
    - Number of cores
        - One ring per core, requests are queued on the ring queue
          that is submitting the request. Especially for background
          requests we might consider to use queues of other cores
          as well - future work.
        - Kernel and userspace have to agree on the number of cores,
          on mismatch the ioctl is rejected.
        - For each queue a separate ioctl needs to be send.

Example:

fuse_uring_configure_kernel_queue()
{
	struct fuse_uring_cfg ioc_cfg = {
		.cmd = FUSE_URING_IOCTL_CMD_QUEUE_CFG,
		.qid = 2,
		.nr_queues = 3,
		.fg_queue_depth = 16,
		.bg_queue_depth = 4,
		.req_arg_len = 1024 * 1024,
		.numa_node_id = 1,
	};

    rc = ioctl(se->fd, FUSE_DEV_IOC_URING, &ioc_cfg);
}


On kernel side the first ioctl that arrives configures the basic fuse ring
and then its queue id. All further ioctls only their queue. Each queue gets
a memory allocation that is then assigned per queue entry.

MMAP
====

For shared memory communication allocated memory per queue is mmaped with
mmap. The corresponding queue is identified with the offset parameter.
Important is a strict agreement between kernel and userspace daemon side
on memory assignment per queue entry - a mismatch would lead to data
corruption.
Ideal would be an mmap per ring entry and to verify the pointer on SQE
submission, but the result obtained in the file_operations::mmap method
is scrambled further down the stack - fuse kernel does not know the exact
pointer value returned to mmap initiated by userspace.


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


Shutdown
========

A dayled workqueue is started when the ring gets configured with ioctls and
runs periodically to complete ring entries on umount or daemon stop.
See fuse_uring_stop_mon() and subfunctions for details - basically it needs
to run io_uring_cmd_done() for waiting SQEs and fuse_request_end() for
queue entries that have a fuse request assigned.

In order to avoid periodic cpu cycles for shutdown the userspace daemon can
create a thread and submit that thread into a waiting state with the
FUSE_DEV_IOC_URING ioctl and FUSE_URING_IOCTL_CMD_WAIT subcommand.
Kernel side will stop the periodic waiter on receiving this ioctl
and will go into a waitq. On umount or daemon termination it will
wake up and start the delayed stop workq again before returning to
userspace.
